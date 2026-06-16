// codeitem_sink.cpp — see codeitem_sink.h. INERT until VECTOR_UNPACK_ENABLED.

#ifdef VECTOR_UNPACK_ENABLED

#include "unpack/codeitem_sink.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <cerrno>
#include <csetjmp>
#include <csignal>
#include <cstdio>
#include <cstring>

#include <common/logging.h>

#include "unpack/dex_layout.h"

namespace vector::native::unpack {

namespace {

// Find the mapped region [out_start, out_end) of /proc/self/maps that contains `addr`.
// `want_app` = require the mapping to be an app dex (anonymous, or path under /data) and
// reject /system, /apex, /vendor framework images. Returns false if not found / filtered.
bool FindMapping(uintptr_t addr, uintptr_t *out_start, uintptr_t *out_end, bool want_app) {
    FILE *f = fopen("/proc/self/maps", "re");
    if (!f) return false;
    char line[512];
    bool found = false;
    while (fgets(line, sizeof(line), f)) {
        uintptr_t start = 0, end = 0;
        char perms[5] = {0};
        // "start-end perms off dev:dev inode pathname"
        if (sscanf(line, "%lx-%lx %4s", &start, &end, perms) != 3) continue;
        if (addr < start || addr >= end) continue;
        // Must be readable to scan.
        if (perms[0] != 'r') break;
        if (want_app) {
            const char *path = strchr(line, '/');
            if (path) {
                if (strncmp(path, "/system", 7) == 0 || strncmp(path, "/apex", 5) == 0 ||
                    strncmp(path, "/vendor", 7) == 0 || strncmp(path, "/product", 8) == 0) {
                    break;  // framework image — skip
                }
            }
        }
        *out_start = start;
        *out_end = end;
        found = true;
        break;
    }
    fclose(f);
    return found;
}

// From an inner pointer known to lie inside a dex's data, recover the dex base + size by
// scanning backward (4-byte aligned) within the containing VMA for a valid dex header whose
// [base, base+file_size) still contains `inner`. Bounded by the VMA start and a 32 MB cap.
// Returns the base (and sets *out_size), or nullptr.
const uint8_t *FindDexImage(const uint8_t *inner, size_t *out_size) {
    uintptr_t vstart = 0, vend = 0;
    if (!FindMapping(reinterpret_cast<uintptr_t>(inner), &vstart, &vend, /*want_app=*/true))
        return nullptr;

    const uintptr_t kCap = 32u << 20;
    uintptr_t lo = reinterpret_cast<uintptr_t>(inner);
    if (lo > kCap && lo - kCap > vstart) vstart = lo - kCap;  // cap the backward window
    uintptr_t p = lo & ~uintptr_t(3);                          // 4-byte align downward
    for (; p >= vstart; p -= 4) {
        const uint8_t *cand = reinterpret_cast<const uint8_t *>(p);
        if (p + sizeof(dex::Header) > vend) continue;
        if (!dex::IsDexHeader(cand)) continue;
        uint32_t fsize = dex::DexFileSize(cand);
        if (p + fsize > vend) continue;                        // image must fit in the VMA
        if (reinterpret_cast<uintptr_t>(inner) >= p + fsize) continue;  // must contain inner
        *out_size = fsize;
        return cand;
    }
    return nullptr;
}

// ---- fault-guarded self-read ------------------------------------------------------------
// /proc/self/mem is EACCES for untrusted_app (SELinux), and a direct read can fault on pages
// that /proc/self/maps lists readable (guard pages, userfaultfd-GC pages on Android 14+, or a
// racing unmap in a multithreaded packer like NetEase Yidun). So we read under a SIGSEGV/SIGBUS
// guard scoped to THIS thread: a fault on our scan thread siglongjmp's back and we skip that
// page; a fault on any OTHER thread is chained to the app's own handler (we must not disturb the
// packer's signal handling). No special permissions needed.
sigjmp_buf g_fault_jmp;
volatile sig_atomic_t g_fault_active = 0;
pid_t g_fault_tid = 0;
struct sigaction g_old_segv, g_old_bus;
bool g_guard_installed = false;

inline pid_t cur_tid() { return (pid_t)syscall(SYS_gettid); }

void fault_handler(int sig, siginfo_t *info, void *uctx) {
    if (g_fault_active && cur_tid() == g_fault_tid) siglongjmp(g_fault_jmp, 1);
    // Not our scan thread (or not scanning) -> chain to the app's previous handler.
    struct sigaction *old = (sig == SIGBUS) ? &g_old_bus : &g_old_segv;
    if (old->sa_flags & SA_SIGINFO) {
        if (old->sa_sigaction) old->sa_sigaction(sig, info, uctx);
    } else if (old->sa_handler == SIG_DFL || old->sa_handler == SIG_IGN) {
        signal(sig, SIG_DFL);
        raise(sig);
    } else if (old->sa_handler) {
        old->sa_handler(sig);
    }
}

void InstallFaultGuard() {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = fault_handler;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGSEGV, &sa, &g_old_segv);
    sigaction(SIGBUS, &sa, &g_old_bus);
    g_fault_tid = cur_tid();
    g_guard_installed = true;
}

void RemoveFaultGuard() {
    if (!g_guard_installed) return;
    sigaction(SIGSEGV, &g_old_segv, nullptr);
    sigaction(SIGBUS, &g_old_bus, nullptr);
    g_guard_installed = false;
}

// Copy [base, base+n) into buf, page by page under the guard; faulting pages are zeroed.
// Returns true if any page copied. Caller must hold the guard (InstallFaultGuard) + be the
// g_fault_tid thread.
bool ReadRegionGuarded(const uint8_t *base, size_t n, uint8_t *buf) {
    const size_t PAGE = 4096;
    bool any = false;
    for (size_t off = 0; off < n; off += PAGE) {
        size_t psz = (n - off < PAGE) ? (n - off) : PAGE;
        if (sigsetjmp(g_fault_jmp, 1) == 0) {
            g_fault_active = 1;
            memcpy(buf + off, base + off, psz);
            any = true;
        } else {
            memset(buf + off, 0, psz);  // faulted -> zero this page and continue
        }
        g_fault_active = 0;
    }
    return any;
}

}  // namespace

bool CodeItemSink::Init(const char *out_dir) {
    if (!out_dir) return false;
    // mkdir -p (best-effort; each component).
    char tmp[256];
    snprintf(tmp, sizeof(tmp), "%s", out_dir);
    for (char *q = tmp + 1; *q; ++q) {
        if (*q == '/') {
            *q = 0;
            mkdir(tmp, 0700);
            *q = '/';
        }
    }
    mkdir(tmp, 0700);
    snprintf(dir_, sizeof(dir_), "%s", out_dir);
    inited_ = true;
    LOGI("[unpack] sink init dir={}", dir_);
    return true;
}

long CodeItemSink::FindRangeLocked(const uint8_t *inner) const {
    for (const auto &r : ranges_) {
        if (inner >= r.base && inner < r.end) return (long)r.id;
    }
    return -1;
}

void CodeItemSink::DumpDexLocked(const uint8_t *base, size_t size) {
    char path[320];
    snprintf(path, sizeof(path), "%s/dump_%08x_%zu.dex", dir_, dex::DexChecksum(base), size);
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        LOGW("[unpack] dump open failed: {} (errno={})", path, errno);
        return;
    }
    size_t off = 0;
    while (off < size) {
        ssize_t w = write(fd, base + off, size - off);
        if (w <= 0) break;
        off += (size_t)w;
    }
    fsync(fd);
    close(fd);
    LOGI("[unpack] dumped dex -> {} ({} bytes)", path, off);
}

void CodeItemSink::ObserveCodeItem(const void *code_item) {
    if (!inited_ || !code_item) return;
    const uint8_t *ci = reinterpret_cast<const uint8_t *>(code_item);
    {
        std::lock_guard<std::mutex> g(lock_);
        if (FindRangeLocked(ci) >= 0) return;  // dex already known/dumped — hot path
    }
    // Slow path (once per dex): locate + dump outside? No — recover then take the lock to
    // commit, re-checking the range to avoid a double dump under concurrency.
    size_t size = 0;
    const uint8_t *base = FindDexImage(ci, &size);
    if (!base) return;  // not an app dex / couldn't locate — fail closed
    std::lock_guard<std::mutex> g(lock_);
    if (FindRangeLocked(ci) >= 0) return;  // another thread won the race
    uint32_t id = (uint32_t)dex_count_++;
    ranges_.push_back({base, base + size, id});
    DumpDexLocked(base, size);
}

void CodeItemSink::ScanProcessForDexes() {
    if (!inited_) return;
    FILE *f = fopen("/proc/self/maps", "re");
    if (!f) return;
    InstallFaultGuard();
    char line[512];
    size_t found = 0, scanned = 0;
    std::vector<uint8_t> buf;
    while (fgets(line, sizeof(line), f)) {
        uintptr_t start = 0, end = 0;
        char perms[5] = {0};
        if (sscanf(line, "%lx-%lx %4s", &start, &end, perms) != 3) continue;
        if (perms[0] != 'r') continue;   // must be readable
        if (perms[2] == 'x') continue;   // dex DATA lives in r--p/rw-p, not code pages
        // Pathname filter: skip framework images; allow anon (decrypted dex) and /data.
        const char *path = strchr(line, '/');
        if (path) {
            if (strncmp(path, "/system", 7) == 0 || strncmp(path, "/apex", 5) == 0 ||
                strncmp(path, "/vendor", 7) == 0 || strncmp(path, "/product", 8) == 0)
                continue;
        }
        size_t rsize = end - start;
        if (rsize < sizeof(dex::Header) || rsize > (96u << 20)) continue;  // cap the per-region copy
        const uint8_t *live = reinterpret_cast<const uint8_t *>(start);
        // Copy the region into a private buffer under the SIGSEGV/SIGBUS guard (never faults us).
        buf.resize(rsize);
        if (!ReadRegionGuarded(live, rsize, buf.data())) continue;
        scanned++;
        const uint8_t *b = buf.data();
        size_t i = 0;
        while (i + sizeof(dex::Header) <= rsize) {
            const uint8_t *cand = b + i;            // candidate in the SAFE buffer copy
            if (cand[0] == 'd' && dex::IsDexHeader(cand)) {
                uint32_t fsize = dex::DexFileSize(cand);
                if ((size_t)i + fsize <= rsize) {
                    const uint8_t *live_at = live + i;  // dedup key = live address
                    std::lock_guard<std::mutex> g(lock_);
                    if (FindRangeLocked(live_at) < 0) {
                        uint32_t id = (uint32_t)dex_count_++;
                        ranges_.push_back({live_at, live_at + fsize, id});
                        DumpDexLocked(cand, fsize);   // dump from the buffer copy (safe)
                        found++;
                    }
                    i += fsize;   // jump past this dex (handles multidex in one vdex)
                    continue;
                }
            }
            i += 4;
        }
    }
    RemoveFaultGuard();
    fclose(f);
    LOGI("[unpack] maps scan: {} region(s) scanned, {} new dex image(s) dumped", scanned, found);
}

uint32_t CodeItemSink::RegisterDex(const void *begin, size_t size) {
    std::lock_guard<std::mutex> g(lock_);
    const uint8_t *b = reinterpret_cast<const uint8_t *>(begin);
    long existing = FindRangeLocked(b);
    if (existing >= 0) return (uint32_t)existing;
    uint32_t id = (uint32_t)dex_count_++;
    ranges_.push_back({b, b + size, id});
    if (inited_) DumpDexLocked(b, size);
    return id;
}

void CodeItemSink::Capture(const CaptureRecord &rec) {
    // TODO(P0-design): append {dex_id, method_idx, off, len} to an index + copy the
    // CodeItem bytes into a per-dex blob (dedup by (dex_id, method_idx)). P0-simple does
    // whole-dex dumps in ObserveCodeItem and does not need per-method capture.
    (void)rec;
    std::lock_guard<std::mutex> g(lock_);
    ++capture_count_;
}

void CodeItemSink::Flush() {
    std::lock_guard<std::mutex> g(lock_);
    LOGI("[unpack] sink flush: dex={} captures={}", dex_count_, capture_count_);
}

}  // namespace vector::native::unpack

#endif  // VECTOR_UNPACK_ENABLED
