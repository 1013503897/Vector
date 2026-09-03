// codeitem_sink.cpp — see codeitem_sink.h. INERT until VECTOR_UNPACK_ENABLED.

#ifdef VECTOR_UNPACK_ENABLED

#include "unpack/codeitem_sink.h"

#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <zlib.h>      // adler32 (dex checksum)

#include <cerrno>
#include <csetjmp>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <utility>
#include <vector>

#include <common/logging.h>

#include "unpack/dex_layout.h"

namespace vector::native::unpack {

namespace {

// Minimal SHA-1 (for rebuilding the dex signature on device). Public-domain construction.
struct Sha1 {
    uint32_t h[5];
    uint64_t len;
    uint8_t buf[64];
    size_t bl;
    void init() {
        h[0] = 0x67452301; h[1] = 0xEFCDAB89; h[2] = 0x98BADCFE; h[3] = 0x10325476;
        h[4] = 0xC3D2E1F0; len = 0; bl = 0;
    }
    static uint32_t rol(uint32_t v, int b) { return (v << b) | (v >> (32 - b)); }
    void block(const uint8_t *p) {
        uint32_t w[80];
        for (int i = 0; i < 16; i++)
            w[i] = (p[i * 4] << 24) | (p[i * 4 + 1] << 16) | (p[i * 4 + 2] << 8) | p[i * 4 + 3];
        for (int i = 16; i < 80; i++) w[i] = rol(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
        uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4];
        for (int i = 0; i < 80; i++) {
            uint32_t f, k;
            if (i < 20) { f = (b & c) | (~b & d); k = 0x5A827999; }
            else if (i < 40) { f = b ^ c ^ d; k = 0x6ED9EBA1; }
            else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDC; }
            else { f = b ^ c ^ d; k = 0xCA62C1D6; }
            uint32_t t = rol(a, 5) + f + e + k + w[i];
            e = d; d = c; c = rol(b, 30); b = a; a = t;
        }
        h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e;
    }
    void update(const uint8_t *p, size_t n) {
        len += n;
        while (n) {
            size_t take = 64 - bl;
            if (take > n) take = n;
            memcpy(buf + bl, p, take);
            bl += take; p += take; n -= take;
            if (bl == 64) { block(buf); bl = 0; }
        }
    }
    void final(uint8_t out[20]) {
        uint64_t bits = len * 8;   // capture BEFORE padding (the pad bytes go through update())
        uint8_t pad = 0x80;
        update(&pad, 1);
        uint8_t z = 0;
        while (bl != 56) update(&z, 1);
        uint8_t lb[8];
        for (int i = 0; i < 8; i++) lb[i] = (uint8_t)(bits >> (56 - i * 8));
        update(lb, 8);
        for (int i = 0; i < 5; i++) {
            out[i * 4] = (uint8_t)(h[i] >> 24); out[i * 4 + 1] = (uint8_t)(h[i] >> 16);
            out[i * 4 + 2] = (uint8_t)(h[i] >> 8); out[i * 4 + 3] = (uint8_t)h[i];
        }
    }
};

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

// On-device dexfixer: scan a SAFE region copy for dex(es) by the surviving invariants
// (header_size==0x70 @ hdr+0x24, endian @ +0x28 — present even when the shell mangled the magic),
// reconstruct each into a valid .dex (rebuild magic + adler32 checksum + sha1 signature), and write
// it. This folds tools/dexfixer/dexfixer.py into the dump so the recipe emits jadx-ready .dex on
// device (no offline python). For an in-place-restore extraction shell (dpt) the restored CodeItems
// are already in the region, so the reconstructed dex is complete; parallel-structure shells still
// need the offline splice (captures.txt). `region` is the heap copy (no fault risk); `region_start`
// is the live VA for the filename (matches region_<start>_<size>.bin / splice.py).
void CodeItemSink::ReconstructDexesFromRegion(const uint8_t *region, size_t n, uintptr_t region_start) {
    int idx = 0;
    const int kMaxDexesPerRegion = 64;   // bound output on a region full of coincidental invariants
    for (size_t i = 4; i + 8 <= n && idx < kMaxDexesPerRegion; i += 4) {
        if (!(region[i] == 0x70 && region[i + 1] == 0 && region[i + 2] == 0 && region[i + 3] == 0))
            continue;
        if (!(region[i + 4] == 0x78 && region[i + 5] == 0x56 && region[i + 6] == 0x34 &&
              region[i + 7] == 0x12))
            continue;
        long base = (long)i - 0x24;                              // dex header start
        uint32_t file_size = *reinterpret_cast<const uint32_t *>(region + (i - 4));  // hdr+0x20
        // STRICT bounds: the whole dex must lie inside the region copy, so every read below
        // (memcpy, sha1, adler) is provably in-buffer — no edge over-read / SIGBUS. (Drops the
        // rare base<0 page-overhang case dexfixer.py handles; the device region copy starts at the
        // mapping, so a dex starting before it can't be fully reconstructed here anyway.)
        if (base < 0 || file_size <= 0x70 || (size_t)base + file_size > n) continue;

        // Reject a coincidental invariant match (the byte pattern 70 00 00 00 / 78 56 34 12 occurs
        // in real data): the section table must be self-consistent within file_size. (hdr[0x38..0x68]
        // is within [base, base+0x70) ⊆ [0, n), so these reads are safe.)
        const uint8_t *hdr = region + base;
        uint32_t sids_sz = *reinterpret_cast<const uint32_t *>(hdr + 0x38);
        uint32_t sids_off = *reinterpret_cast<const uint32_t *>(hdr + 0x3c);
        uint32_t cdef_sz = *reinterpret_cast<const uint32_t *>(hdr + 0x60);
        uint32_t cdef_off = *reinterpret_cast<const uint32_t *>(hdr + 0x64);
        if (!sids_sz || !cdef_sz || sids_sz > (1u << 23) || cdef_sz > (1u << 22)) continue;
        if ((uint64_t)sids_off + (uint64_t)sids_sz * 4 > file_size) continue;
        if ((uint64_t)cdef_off + (uint64_t)cdef_sz * 0x20 > file_size) continue;

        std::vector<uint8_t> dex(file_size);
        memcpy(dex.data(), region + base, file_size);            // [base, base+file_size) ⊆ [0, n)

        bool verdig = dex[4] >= '0' && dex[4] <= '9' && dex[5] >= '0' && dex[5] <= '9' &&
                      dex[6] >= '0' && dex[6] <= '9';
        if (!verdig) { dex[4] = '0'; dex[5] = '3'; dex[6] = '5'; }
        dex[0] = 'd'; dex[1] = 'e'; dex[2] = 'x'; dex[3] = '\n'; dex[7] = 0;   // magic
        Sha1 s;
        s.init();
        s.update(dex.data() + 32, file_size - 32);
        s.final(dex.data() + 12);                                // signature = sha1(dex[32:])
        uint32_t ck = (uint32_t)adler32(1L, dex.data() + 12, file_size - 12);  // checksum = adler32(dex[12:])
        memcpy(dex.data() + 8, &ck, 4);

        char path[360];
        if (idx == 0)
            snprintf(path, sizeof(path), "%s/region_%lx_%zu_fixed.dex", dir_,
                     (unsigned long)region_start, n);
        else
            snprintf(path, sizeof(path), "%s/region_%lx_%zu_fixed_%d.dex", dir_,
                     (unsigned long)region_start, n, idx);
        int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (fd >= 0) {
            size_t off = 0;
            while (off < file_size) {
                ssize_t w = write(fd, dex.data() + off, file_size - off);
                if (w <= 0) break;
                off += (size_t)w;
            }
            fsync(fd);
            close(fd);
            LOGI("[unpack] dex reconstructed -> {} ({} bytes, base_off={:#x})", path, file_size,
                 (long)base);
        }
        idx++;
    }
    if (idx == 0)
        LOGI("[unpack] region {:#x}: no dex invariants -> no on-device reconstruct",
             (unsigned long)region_start);
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

void CodeItemSink::DumpRegionContaining(const void *inner_ptr) {
    if (!inited_ || !inner_ptr) return;
    const uint8_t *inner = reinterpret_cast<const uint8_t *>(inner_ptr);
    {
        std::lock_guard<std::mutex> g(lock_);
        if (FindRangeLocked(inner) >= 0) return;  // region already dumped — hot path
    }
    uintptr_t vstart = 0, vend = 0;
    if (!FindMapping(reinterpret_cast<uintptr_t>(inner), &vstart, &vend, /*want_app=*/true))
        return;  // not an app region (framework dex / unreadable) — fail closed
    size_t rsize = vend - vstart;
    if (rsize < sizeof(dex::Header) || rsize > (96u << 20)) return;

    const uint8_t *live = reinterpret_cast<const uint8_t *>(vstart);
    std::vector<uint8_t> buf(rsize);
    InstallFaultGuard();
    bool ok = ReadRegionGuarded(live, rsize, buf.data());
    RemoveFaultGuard();
    if (!ok) return;

    std::lock_guard<std::mutex> g(lock_);
    if (FindRangeLocked(live) >= 0) return;  // another thread won the race
    uint32_t id = (uint32_t)dex_count_++;
    ranges_.push_back({live, live + rsize, id});

    // Raw region dump (header-agnostic) — keyed by live start so a mangled header doesn't matter.
    char path[320];
    snprintf(path, sizeof(path), "%s/region_%lx_%zu.bin", dir_, (unsigned long)vstart, rsize);
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd >= 0) {
        size_t off = 0;
        while (off < rsize) {
            ssize_t w = write(fd, buf.data() + off, rsize - off);
            if (w <= 0) break;
            off += (size_t)w;
        }
        fsync(fd);
        close(fd);
        LOGI("[unpack] region dump -> {} ({} bytes, inner +{})", path, off,
             (size_t)(inner - live));
    } else {
        LOGW("[unpack] region dump open failed: {} (errno={})", path, errno);
    }
    // Bonus: if the region ALSO starts with (or contains near the start) a clean dex header,
    // emit a proper .dex too so the common (non-mangled) case is directly jadx-loadable.
    const uint8_t *b = buf.data();
    if (dex::IsDexHeader(b)) {
        uint32_t fsize = dex::DexFileSize(b);
        if (fsize <= rsize) DumpDexLocked(b, fsize);
    }
}

void CodeItemSink::DumpRegionsForPointers(const void *const *ptrs, size_t n) {
    if (!inited_ || !ptrs || n == 0) return;

    // 1. Snapshot /proc/self/maps ONCE (vs. reopening it per pointer). Readable regions only;
    //    flag framework images (/system,/apex,/vendor,/product) so we never dump those.
    struct Reg {
        uintptr_t start, end;
        bool app;
    };
    std::vector<Reg> regs;
    {
        FILE *f = fopen("/proc/self/maps", "re");
        if (!f) return;
        char line[512];
        while (fgets(line, sizeof(line), f)) {
            uintptr_t s = 0, e = 0;
            char perms[5] = {0};
            if (sscanf(line, "%lx-%lx %4s", &s, &e, perms) != 3) continue;
            if (perms[0] != 'r') continue;
            bool app = true;
            const char *path = strchr(line, '/');
            if (path && (strncmp(path, "/system", 7) == 0 || strncmp(path, "/apex", 5) == 0 ||
                         strncmp(path, "/vendor", 7) == 0 || strncmp(path, "/product", 8) == 0))
                app = false;
            regs.push_back({s, e, app});
        }
        fclose(f);
    }
    if (regs.empty()) return;  // maps order is ascending by start -> binary-searchable

    // 2. Map every pointer to its region (largest start <= addr); mark distinct app regions.
    std::vector<char> hit(regs.size(), 0);
    for (size_t i = 0; i < n; i++) {
        uintptr_t a = reinterpret_cast<uintptr_t>(ptrs[i]);
        if (!a) continue;
        size_t lo = 0, hi = regs.size();
        while (lo < hi) {
            size_t mid = (lo + hi) / 2;
            if (regs[mid].start <= a)
                lo = mid + 1;
            else
                hi = mid;
        }
        if (lo == 0) continue;
        size_t idx = lo - 1;
        if (a < regs[idx].end && regs[idx].app) hit[idx] = 1;
    }

    // 3. Dump each distinct app region once, fault-guarded (one guard install for the whole pass).
    InstallFaultGuard();
    std::vector<uint8_t> buf;
    std::vector<std::pair<uintptr_t, size_t>> recon;  // (region_start, size) to reconstruct in pass 2
    size_t dumped = 0;
    for (size_t i = 0; i < regs.size(); i++) {
        if (!hit[i]) continue;
        const uintptr_t s = regs[i].start, e = regs[i].end;
        const size_t rsize = e - s;
        if (rsize < sizeof(dex::Header) || rsize > (96u << 20)) continue;
        const uint8_t *live = reinterpret_cast<const uint8_t *>(s);
        {
            std::lock_guard<std::mutex> g(lock_);
            if (FindRangeLocked(live) >= 0) continue;  // already dumped (a prior scan/pass)
        }
        // Multi-region dex: a real dex whose header.file_size EXCEEDS this VMA spans into the
        // following (contiguous) memory. Read file_size, not just rsize, so a large dex is captured
        // WHOLE instead of truncated — the plain VMA read + the burst scan's `i+fsize<=rsize` bound
        // both drop these, which is exactly why an extraction shell's big (multi-VMA) restored dexes
        // never reassembled. Peek the header first (page 0 of this region), then extend the read.
        size_t read_size = rsize;
        {
            uint8_t hdr[0x28];
            std::vector<uint8_t> peek(0x28);
            if (ReadRegionGuarded(live, 0x28, peek.data())) {
                memcpy(hdr, peek.data(), 0x28);
                if (hdr[0] == 'd' && hdr[1] == 'e' && hdr[2] == 'x' && hdr[3] == '\n') {
                    uint32_t fsz = *reinterpret_cast<const uint32_t *>(hdr + 0x20);
                    if (fsz > rsize && fsz <= (96u << 20)) read_size = fsz;
                }
            }
        }
        buf.resize(read_size);
        if (!ReadRegionGuarded(live, read_size, buf.data())) continue;

        std::lock_guard<std::mutex> g(lock_);
        if (FindRangeLocked(live) >= 0) continue;
        uint32_t id = (uint32_t)dex_count_++;
        ranges_.push_back({live, live + read_size, id});

        char path[320];
        snprintf(path, sizeof(path), "%s/region_%lx_%zu.bin", dir_, (unsigned long)s, read_size);
        int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (fd >= 0) {
            size_t off = 0;
            while (off < read_size) {
                ssize_t w = write(fd, buf.data() + off, read_size - off);
                if (w <= 0) break;
                off += (size_t)w;
            }
            fsync(fd);
            close(fd);
            dumped++;
            LOGI("[unpack] region dump -> {} ({} bytes{})", path, off,
                 read_size > rsize ? " [multi-region dex, extended to file_size]" : "");
        }
        // Defer on-device reconstruction to pass 2 (below) — it must run with NO fault guard
        // installed: reconstruction reads only safe heap, but if it ever faulted under the guard the
        // handler would siglongjmp to a stale jmp_buf (PC=0 crash). Record the region for pass 2.
        recon.emplace_back(s, read_size);
    }
    RemoveFaultGuard();

    // Pass 2: on-device dexfixer. Re-read each dumped region's .bin from disk (safe regular-file
    // I/O — no live memory) and emit jadx-ready .dex(es) by locating dex(es) via the surviving
    // header invariants. Folds tools/dexfixer/dexfixer.py onto the device. The reads are strictly
    // bounded, but we still run under the SIGSEGV/SIGBUS guard so a garbage invariant can never
    // crash the app — a fault just skips that region. (Own guard scope, distinct from pass 1's.)
    if (!recon.empty()) {
        InstallFaultGuard();
        for (auto &rc : recon) {
            char binpath[320];
            snprintf(binpath, sizeof(binpath), "%s/region_%lx_%zu.bin", dir_,
                     (unsigned long)rc.first, rc.second);
            FILE *bf = fopen(binpath, "re");
            if (!bf) continue;
            std::vector<uint8_t> rb(rc.second);
            size_t got = fread(rb.data(), 1, rc.second, bf);
            fclose(bf);
            if (got != rc.second) continue;
            if (sigsetjmp(g_fault_jmp, 1) == 0) {
                g_fault_active = 1;
                ReconstructDexesFromRegion(rb.data(), rc.second, rc.first);
            } else {
                LOGW("[unpack] reconstruct faulted for region {:#x}; skipped",
                     (unsigned long)rc.first);
            }
            g_fault_active = 0;
        }
        RemoveFaultGuard();

        // Remove any 0-byte *_fixed*.dex a fault-skipped reconstruction left behind (the SIGSEGV/
        // SIGBUS guard caught the fault after the file was open()'d but before the write completed).
        if (DIR *d = opendir(dir_)) {
            struct dirent *de;
            while ((de = readdir(d)) != nullptr) {
                if (!strstr(de->d_name, "_fixed") || !strstr(de->d_name, ".dex")) continue;
                char p[400];
                snprintf(p, sizeof(p), "%s/%s", dir_, de->d_name);
                struct stat st;
                if (stat(p, &st) == 0 && st.st_size == 0) unlink(p);
            }
            closedir(d);
        }
    }
    LOGI("[unpack] dexfind: dumped {} distinct app region(s)", dumped);
}

size_t CodeItemSink::DumpMethodCaptures(const MethodCapture *caps, size_t n) {
    if (!inited_ || !caps || n == 0) return 0;

    // Dump the regions the captures actually reference BEFORE keying captures.txt to them. The
    // captures' owning dexes (classdef pointers) frequently land in regions the dexfind `defs`
    // pass did NOT dump — e.g. a method-extraction shell whose GetCodeItem restore re-points the
    // class to a freshly-allocated "restored dex" region that isn't among the pre-restore `defs`.
    // Those regions are still mapped RIGHT NOW (region_of below finds them), but they're transient
    // and get recycled, so dump them here, at capture-flush time, or splice.py has captures.txt
    // keys with no matching region_<start>_<size>_fixed.dex. Dedup is handled inside
    // DumpRegionsForPointers (already-dumped regions are skipped).
    {
        static std::vector<const void *> cds;
        cds.clear();
        cds.reserve(n);
        for (size_t i = 0; i < n; i++)
            if (caps[i].classdef) cds.push_back(caps[i].classdef);
        if (!cds.empty()) DumpRegionsForPointers(cds.data(), cds.size());
    }

    // maps snapshot: classdef pointer -> owning region start (== the dumped region's key).
    std::vector<std::pair<uintptr_t, uintptr_t>> regs;  // sorted [start,end)
    {
        FILE *f = fopen("/proc/self/maps", "re");
        if (!f) return 0;
        char line[512];
        while (fgets(line, sizeof(line), f)) {
            uintptr_t s = 0, e = 0;
            char perms[5] = {0};
            if (sscanf(line, "%lx-%lx %4s", &s, &e, perms) != 3) continue;
            if (perms[0] == 'r') regs.emplace_back(s, e);
        }
        fclose(f);
    }
    if (regs.empty()) return 0;
    auto region_of = [&](uintptr_t a) -> uintptr_t {
        size_t lo = 0, hi = regs.size();
        while (lo < hi) {
            size_t m = (lo + hi) / 2;
            if (regs[m].first <= a) lo = m + 1; else hi = m;
        }
        if (lo == 0) return 0;
        return (a < regs[lo - 1].second) ? regs[lo - 1].first : 0;
    };

    char path[320];
    snprintf(path, sizeof(path), "%s/captures.txt", dir_);
    FILE *out = fopen(path, "we");
    if (!out) {
        LOGW("[unpack] captures.txt open failed (errno={})", errno);
        return 0;
    }

    // The CodeItem bytes are already a SAFE caller-owned copy (the finder copied them in the
    // trigger before the shell recycled the side structure), so no fault guard / live read here:
    // just resolve the owning dex region and hex-write the bytes.
    static char hexbuf[1 << 16];
    static const char *H = "0123456789abcdef";
    size_t written = 0;
    for (size_t i = 0; i < n; i++) {
        const uint8_t *b = caps[i].bytes;
        uint32_t len = caps[i].len;
        if (!b || len == 0 || len > sizeof(hexbuf) / 2) continue;
        uintptr_t rs = region_of(reinterpret_cast<uintptr_t>(caps[i].classdef));
        if (!rs) continue;  // owning dex not in a readable region
        for (uint32_t k = 0; k < len; k++) {
            hexbuf[k * 2] = H[b[k] >> 4];
            hexbuf[k * 2 + 1] = H[b[k] & 0xf];
        }
        fprintf(out, "%lx %u ", (unsigned long)rs, caps[i].method_idx);
        fwrite(hexbuf, 1, len * 2, out);
        fputc('\n', out);
        written++;
    }
    fclose(out);
    capture_count_ += written;
    LOGI("[unpack] captures: wrote {} method CodeItem(s) -> {}", written, path);
    return written;
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
