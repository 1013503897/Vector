// unpacker.cpp — see unpacker.h. INERT until VECTOR_UNPACK_ENABLED.
//
// Orchestration mirrors module.cpp RunTracelessConvert (module.cpp:307): a detached
// worker thread attaches to the ART runtime post-init, does the ART-touching work, then
// exits. Default OFF (gated by persist.kpmhook.unpack); fail-safe to no-op everywhere.

#ifdef VECTOR_UNPACK_ENABLED

#include "unpack/unpacker.h"

#include <dlfcn.h>
#include <fcntl.h>
#include <link.h>
#include <sys/stat.h>
#include <sys/system_properties.h>
#include <unistd.h>

#include <unwind.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <errno.h>
#include <sys/syscall.h>

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <set>
#include <string>
#include <thread>

#include <common/logging.h>
#include <dobby.h>  // control-arm backend for the openat probe (persist.kpmhook.unpack.openat_dobby=1)
#include <elf/elf_image.h>  // resolve libc-internal symbols (__openat) from .symtab/.gnu_debugdata

// Traceless KPM backend (defined in native/src/kpm, declared in core/native_api.h). Forward-
// declared here so the openat probe can call kpm_inline_hooker DIRECTLY -- traceless-ONLY, with
// NO Dobby fallback (a Dobby/inline patch gets the process SIGKILL'd by anti-tamper guards).
extern "C" void *kpm_inline_hooker(void *target, void *hooker);
extern "C" int kpm_inline_unhooker(void *func);
// mm-gated maps-hide: filters the page/VMA containing `addr` out of in-process /proc/self/{maps,
// smaps} reads (kernel-side, so it works no matter how the target reads maps). Used to hide the
// injected module .so + trampolines from GCash's libloader maps-scan RASP.
extern "C" int kpm_hide_region(void *addr);
// Identify this process to the KPM's proc_is_target() gate (which compares against
// persist.kpmhook.target). Vector's normal path sets this in module.cpp, but only AFTER
// StartIfEnabled and only for in-scope apps -- so the traceless worker must set it itself
// or the gate latches g_init_failed on the stale "zygote64" cmdline.
extern "C" void kpm_hook_set_process_name(const char *name);
// Rev1-(1): host every traceless clone in VMA-less kernel memory (KPM `pghookg`) instead of
// an anon RX mmap, so the recompiled hook code is unreachable by maps/mincore enumeration.
// Off by default in the backend; enabled once in StartIfEnabled. Safe: on a pre-0.6.2 KPM the
// pghookg reply isn't "ok", the hook returns NULL, and we fall back exactly as before.
extern "C" void kpm_hook_set_ghost(int on);
// fs-hide: register this process's tgid so the KPM spoofs its statfs f_type (overlayfs->erofs) and
// drops overlay/magisk lines from its mountinfo -- defeats the "hidden overlayfs" mount detection.
// Needs shpte KPM >= v0.6.6 (older KPM replies "usage:" -> harmless no-op). Gated persist.kpmhook.fshide.
extern "C" void kpm_hook_fshide_enable(void);

#include "unpack/art_internal.h"      // CalibrateForMethodEnum (increment-2)
#include "unpack/choke_hook.h"        // ChokePoint
#include "unpack/class_dex_finder.h"  // FindAndDumpClassDexes (direction-1 increment-1/2)
#include "unpack/codeitem_sink.h"
#include "unpack/interp_capture.h"    // CaptureInterpreted (direction-1 increment-2c)
#include "unpack/method_enumerator.h" // Tier, EnumerateAndDrive

namespace vector::native::unpack {

namespace {

// Prop-gated run config (fully internal; the public header exposes only StartIfEnabled).
struct Config {
    bool enabled = false;                                  // persist.kpmhook.unpack = 1
    Tier tier = Tier::kPassive;                            // .tier = A|B|C (P0 = A)
    bool stealth = false;                                  // .stealth = 0|1
    ChokePoint choke = ChokePoint::kArtMethodGetCodeItem;  // .choke = getcodeitem|invoke|bridge|execute
    bool dexfind = false;                                  // .dexfind = 1 (direction-1 increment-1)
    bool trigger = false;                                  // .trigger = 1 (increment-2 per-method restore)
    bool interp = false;                                   // .interp = 1 (increment-2c interpreter capture)
    bool active_load = false;                              // .activeload = 1 (increment-2d force-load all classes)
    bool extout = false;                                   // .extout = 1 (write dumps to app EXTERNAL dir, pullable past SELinux MLS)
    bool traceless = false;                                // .traceless = 1 (KPM clone hook for dexfind FindClass; RASP-safe)
    bool openat_probe = false;                             // .openat = 1 (traceless openat probe; frida-parallel)
    int openat_ms = 20000;                                 // .openat_ms (probe window)
    bool openat_dobby = false;                             // .openat_dobby = 1 (control arm: DobbyHook not KPM)
    bool gcash_fix = false;                                // .gcashfix = 1 (KPM-traceless neutralize GCash Ant-APSE libloader RASP)
    unsigned long gcash_off = 0x1d0bb0;                    // .gcashoff (libloader detect-fn offset; RE: FUN_002d0bb0)
};

// ---- openat traceless probe (frida-parallel; persist.kpmhook.unpack.openat=1) ---------------
// Installs a KPM-TRACELESS inline hook on libc openat and logs DISTINCT file paths for a window.
// Proves a Vector traceless hook SURVIVES + captures data on an app where frida and a Dobby hook
// both get the process killed. Traceless-only: if kpm_inline_hooker fails (bridge down) we skip
// rather than fall back to Dobby (which would trip the anti-tamper SIGKILL).
std::mutex g_oa_mu;
std::set<std::string> g_oa_seen;
std::atomic<uint64_t> g_open_hits{0};
std::atomic<uint64_t> g_openat_hits{0};
thread_local bool g_oa_in = false;
using OpenFn = int (*)(const char *, int, int);
using OpenatFn = int (*)(int, const char *, int, int);
OpenFn g_open_orig = nullptr;
OpenatFn g_openat_orig = nullptr;

void RecordPath(const char *tag, const char *path, int flags, int fd) {
    if (g_oa_in || !path) return;
    g_oa_in = true;  // re-entrancy guard: LOGI below may itself open() the logd socket once
    std::string p(path);
    bool fresh;
    {
        std::lock_guard<std::mutex> lk(g_oa_mu);
        fresh = g_oa_seen.insert(p).second;
    }
    if (fresh) LOGI("[openat] ({}) {} flags=0x{:x} -> fd={}", tag, p.c_str(), flags, fd);
    g_oa_in = false;
}

int OpenProbeHook(const char *path, int flags, int mode) {
    int fd = g_open_orig ? g_open_orig(path, flags, mode) : -1;
    g_open_hits.fetch_add(1, std::memory_order_relaxed);
    RecordPath("open", path, flags, fd);
    return fd;
}

int OpenatProbeHook(int dirfd, const char *path, int flags, int mode) {
    int fd = g_openat_orig ? g_openat_orig(dirfd, path, flags, mode) : -1;
    g_openat_hits.fetch_add(1, std::memory_order_relaxed);
    RecordPath("openat", path, flags, fd);
    return fd;
}

// Hook one libc symbol via the chosen backend; store its backup(orig) via `store`. Returns the
// hooked address (for later unhook) or nullptr on failure. use_dobby=false -> KPM traceless (no
// Dobby fallback); use_dobby=true -> DobbyHook inline patch (the frida-parallel A/B CONTROL arm:
// an inline patch is what an anti-tamper code-integrity scan is meant to catch).
void *HookLibcFn(const char *sym, void *hook, void (*store)(void *), bool use_dobby) {
    void *addr = dlsym(RTLD_DEFAULT, sym);
    if (!addr) {
        LOGW("[openat] dlsym({}) failed", sym);
        return nullptr;
    }
    void *backup = nullptr;
    if (use_dobby) {
        if (DobbyHook(addr, reinterpret_cast<dobby_dummy_func_t>(hook),
                      reinterpret_cast<dobby_dummy_func_t *>(&backup)) != 0) {
            LOGW("[openat] DobbyHook({}) failed", sym);
            return nullptr;
        }
    } else {
        backup = kpm_inline_hooker(addr, hook);
        if (!backup) {
            LOGW("[openat] kpm_inline_hooker({}) FAILED (bridge down / not gated) -- traceless-only", sym);
            return nullptr;
        }
    }
    store(backup);
    LOGI("[openat] {} hook on {} @ {} (backup={})", use_dobby ? "DOBBY" : "TRACELESS", sym, addr, backup);
    return addr;
}

void RunOpenatProbe(int window_ms, bool use_dobby) {
    LOGI("[openat] backend = {}", use_dobby ? "DOBBY inline-patch (control arm)" : "KPM-TRACELESS");
    // Hook BOTH open and openat: bionic routes many file opens through open()->__openat, which
    // bypasses the public openat symbol -- so hooking openat alone under-captures. Per-fn hit
    // counters disambiguate "the reroute/patch never fired" from "that symbol was just cold".
    void *open_addr =
        HookLibcFn("open", reinterpret_cast<void *>(&OpenProbeHook),
                   [](void *b) { g_open_orig = reinterpret_cast<OpenFn>(b); }, use_dobby);
    void *openat_addr =
        HookLibcFn("openat", reinterpret_cast<void *>(&OpenatProbeHook),
                   [](void *b) { g_openat_orig = reinterpret_cast<OpenatFn>(b); }, use_dobby);
    if (!open_addr && !openat_addr) {
        LOGW("[openat] no hook installed -- abort probe");
        return;
    }
    LOGI("[openat] logging distinct paths for {}ms ...", window_ms);
    usleep((useconds_t)window_ms * 1000);
    if (use_dobby) {
        // Do NOT DobbyDestroy: open is hot (100s of calls/window); unpatching while an app
        // thread is inside the trampoline spins/hangs the worker (same hazard as the interp
        // Execute hook). The control arm only needs the survival signal, so leave it patched.
        LOGI("[openat] (dobby control arm: hooks left installed -- hot-fn destroy would hang)");
    } else {
        if (open_addr) kpm_inline_unhooker(open_addr);
        if (openat_addr) kpm_inline_unhooker(openat_addr);
    }
    size_t n;
    {
        std::lock_guard<std::mutex> lk(g_oa_mu);
        n = g_oa_seen.size();
    }
    LOGI("[openat] done: open fired {}x, openat fired {}x, {} distinct path(s); {}",
         g_open_hits.load(), g_openat_hits.load(), n,
         use_dobby ? "dobby hooks LEFT installed" : "traceless hooks removed");
}

bool PropIs(const char *name, char want) {
    char v[PROP_VALUE_MAX] = {0};
    return __system_property_get(name, v) > 0 && v[0] == want;
}

int PropInt(const char *name, int dflt) {
    char v[PROP_VALUE_MAX] = {0};
    if (__system_property_get(name, v) <= 0 || !v[0]) return dflt;
    int n = atoi(v);
    return n > 0 ? n : dflt;
}

// stealth=0 (Dobby) gate: only run in the process named by persist.kpmhook.target. If the
// prop is unset/empty, allow (caller already limits to Vector's injection scope). NOTE:
// /proc/self/cmdline is still "zygote64" at postAppSpecialize time, so the caller passes the
// real nice name. The stealth=1 path is additionally gated by the KPM itself.
bool ProcessMatchesTarget(const char *process_name) {
    char want[PROP_VALUE_MAX] = {0};
    if (__system_property_get("persist.kpmhook.target", want) <= 0 || !want[0]) return true;
    return process_name && strcmp(process_name, want) == 0;
}

Tier ParseTier() {
    char v[PROP_VALUE_MAX] = {0};
    if (__system_property_get("persist.kpmhook.unpack.tier", v) <= 0) return Tier::kPassive;
    switch (v[0]) {
        case 'B': case 'b': return Tier::kForceCompile;
        case 'C': case 'c': return Tier::kInvoke;
        case 'A': case 'a': default: return Tier::kPassive;
    }
}

ChokePoint ParseChoke() {
    char v[PROP_VALUE_MAX] = {0};
    if (__system_property_get("persist.kpmhook.unpack.choke", v) <= 0)
        return ChokePoint::kArtMethodGetCodeItem;
    if (v[0] == 'i') return ChokePoint::kArtMethodInvoke;
    if (v[0] == 'b') return ChokePoint::kInterpreterBridge;
    if (v[0] == 'e') return ChokePoint::kExecute;
    return ChokePoint::kArtMethodGetCodeItem;
}

// ---- GCash Ant-APSE libloader RASP neutralize (persist.kpmhook.unpack.gcashfix=1) -----------
// RE (subagent): libloader = Ant/Alipay APSE packer; FUN_002d0bb0 @ off 0x1d0bb0 decrypts the
// string "/proc/self/maps", reads it, strcasecmp-scans each line vs a blocklist, returns w20=1 on
// a hit (an injected .so) -> falls through to _exit. libloader SELF-CRCs its .text, so a
// Dobby/inline patch is detected (each extra hook killed GCash faster). The KPM whole-page clone
// hook leaves the ORIGINAL .text byte-identical (self-CRC reads pass) while rerouting EXECUTION to
// the clone -> traceless-hook the detect fn to just return 0 (clean verdict), so libloader never
// self-exits. Offset is prop-overridable (persist.kpmhook.unpack.gcashoff) for iteration.
uintptr_t FindLibBase(const char *name) {
    FILE *f = fopen("/proc/self/maps", "re");
    if (!f) return 0;
    char line[600];
    uintptr_t base = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, name)) {
            uintptr_t s = strtoul(line, nullptr, 16);
            if (s && (base == 0 || s < base)) base = s;
        }
    }
    fclose(f);
    return base;
}

// A maps line is an injected/anomalous region libloader's RASP would flag: a module .so under
// /data/adb/modules (zygisk_vector / zygisksu / phoenix / riru), or a lone rwxp anon page (an
// LSPlant trampoline / KPM clone). We do NOT hide libloader itself or app/system libs.
bool MapsLineIsInjected(const char *line) {
    if (strstr(line, "/data/adb/") || strstr(line, "zygisk") || strstr(line, "riru") ||
        strstr(line, "libphoenix") || strstr(line, "/vector"))
        return true;
    // lone rwxp anon (no pathname): perms field "rwxp" and the line has no '/'
    const char *sp = strchr(line, ' ');
    if (sp && strncmp(sp + 1, "rwxp", 4) == 0 && !strchr(line, '/') && !strstr(line, "[anon:"))
        return true;
    return false;
}

// ---- next-layer diagnosis + neutralize: the SIGKILL that fires after maps-scan is defeated ----
// KPM-traceless-hook libc kill/tgkill: block a lethal self-directed signal (the RASP's kill path)
// and unwind-log the caller so we can identify + locate the NEXT detection. Traceless (KPM clone)
// so libloader's .text/libc self-CRC stays clean.
struct GcBt { void **f; int n; int max; };
static _Unwind_Reason_Code GcTraceCb(struct _Unwind_Context *c, void *a) {
    GcBt *s = reinterpret_cast<GcBt *>(a);
    void *pc = reinterpret_cast<void *>(_Unwind_GetIP(c));
    if (pc && s->n < s->max) s->f[s->n++] = pc;
    return s->n >= s->max ? _URC_END_OF_STACK : _URC_NO_REASON;
}
void GcLogCaller(const char *what, int arg) {
    void *fr[8];
    GcBt st{fr, 0, 8};
    _Unwind_Backtrace(GcTraceCb, &st);
    LOGW("[gcashfix] BLOCK {}({}) — caller chain:", what, arg);
    for (int i = 0; i < st.n; i++) {
        Dl_info di;
        if (dladdr(fr[i], &di) && di.dli_fname) {
            const char *b = strrchr(di.dli_fname, '/');
            b = b ? b + 1 : di.dli_fname;
            LOGW("[gcashfix]   #{} {}+0x{:x}", i, b,
                 (unsigned long)fr[i] - (unsigned long)di.dli_fbase);
        }
    }
}
// dl_iterate_phdr module-enumeration filter: libloader's SECOND way to find injected modules
// (walks the linker's in-memory link_map, NOT /proc/self/maps -> maps-hide can't touch it). Hook
// it (KPM-traceless) and drop injected modules from the callback so the scan sees a clean set.
struct GcDlWrap { int (*cb)(struct dl_phdr_info *, size_t, void *); void *data; };
int GcDlFilterCb(struct dl_phdr_info *info, size_t size, void *data) {
    GcDlWrap *w = reinterpret_cast<GcDlWrap *>(data);
    const char *n = info->dlpi_name;
    if (n && (strstr(n, "zygisk") || strstr(n, "/data/adb") || strstr(n, "libphoenix") ||
              strstr(n, "riru") || strstr(n, "/vector")))
        return 0;  // skip injected module (don't surface it to the real callback)
    return w->cb(info, size, w->data);
}
int (*g_gc_orig_dlip)(int (*)(struct dl_phdr_info *, size_t, void *), void *) = nullptr;
extern "C" int GcashDlIterateHook(int (*cb)(struct dl_phdr_info *, size_t, void *), void *data) {
    if (!g_gc_orig_dlip) return -1;
    GcDlWrap w{cb, data};
    return g_gc_orig_dlip(GcDlFilterCb, &w);
}

void GcDumpJavaStack(const char *why);  // fwd (defined below, near the kill hooks)
// Shamiko-style root-file hiding: GCash's Java root detection (File.exists/canRead) resolves to
// libc faccessat/fstatat. Return ENOENT for known root paths so the scan finds a clean device.
static bool GcIsRootPath(const char *p) {
    if (!p) return false;
    static const char *bl[] = {
        "/debug_ramdisk", "/data/adb", "/sbin/su", "/system/bin/su", "/system/xbin/su",
        "/vendor/bin/su", "/product/bin/su", "/su/bin", "vsync_svc_hlpr", "/dev/su",
        "/data/local/tmp/su", "supersu", "SuperSU", "/system/app/Superuser", "busybox",
        "magisk", ".magisk", "riru", "zygisk", "lsposed", "xposed", "apatch", "/data/adb/ap",
        "kernelsu", "/system/xbin/busybox", "/cache/su", nullptr};
    for (int i = 0; bl[i]; i++)
        if (strstr(p, bl[i])) return true;
    return false;
}
int (*g_gc_orig_faccessat)(int, const char *, int, int) = nullptr;
int (*g_gc_orig_fstatat)(int, const char *, void *, int) = nullptr;
int (*g_gc_orig_openat)(int, const char *, int, int) = nullptr;
// A mount/proc line that would reveal root (module mounts, overlay, /data/adb, magisk, su path).
static bool GcMountLineDirty(const char *line) {
    if (strstr(line, "/data/adb") || strstr(line, "magisk") || strstr(line, "overlay") ||
        strstr(line, "meta-overlayfs") || strstr(line, "vsync_svc_hlpr") || strstr(line, "riru") ||
        strstr(line, "KSU") || strstr(line, "zygisk") || strstr(line, "/debug_ramdisk") ||
        strstr(line, "libphoenix") || strstr(line, "/vector"))
        return true;
    // maps: a lone rwxp anon region (KPM clone / LSPlant trampoline) -- exec+writable, no path.
    const char *sp = strchr(line, ' ');
    if (sp && strncmp(sp + 1, "rwxp", 4) == 0 && !strchr(line, '/') && !strstr(line, "[anon:"))
        return true;
    return false;
}
// Hook __openat: for /proc/{mounts,self/mountinfo,self/mounts}, return a memfd holding the file
// with root-revealing lines filtered out. Java File reads (open()->__openat) then see a clean view.
extern "C" int GcashOpenatHook(int dirfd, const char *path, int flags, int mode) {
    if (path && (strstr(path, "/proc/") || strstr(path, "/sys/")) &&
        !strstr(path, "/proc/self/task") && !strstr(path, "cgroup"))
        LOGI("[gcashfix] OPEN {}", path);  // diagnostic: what /proc,/sys does GCash read?
    // NOTE: /proc/self/maps is NOT sanitized here -- the kernel maps-hide (kpm_hide_region) filters
    // its content in-kernel, so readlink(/proc/self/fd/N) still shows the real path (a memfd
    // substitution would be detectable via /proc/self/fd, which RASPs scan). Only /proc/mounts
    // (rarely readlink'd) goes through the memfd path.
    if (path && g_gc_orig_openat &&
        (strstr(path, "/proc/mounts") || strstr(path, "/proc/self/mountinfo") ||
         strstr(path, "/proc/self/mounts") || strstr(path, "/proc/1/mounts"))) {
        int real = g_gc_orig_openat(dirfd, path, O_RDONLY | O_CLOEXEC, 0);
        if (real >= 0) {
            std::string clean;
            char buf[8192];
            std::string cur;
            ssize_t n;
            while ((n = read(real, buf, sizeof(buf))) > 0) cur.append(buf, n);
            close(real);
            size_t start = 0;
            while (start < cur.size()) {
                size_t nl = cur.find('\n', start);
                if (nl == std::string::npos) nl = cur.size();
                std::string line = cur.substr(start, nl - start);
                if (!GcMountLineDirty(line.c_str())) { clean += line; clean += '\n'; }
                start = nl + 1;
            }
            int mfd = syscall(__NR_memfd_create, "m", 0);
            if (mfd >= 0) {
                write(mfd, clean.data(), clean.size());
                lseek(mfd, 0, SEEK_SET);
                return mfd;
            }
        }
    }
    return g_gc_orig_openat ? g_gc_orig_openat(dirfd, path, flags, mode) : -1;
}
std::atomic<int> g_gc_stack_dumps{0};
extern "C" int GcashFaccessatHook(int dirfd, const char *path, int mode, int flags) {
    if (GcIsRootPath(path)) {
        LOGI("[gcashfix] HIDE access({})", path ? path : "?");
        if (g_gc_stack_dumps.fetch_add(1) < 2) GcDumpJavaStack("root-file scan (access)");
        errno = ENOENT;
        return -1;
    }
    return g_gc_orig_faccessat ? g_gc_orig_faccessat(dirfd, path, mode, flags) : -1;
}
extern "C" int GcashFstatatHook(int dirfd, const char *path, void *buf, int flags) {
    if (GcIsRootPath(path)) { LOGI("[gcashfix] HIDE stat({})", path ? path : "?"); errno = ENOENT; return -1; }
    return g_gc_orig_fstatat ? g_gc_orig_fstatat(dirfd, path, buf, flags) : -1;
}

// Dump the CURRENT thread's Java stack (the thread that called Process.killProcess / decided to
// finish) -> reveals which GCash class/method drives the close. Uses vm->GetEnv (the calling thread
// is a live app Java thread, already attached). PROOF, not inference.
JavaVM *g_gc_vm = nullptr;
void GcDumpJavaStack(const char *why) {
    if (!g_gc_vm) return;
    JNIEnv *env = nullptr;
    if (g_gc_vm->GetEnv(reinterpret_cast<void **>(&env), JNI_VERSION_1_6) != JNI_OK || !env) return;
    if (env->ExceptionCheck()) env->ExceptionClear();
    jclass thrCls = env->FindClass("java/lang/Thread");
    jclass steCls = env->FindClass("java/lang/StackTraceElement");
    if (!thrCls || !steCls) { env->ExceptionClear(); return; }
    jmethodID curThr = env->GetStaticMethodID(thrCls, "currentThread", "()Ljava/lang/Thread;");
    jmethodID getStk = env->GetMethodID(thrCls, "getStackTrace", "()[Ljava/lang/StackTraceElement;");
    jmethodID toStr = env->GetMethodID(steCls, "toString", "()Ljava/lang/String;");
    if (!curThr || !getStk || !toStr) { env->ExceptionClear(); return; }
    jobject thr = env->CallStaticObjectMethod(thrCls, curThr);
    jobjectArray stk = reinterpret_cast<jobjectArray>(env->CallObjectMethod(thr, getStk));
    if (!stk) { env->ExceptionClear(); return; }
    jsize n = env->GetArrayLength(stk);
    LOGW("[gcashfix] JAVA STACK at {} ({} frames):", why, (int)n);
    for (jsize i = 0; i < n && i < 30; i++) {
        jobject ste = env->GetObjectArrayElement(stk, i);
        jstring s = reinterpret_cast<jstring>(env->CallObjectMethod(ste, toStr));
        if (s) {
            const char *cs = env->GetStringUTFChars(s, nullptr);
            LOGW("[gcashfix]   #{} {}", (int)i, cs ? cs : "?");
            if (cs) env->ReleaseStringUTFChars(s, cs);
        }
        env->DeleteLocalRef(ste);
        if (s) env->DeleteLocalRef(s);
    }
    if (env->ExceptionCheck()) env->ExceptionClear();
}

static bool GcLethal(int sig) { return sig == 9 || sig == 6 || sig == 4 || sig == 11; }
int (*g_gc_orig_kill)(pid_t, int) = nullptr;
int (*g_gc_orig_tgkill)(int, int, int) = nullptr;
// BLOCK the self-directed lethal signal. The RE-confirmed kill is Java `Process.killProcess(self)`
// -> Process.sendSignal -> libc kill(pid,9); no-op'ing it just returns to GCash's Java code (void,
// no return check) so the app keeps running -- unlike libloader's NATIVE self-kill (which we avoid
// triggering by hiding the injection via maps-hide + dl_iterate). Return 0 = "signal sent OK".
extern "C" int GcashKillHook(pid_t pid, int sig) {
    if (GcLethal(sig) && (pid == getpid() || pid <= 0)) {
        GcLogCaller("kill", sig);
        GcDumpJavaStack("kill(self)");
        return 0;
    }
    return g_gc_orig_kill ? g_gc_orig_kill(pid, sig) : -1;
}
extern "C" int GcashTgkillHook(int tgid, int tid, int sig) {
    if (GcLethal(sig) && (tgid == getpid() || tgid <= 0)) {
        GcLogCaller("tgkill", sig);
        GcDumpJavaStack("tgkill(self)");
        return 0;
    }
    return g_gc_orig_tgkill ? g_gc_orig_tgkill(tgid, tid, sig) : -1;
}

// seccomp: kernel BPF filter blocking the RASP's inline-svc self-kill (exit_group + lethal
// kill/tgkill). Syscall-level -> catches the inline svc that libc-function hooks miss; modifies NO
// .text -> libloader's self-CRC stays clean (unlike svc-instrument). TSYNC applies it to ALL
// threads (incl. the RASP detection threads). exit(93) stays allowed so a detection THREAD can
// exit while the PROCESS survives.
void InstallGcashSeccomp() {
    struct sock_filter f[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 94, 11, 0),  // exit_group -> BLOCK(13)
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 129, 2, 0),  // kill       -> CHK_KILL(5)
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 131, 5, 0),  // tgkill     -> CHK_TG(9)
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[1])),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 9, 6, 0),  // SIGKILL -> BLOCK
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 6, 5, 0),  // SIGABRT -> BLOCK
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[2])),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 9, 2, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 6, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)),
    };
    struct sock_fprog prog = {(unsigned short)(sizeof(f) / sizeof(f[0])), f};
    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);  // required for an unprivileged filter
    long r = syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_TSYNC, &prog);
    if (r == 0)
        LOGI("[gcashfix] seccomp installed (TSYNC all-threads): block exit_group + lethal kill/tgkill");
    else
        LOGW("[gcashfix] seccomp(TSYNC) failed: {}", strerror(errno));
}

// Hide every injected/anomalous maps region so libloader's /proc/self/maps blocklist scan finds
// nothing. Kernel mm-gated (kpm_hide_region) -> defeats the scan no matter how it reads maps, and
// leaves all code byte-identical (self-CRC clean). Repeated a few rounds: new trampolines/clones
// and the module .so may map at slightly different times during startup.
void RunGcashNeutralize(JavaVM *vm, unsigned long off) {
    (void)off;
    g_gc_vm = vm;  // for GcDumpJavaStack (proof of what code drives the close)
    // Install the hooks ASAP -- root/tamper detection fires very early (OneApp exits ~10s). Only a
    // brief settle so our injected .so is mapped (it is, at inject time). (Was a GCash-specific
    // 8s wait for libloader.so, which starved non-GCash targets of their hooks before they ran.)
    usleep(150 * 1000);

    // Prevent DETECTION (not block the response -- blocking exit/kill just crashes libloader, which
    // isn't built to survive its own self-kill failing). Hide the injected modules from BOTH
    // enumeration methods: /proc/self/maps (maps-hide loop below) AND dl_iterate_phdr (link_map).
    // Resolve libc symbols by ADDRESS (&fn); dlsym(RTLD_DEFAULT,...) returned NULL in the injected
    // .so's namespace. Hide the injected modules from dl_iterate_phdr (link_map enumeration).
    void *dl = reinterpret_cast<void *>(&dl_iterate_phdr);
    {
        void *bk = kpm_inline_hooker(dl, reinterpret_cast<void *>(&GcashDlIterateHook));
        if (bk) {
            g_gc_orig_dlip = reinterpret_cast<int (*)(int (*)(struct dl_phdr_info *, size_t, void *),
                                                      void *)>(bk);
            LOGI("[gcashfix] traceless-hooked dl_iterate_phdr @ {} (hide injected modules)", dl);
        } else {
            LOGW("[gcashfix] kpm_inline_hooker(dl_iterate_phdr) FAILED");
        }
    }
    // kill + tgkill BLOCK hooks: stop GCash's Java `Process.killProcess(self)` root-detection
    // response. Resolve by address (&fn); tgkill has no libc wrapper decl on bionic, resolve via
    // dlsym as a fallback.
    void *kf = reinterpret_cast<void *>(&kill);
    {
        void *bk = kpm_inline_hooker(kf, reinterpret_cast<void *>(&GcashKillHook));
        if (bk) { g_gc_orig_kill = reinterpret_cast<int (*)(pid_t, int)>(bk);
                  LOGI("[gcashfix] traceless-hooked kill @ {} (BLOCK self)", kf); }
        else LOGW("[gcashfix] kpm_inline_hooker(kill) FAILED");
    }
    void *tf = dlsym(RTLD_DEFAULT, "tgkill");
    if (!tf) {
        vector::native::ElfImage libc("libc.so");
        if (libc.IsValid()) tf = const_cast<void *>(libc.getSymbAddress<const void *>("tgkill"));
    }
    if (tf) {
        void *bk = kpm_inline_hooker(tf, reinterpret_cast<void *>(&GcashTgkillHook));
        if (bk) { g_gc_orig_tgkill = reinterpret_cast<int (*)(int, int, int)>(bk);
                  LOGI("[gcashfix] traceless-hooked tgkill @ {} (BLOCK self)", tf); }
        else LOGW("[gcashfix] kpm_inline_hooker(tgkill) FAILED");
    } else {
        LOGW("[gcashfix] tgkill symbol not found");
    }
    // Shamiko-style root-file hiding: hook faccessat + fstatat -> ENOENT for root paths, so GCash's
    // Java File.exists()/canRead() root detection sees a clean device (it can't decide to close).
    void *af = reinterpret_cast<void *>(&faccessat);
    if (af) {
        void *bk = kpm_inline_hooker(af, reinterpret_cast<void *>(&GcashFaccessatHook));
        if (bk) { g_gc_orig_faccessat = reinterpret_cast<int (*)(int, const char *, int, int)>(bk);
                  LOGI("[gcashfix] traceless-hooked faccessat @ {} (hide root paths)", af); }
        else LOGW("[gcashfix] kpm_inline_hooker(faccessat) FAILED");
    }
    void *sf = reinterpret_cast<void *>(&fstatat);
    if (sf) {
        void *bk = kpm_inline_hooker(sf, reinterpret_cast<void *>(&GcashFstatatHook));
        if (bk) { g_gc_orig_fstatat = reinterpret_cast<int (*)(int, const char *, void *, int)>(bk);
                  LOGI("[gcashfix] traceless-hooked fstatat @ {} (hide root paths)", sf); }
        else LOGW("[gcashfix] kpm_inline_hooker(fstatat) FAILED");
    } else {
        LOGW("[gcashfix] fstatat symbol not found");
    }
    // Hook __openat (the internal both open()+openat() funnel through; libloader hooks the public
    // `open`, not this) to sanitize /proc/{mounts,self/mountinfo} -> hide module/overlay mounts.
    // GATED OFF by default (persist.kpmhook.unpack.gcashopenat=1 to enable): hooking __openat, a
    // very hot libc funnel, self-interferes with Vector's OWN hook-dex loading (openDexFileNative ->
    // ZipArchive::OpenFromFdInternal -> SIGSEGV in libartbase). faccessat/fstatat already hide root.
    if (PropInt("persist.kpmhook.unpack.gcashopenat", 0)) {
        void *of = dlsym(RTLD_DEFAULT, "__openat");
        if (!of) {
            vector::native::ElfImage libc("libc.so");
            if (libc.IsValid()) {
                of = const_cast<void *>(libc.getSymbAddress<const void *>("__openat"));
                if (!of) of = const_cast<void *>(libc.getSymbAddress<const void *>("___openat"));
            }
        }
        if (of) {
            void *bk = kpm_inline_hooker(of, reinterpret_cast<void *>(&GcashOpenatHook));
            if (bk) { g_gc_orig_openat = reinterpret_cast<int (*)(int, const char *, int, int)>(bk);
                      LOGI("[gcashfix] traceless-hooked __openat @ {} (sanitize /proc/mounts)", of); }
            else LOGW("[gcashfix] kpm_inline_hooker(__openat) FAILED");
        } else {
            LOGW("[gcashfix] __openat symbol not found");
        }
    } else {
        LOGI("[gcashfix] __openat hook SKIPPED (gated off — avoids Vector dex-load self-interference)");
    }

    // Dump libloader's runtime-DECRYPTED 2nd-detection region (RE: exit site 0x386adc, encrypted
    // on disk) to logcat, for offline RE of what that inline-svc-self-kill check reads.
    {
        uintptr_t lb = FindLibBase("libloader.so");
        if (lb) {
            const unsigned char *p = reinterpret_cast<const unsigned char *>(lb + 0x386800);
            for (unsigned o = 0; o < 0x800; o += 32) {
                char hex[80];
                int n = 0;
                for (int j = 0; j < 32; j++) n += snprintf(hex + n, sizeof(hex) - n, "%02x", p[o + j]);
                LOGI("[gcashdump] +{:x} {}", 0x386800 + o, hex);
            }
        }
    }

    int total_hidden = 0;
    for (int round = 0; round < 30; round++) {  // ~6s of coverage @200ms
        FILE *f = fopen("/proc/self/maps", "re");
        if (!f) break;
        char line[600];
        int this_round = 0;
        while (fgets(line, sizeof(line), f)) {
            if (!MapsLineIsInjected(line)) continue;
            uintptr_t start = 0, end = 0;
            if (sscanf(line, "%lx-%lx", &start, &end) != 2 || !start || end <= start) continue;
            // One hide at the VMA start (hidergn is expected VMA-granular). If a test shows a VMA
            // only partially hidden, switch to a per-page loop here.
            if (kpm_hide_region(reinterpret_cast<void *>(start))) {
                total_hidden++;
                this_round++;
            }
        }
        fclose(f);
        if (round == 0)
            LOGI("[gcashfix] maps-hide round0: hid {} injected VMA(s)", this_round);
        usleep(200 * 1000);
    }
    LOGI("[gcashfix] maps-hide done: {} page-hides total", total_hidden);
}

void WorkerMain(JavaVM *vm, Config cfg, std::string out_dir) {
    // GCash Ant-APSE neutralize: race to KPM-traceless-hook libloader's detect fn BEFORE its
    // ~2-7s self-check fires. Needs no JNI/ART -- run it first (the KPM gate is already set via
    // kpm_hook_set_process_name in StartIfEnabled) to win the race.
    if (cfg.gcash_fix) {
        RunGcashNeutralize(vm, cfg.gcash_off);
        return;
    }

    // Attach to the ART runtime so we hold a valid art::Thread* for the driver.
    JNIEnv *env = nullptr;
    if (vm->AttachCurrentThread(&env, nullptr) != JNI_OK || !env) {
        LOGW("[unpack] worker: AttachCurrentThread failed");
        return;
    }

    // openat traceless probe (frida-parallel). If set, this is the worker's WHOLE job -- install
    // the traceless openat hook, log distinct paths, exit. Kept isolated from the dump path so the
    // survival/capture experiment is clean (no choke hook, no maps burst, no dexfind).
    if (cfg.openat_probe) {
        RunOpenatProbe(cfg.openat_ms, cfg.openat_dobby);
        vm->DetachCurrentThread();
        return;
    }

    void *art_thread = env->functions->reserved3;  // TODO(P1): the real art::Thread* (JNIEnv cookie / __get_tls)

    static CodeItemSink sink;
    sink.Init(out_dir.c_str());

    // increment-2c: interpreter-point capture (FART-style) — the ONLY way to recover a side-cache /
    // DefineClass-restore extraction shell (dpt-shell), whose real CodeItems GetCodeItem (2b) can't
    // see. Hook art::interpreter::Execute FIRST (this fires near app startup, before the app runs
    // its own methods) and capture for a window while the app initializes + the operator drives it.
    // The structure dexes themselves are dumped by the dexfind pass below (same region keys), so the
    // offline splicer can graft the captured CodeItems back in.
    if (cfg.interp) {
        int interp_ms = PropInt("persist.kpmhook.unpack.interp_ms", 30000);
        size_t ncap = CaptureInterpreted(&sink, interp_ms);
        LOGI("[unpack] interp: {} method CodeItem(s) captured over {}ms", ncap, interp_ms);
    }

    // The CodeItem-restore choke is only useful for the active/per-method tiers; the P0-simple
    // whole-dex path is a /proc/self/maps scan (immune to libart inlining GetCodeItem).
    bool hooked = false;
    if (cfg.tier != Tier::kPassive) {
        hooked = InstallChokeHook(cfg.choke, cfg.stealth, &sink);
        if (!hooked) LOGW("[unpack] choke hook install failed; continuing with maps scan only");
        size_t driven = EnumerateAndDrive(cfg.tier, art_thread);
        LOGI("[unpack] worker: driven={} methods", driven);
    }

    // Packers decrypt lazily / in stages (Yidun, legu, ...) and some anti-root packers exit the
    // app within a few seconds. So scan IMMEDIATELY and repeatedly with a sub-second interval to
    // catch the decrypted dex(es) inside that brief window, whenever they materialize
    // (range-deduped -> already-dumped dexes are skipped cheaply). Props tune the burst.
    //
    // SKIP the burst when dexfind is on: (1) dexfind is strictly superior — it reaches every loaded
    // dex via ART (incl. header-mangled ones the scan can't validate), so the burst adds nothing;
    // (2) the burst's heavy page-by-page read + process-wide SIGSEGV fault-guard CONFLICTS with
    // signal/lazy-restore shells (dpt-shell crashed the app at pc=0 during the burst, but runs fine
    // under dexfind-only). dexfind's region reads touch only the few loaded-dex regions.
    if (!cfg.dexfind && !cfg.interp && !cfg.active_load) {
        int rounds = PropInt("persist.kpmhook.unpack.rounds", 40);
        int interval_ms = PropInt("persist.kpmhook.unpack.interval_ms", 400);
        if (rounds < 1) rounds = 1;
        if (interval_ms < 1) interval_ms = 1;
        LOGI("[unpack] scanning {} round(s) every {}ms (immediate start)", rounds, interval_ms);
        for (int r = 0; r < rounds; r++) {
            sink.ScanProcessForDexes();                   // scan FIRST -> catch fast-exit packers
            if (r + 1 < rounds) usleep((useconds_t)interval_ms * 1000);
        }
    } else {
        LOGI("[unpack] dexfind/interp on -> skipping the whole-dex burst scan (superseded)");
    }

    // Direction-1 increment-1: per-class dex discovery. The whole-dex scan above MISSES dexes
    // whose in-memory header the packer mangles (NetEase Yidun extracts/loads its real classes.dex
    // in-memory with a corrupted header). This asks ART directly — VisitClasses -> GetClassDef
    // gives a pointer into each live dex -> dump the containing region header-agnostically. Run
    // AFTER the burst so the app has loaded its real classes; enumeration runs on a runnable app
    // thread (captured via a transient ClassLinker::FindClass hook).
    // Also run for interp mode: the per-class region dump gives the offline splicer its target dexes
    // (whose nop'd CodeItems the interp captures replace). interp-only skips the GetCodeItem trigger.
    if (cfg.dexfind || cfg.interp || cfg.active_load) {
        bool trig = cfg.dexfind && cfg.trigger;
        if (trig) {
            // Calibrate the ArtMethod ABI (size + mirror::Class.methods_ offset) so the finder can
            // enumerate per-class ArtMethods and force-restore their CodeItems (increment-2).
            if (art::CalibrateForMethodEnum(env)) {
                LOGI("[unpack] dexfind: ArtMethod ABI calibrated -> per-method trigger ON");
            } else {
                LOGW("[unpack] dexfind: ArtMethod ABI calibration failed -> dump-only");
                trig = false;
            }
        }
        int pre_ms = PropInt("persist.kpmhook.unpack.predelay_ms", 6000);
        size_t recovered = FindAndDumpClassDexes(&sink, env, 10000, trig, cfg.active_load,
                                                 cfg.traceless, pre_ms);
        LOGI("[unpack] dexfind: {} region(s) recovered (trigger={} activeload={})", recovered, trig,
             cfg.active_load);
    }

    sink.Flush();

    if (hooked) RemoveChokeHook();  // P0: one-shot
    vm->DetachCurrentThread();
    LOGI("[unpack] worker done: dex={} captures={}", sink.dex_count(), sink.capture_count());
}

Config ReadConfigFromProps() {
    Config c;
    c.enabled = PropIs("persist.kpmhook.unpack", '1');
    c.tier = ParseTier();
    c.stealth = PropIs("persist.kpmhook.unpack.stealth", '1');
    c.choke = ParseChoke();
    c.dexfind = PropIs("persist.kpmhook.unpack.dexfind", '1');
    c.trigger = PropIs("persist.kpmhook.unpack.trigger", '1');
    c.interp = PropIs("persist.kpmhook.unpack.interp", '1');
    c.active_load = PropIs("persist.kpmhook.unpack.activeload", '1');
    c.traceless = PropIs("persist.kpmhook.unpack.traceless", '1');
    c.extout = PropIs("persist.kpmhook.unpack.extout", '1');
    c.openat_probe = PropIs("persist.kpmhook.unpack.openat", '1');
    c.openat_ms = PropInt("persist.kpmhook.unpack.openat_ms", 20000);
    c.openat_dobby = PropIs("persist.kpmhook.unpack.openat_dobby", '1');
    c.gcash_fix = PropIs("persist.kpmhook.unpack.gcashfix", '1');
    c.gcash_off = (unsigned long) PropInt("persist.kpmhook.unpack.gcashoff", 0x1d0bb0);
    return c;
}

}  // namespace

bool StartIfEnabled(JavaVM *vm, JNIEnv *env, const char *app_data_dir, const char *process_name) {
    (void)env;
    Config cfg = ReadConfigFromProps();
    if (!cfg.enabled) return false;  // default path: no-op
    if (!ProcessMatchesTarget(process_name)) return false;  // stealth=0 per-app gate
    if (!vm) {
        LOGW("[unpack] StartIfEnabled: no JavaVM");
        return false;
    }
    // Tell the KPM gate who we are BEFORE the worker calls kpm_inline_hooker (see the extern
    // decl above). Without this the openat/traceless path fails the gate and latches.
    kpm_hook_set_process_name(process_name);
    // Rev1-(1): host traceless clones VMA-less (enumeration-blind). Must precede the first
    // kpm_inline_hooker; affects regions created after. Auto-falls-back on a pre-0.6.2 KPM.
    kpm_hook_set_ghost(1);
    // fs-hide: spoof this process's statfs f_type (overlayfs->erofs) + drop overlay/magisk mount
    // lines, so the app's own root-detection can't catch the "hidden overlayfs" inconsistency.
    // Default on; disable with `resetprop persist.kpmhook.fshide 0`. Harmless no-op on <0.6.6 KPM.
    if (PropInt("persist.kpmhook.fshide", 1)) kpm_hook_fshide_enable();
    // Output dir. Default = the app's INTERNAL data dir (/data/user/0/<pkg>/unpack). On a hardened
    // app with strict SELinux MLS categories (e.g. GCash), a locked-down su can't read those files
    // (can't relabel/setenforce), so pulling the dump fails. extout=1 writes to the app's EXTERNAL
    // dir instead (the app can write its own /storage/emulated/0/Android/data/<pkg>/files; root
    // reads the same bytes at /data/media/0/... which is media_rw_data_file with NO app categories,
    // so `adb pull` works). process_name == target here (exact-match gate), so it's the clean pkg.
    std::string out_dir;
    if (cfg.extout && process_name && process_name[0]) {
        out_dir = std::string("/storage/emulated/0/Android/data/") + process_name + "/files/vunpack";
    } else if (app_data_dir && app_data_dir[0]) {
        out_dir = std::string(app_data_dir) + "/unpack";
    } else {
        out_dir = "/data/local/tmp/unpack";
    }
    LOGI("[unpack] enabled: tier={} stealth={} choke={} dir={} -> spawning worker",
         static_cast<int>(cfg.tier), cfg.stealth, static_cast<int>(cfg.choke), out_dir.c_str());
    std::thread(WorkerMain, vm, cfg, std::move(out_dir)).detach();
    return true;
}

}  // namespace vector::native::unpack

#endif  // VECTOR_UNPACK_ENABLED
