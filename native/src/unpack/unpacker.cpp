// unpacker.cpp — see unpacker.h. INERT until VECTOR_UNPACK_ENABLED.
//
// Orchestration mirrors module.cpp RunTracelessConvert (module.cpp:307): a detached
// worker thread attaches to the ART runtime post-init, does the ART-touching work, then
// exits. Default OFF (gated by persist.kpmhook.unpack); fail-safe to no-op everywhere.

#ifdef VECTOR_UNPACK_ENABLED

#include "unpack/unpacker.h"

#include <dlfcn.h>
#include <fcntl.h>
#include <sys/system_properties.h>
#include <unistd.h>

#include <atomic>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <set>
#include <string>
#include <thread>

#include <common/logging.h>
#include <dobby.h>  // control-arm backend for the openat probe (persist.kpmhook.unpack.openat_dobby=1)

// Traceless KPM backend (defined in native/src/kpm, declared in core/native_api.h). Forward-
// declared here so the openat probe can call kpm_inline_hooker DIRECTLY -- traceless-ONLY, with
// NO Dobby fallback (a Dobby/inline patch gets the process SIGKILL'd by anti-tamper guards).
extern "C" void *kpm_inline_hooker(void *target, void *hooker);
extern "C" int kpm_inline_unhooker(void *func);
// Identify this process to the KPM's proc_is_target() gate (which compares against
// persist.kpmhook.target). Vector's normal path sets this in module.cpp, but only AFTER
// StartIfEnabled and only for in-scope apps -- so the traceless worker must set it itself
// or the gate latches g_init_failed on the stale "zygote64" cmdline.
extern "C" void kpm_hook_set_process_name(const char *name);

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
    bool openat_probe = false;                             // .openat = 1 (traceless openat probe; frida-parallel)
    int openat_ms = 20000;                                 // .openat_ms (probe window)
    bool openat_dobby = false;                             // .openat_dobby = 1 (control arm: DobbyHook not KPM)
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

void WorkerMain(JavaVM *vm, Config cfg, std::string out_dir) {
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
        size_t recovered = FindAndDumpClassDexes(&sink, env, 10000, trig, cfg.active_load);
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
    c.openat_probe = PropIs("persist.kpmhook.unpack.openat", '1');
    c.openat_ms = PropInt("persist.kpmhook.unpack.openat_ms", 20000);
    c.openat_dobby = PropIs("persist.kpmhook.unpack.openat_dobby", '1');
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
    std::string out_dir = (app_data_dir && app_data_dir[0]) ? std::string(app_data_dir) + "/unpack"
                                                            : std::string("/data/local/tmp/unpack");
    LOGI("[unpack] enabled: tier={} stealth={} choke={} dir={} -> spawning worker",
         static_cast<int>(cfg.tier), cfg.stealth, static_cast<int>(cfg.choke), out_dir.c_str());
    std::thread(WorkerMain, vm, cfg, std::move(out_dir)).detach();
    return true;
}

}  // namespace vector::native::unpack

#endif  // VECTOR_UNPACK_ENABLED
