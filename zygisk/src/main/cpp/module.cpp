#include <common/config.h>
#include <common/logging.h>
#include <core/context.h>
#include <core/native_api.h>
#include <elf/elf_image.h>
#include <elf/symbol_cache.h>
#include <jni/jni_bridge.h>
#include <sys/system_properties.h>
#include <unistd.h>

#include <cstdio>
#include <cstring>
#include <chrono>
#include <thread>
#include <fcntl.h>

#include <zygisk.hpp>

#include "ipc_bridge.h"

namespace vector::native::module {

// --- Process UID Constants ---
// Values used to identify special Android processes to avoid injection.
// https://android.googlesource.com/platform/system/core/+/master/libcutils/include/private/android_filesystem_config.h

// The range of UIDs used for isolated processes (e.g., web renderers, WebView).
constexpr int FIRST_ISOLATED_UID = 99000;
constexpr int LAST_ISOLATED_UID = 99999;

// The range of UIDs used for application zygotes, which are also not targets.
constexpr int FIRST_APP_ZYGOTE_ISOLATED_UID = 90000;
constexpr int LAST_APP_ZYGOTE_ISOLATED_UID = 98999;

// UID for the process responsible for creating shared RELRO files.
constexpr int SHARED_RELRO_UID = 1037;

// Android uses this to separate users. UID = AppID + UserID * 10000.
constexpr int PER_USER_RANGE = 100000;

// Defined via CMake generated marcos
constexpr uid_t kHostPackageUid = INJECTED_PACKAGE_UID;
const char *const kHostPackageName = VEC_STR(INJECTED_PACKAGE_NAME);
const char *const kManagerPackageName = VEC_STR(MANAGER_PACKAGE_NAME);
constexpr uid_t GID_INET = 3003;  // Android's Internet group ID.

// Hooked-method registry (filled by lsplant's on_method_hooked notifier) -- the detection probe
// reads it to verify surface #3 (each hooked method's ArtMethod is pristine).
static constexpr int kMaxHookedMethods = 512;
static void *g_hooked_methods[kMaxHookedMethods];
static volatile int g_hooked_count = 0;
static void RecordHookedMethod(void *method) {
    int i = g_hooked_count;
    if (i < kMaxHookedMethods) {
        g_hooked_methods[i] = method;
        g_hooked_count = i + 1;
    }
}

// May we KPM-trap `qc` (a Java method's quick-compiled entry) for L2? Two conditions:
//  (1) qc is in a file-backed AOT region (boot.oat / app .odex). Excludes JIT (shared anon
//      cache) and the libart interpreter bridge.
//  (2) qc is a genuine per-method compiled body, NOT a SHARED boot.oat stub. Many framework
//      methods aren't individually AOT-compiled and share an nterp/bridge stub that lives in
//      boot.oat (so (1) alone passes!) -- trapping a shared stub reroutes EVERY method using
//      it. A real dex2oat method has an OatQuickMethodHeader right before its code whose
//      code_size is small/sane; a shared stub's qc-4 is an instruction word (huge when masked),
//      so the code_size sanity check rejects it. Non-traceable methods fall back to in-place.
static bool QcIsTraceable(const void *qc) {
    auto a = reinterpret_cast<uintptr_t>(qc);
    if (a < 0x2000) return false;
    FILE *f = fopen("/proc/self/maps", "re");
    if (!f) return false;
    char line[512];
    bool aot = false;
    while (fgets(line, sizeof line, f)) {
        uintptr_t lo = 0, hi = 0;
        char perms[8] = {0}, path[256] = {0};
        if (sscanf(line, "%lx-%lx %7s %*x %*x:%*x %*u %255[^\n]", &lo, &hi, perms, path) >= 3 &&
            a >= lo && a < hi) {
            aot = perms[2] == 'x' &&
                  (strstr(path, ".oat") || strstr(path, ".odex") || strstr(path, ".art") ||
                   strstr(path, "/oat/") || strstr(path, "jit-code-cache") ||
                   strstr(path, "jit-cache"));  // JIT body (post force-compile) is also a unique trap target
            break;
        }
    }
    fclose(f);
    if (!aot) return false;
    // OatQuickMethodHeader.code_size_ sits at qc-4 (top bit = is_code_info flag). A real method
    // body is a few bytes to a few hundred KiB; a shared stub's qc-4 is an arm64 instruction
    // word (e.g. RET=0xD65F03C0 -> ~0x165F03C0 masked), far above any real method.
    uint32_t code_size = *reinterpret_cast<const uint32_t *>(a - 4) & 0x3FFFFFFFu;
    return code_size >= 8 && code_size <= 0x80000;
}

// M-C: force the JIT to give an nterp/interpreted method its OWN compiled body, so the traceless
// path has a unique region to trap (instead of falling back to the detectable in-place hook).
// Called from DoHook BEFORE the suspend (the JIT compiles on a background thread). entry_point is
// at +24 on this device. Resolves art::Runtime::instance_, Runtime::GetJit, and
// Jit::EnqueueOptimizedCompilation; enqueues an optimized compile and polls until the method gains
// a unique compiled body or a ~1s timeout (then it stays nterp and DoHook takes the in-place path).
static void ForceCompileMethod(void *method, void *thread) {
    if (!method) return;
    void *qc = *reinterpret_cast<void **>(reinterpret_cast<char *>(method) + 24);
    if (QcIsTraceable(qc)) return;  // already has a unique compiled body (AOT/JIT)

    using Sym = ElfSymbolCache;
    static auto runtime_inst =
        reinterpret_cast<void **>(Sym::GetArt()->getSymbAddress("_ZN3art7Runtime9instance_E"));
    static auto get_jit = reinterpret_cast<void *(*)(void *)>(
        Sym::GetArt()->getSymbAddress("_ZNK3art7Runtime6GetJitEv"));
    static auto enqueue = reinterpret_cast<void (*)(void *, void *, void *)>(
        Sym::GetArt()->getSymbAddress(
            "_ZN3art3jit3Jit27EnqueueOptimizedCompilationEPNS_9ArtMethodEPNS_6ThreadE"));
    if (!runtime_inst || !get_jit || !enqueue || !*runtime_inst) {
        LOGW("[forcecompile] symbols missing (rt={} getjit={} enq={})", (void *)runtime_inst,
             (void *)get_jit, (void *)enqueue);
        return;
    }
    void *jit = get_jit(*runtime_inst);
    if (!jit) {
        LOGW("[forcecompile] no JIT instance (jit disabled?)");
        return;
    }
    enqueue(jit, method, thread);
    for (int i = 0; i < 200; i++) {  // ~1s
        usleep(5000);
        void *e = *reinterpret_cast<void **>(reinterpret_cast<char *>(method) + 24);
        if (e != qc && QcIsTraceable(e)) {
            LOGI("[forcecompile] method {} compiled: qc {} -> {}", method, qc, e);
            return;
        }
    }
    LOGW("[forcecompile] method {} compile timeout (stays nterp -> in-place)", method);
}

// ---- Detection probe (the GOAL judge, gated by persist.kpmhook.probe=1) -----------------
// Runs INSIDE the gated target app on a delayed thread (to catch hooks installed during
// startup) and scans the hook-detection surfaces an in-process anti-tamper would check,
// reporting a count per surface. ZERO across all surfaces (with hooks active) == goal met.
// Surfaces implemented here: #2 (anomalous executable memory) + #5 (ptrace/TracerPid).
// #1 (libart/oat CRC), #3 (ArtMethod entry/flags), #4 (inline-hook bytes) need the hooked
// function/method list and are added as the traceless coverage grows.
static void DetectionProbeScan() {
    // ---- surface #2: anomalous executable regions in /proc/self/maps ----
    // A hook clone is an UNLABELED anon r-xp region; an in-place trampoline (Dobby/LSPlant)
    // is an rwxp region. Legit exec memory is file-backed, [vdso], or a LABELED [anon:...]
    // (e.g. dalvik-jit-code-cache). Count the anomalies an anti-tamper scan would flag.
    int anon_rx = 0, rwx = 0;
    FILE *f = fopen("/proc/self/maps", "re");
    if (f) {
        char line[512];
        while (fgets(line, sizeof line, f)) {
            uintptr_t lo = 0, hi = 0;
            char perms[8] = {0}, path[256] = {0};
            int n = sscanf(line, "%lx-%lx %7s %*x %*x:%*x %*u %255[^\n]", &lo, &hi, perms, path);
            if (n < 3 || perms[2] != 'x') continue;        // executable only
            bool rwxp = perms[0] == 'r' && perms[1] == 'w';
            bool labeled = n >= 4 && path[0];
            bool benign_label = labeled && (strstr(path, "[vdso]") || strstr(path, "jit-cache") ||
                                            strstr(path, "dalvik-jit-code-cache"));
            if (rwxp && !benign_label) {
                rwx++;
                LOGW("[probe] S2 rwxp exec region: {}", line);
            } else if (!labeled) {  // unlabeled anon r-xp == hook-clone signature
                anon_rx++;
                LOGW("[probe] S2 unlabeled anon r-xp region: {}", line);
            }
        }
        fclose(f);
    }
    // ---- surface #5: ptrace / TracerPid ----
    int tracer_pid = -1;
    f = fopen("/proc/self/status", "re");
    if (f) {
        char line[256];
        while (fgets(line, sizeof line, f))
            if (sscanf(line, "TracerPid:\t%d", &tracer_pid) == 1) break;
        fclose(f);
    }
    // ---- surface #1/#4: code integrity — compare libart.so's in-memory .text (r-xp) vs the
    // on-disk file. ANY byte diff is an inline patch (Dobby/hook); the KPM never writes .text
    // (it UXN-traps + clones), so a traceless install leaves 0 diffs. (-1 = couldn't check.) ----
    long code_diffs = -1;
    f = fopen("/proc/self/maps", "re");
    if (f) {
        char line[512];
        while (fgets(line, sizeof line, f)) {
            uintptr_t lo = 0, hi = 0;
            unsigned long foff = 0;
            char perms[8] = {0}, path[256] = {0};
            if (sscanf(line, "%lx-%lx %7s %lx %*x:%*x %*u %255[^\n]", &lo, &hi, perms, &foff,
                       path) >= 5 &&
                perms[2] == 'x' && strstr(path, "libart.so")) {
                int fd = open(path, O_RDONLY | O_CLOEXEC);
                if (fd < 0) break;
                code_diffs = 0;
                unsigned char buf[4096];
                for (uintptr_t pg = lo; pg < hi; pg += 4096) {
                    off_t off = (off_t)foff + (off_t)(pg - lo);
                    if (pread(fd, buf, 4096, off) == 4096 &&
                        memcmp(buf, reinterpret_cast<void *>(pg), 4096) != 0)
                        code_diffs++;  // a patched page
                }
                close(fd);
                break;
            }
        }
        fclose(f);
    }
    // ---- surface #3: ArtMethod integrity. For each hooked method, the entry_point must point at
    // legit unique compiled code (oat/jit) and access_flags must not carry the hook's
    // kAccCompileDontBother. An in-place hook leaves entry==trampoline (not traceable) and the flag
    // set -> DETECTED; a traceless hook leaves entry==real oat/jit code, flag clear -> CLEAN. ----
    constexpr uint32_t kAccCompileDontBother = 0x02000000u;
    int hooked = g_hooked_count, s3_bad = 0;
    for (int i = 0; i < hooked && i < kMaxHookedMethods; i++) {
        void *m = g_hooked_methods[i];
        if (!m) continue;
        void *entry = *reinterpret_cast<void **>(reinterpret_cast<char *>(m) + 24);
        uint32_t flags = *reinterpret_cast<uint32_t *>(reinterpret_cast<char *>(m) + 4);
        bool entry_ok = QcIsTraceable(entry);            // points at legit unique oat/jit body
        bool flags_ok = !(flags & kAccCompileDontBother);  // not marked non-compilable by a hook
        if (!entry_ok || !flags_ok) {
            s3_bad++;
            if (s3_bad <= 6)
                LOGW("[probe] S3 mutated ArtMethod {}: entry={} ({}) flags={:#x} ({})", m, entry,
                     entry_ok ? "legit" : "ANOMALOUS", flags, flags_ok ? "ok" : "DontBother-set");
        }
    }

    LOGI("[probe] ===== DETECTION PROBE ===== S2 anon-rx={} rwxp={}  S5 TracerPid={}  S1/4 "
         "libart-patched-pages={}  S3 hooked={} mutated={}",
         anon_rx, rwx, tracer_pid, code_diffs, hooked, s3_bad);
    LOGI("[probe] VERDICT S2(maps/smaps)={} S5(ptrace)={} S1/4(code-CRC)={} S3(ArtMethod)={}",
         (anon_rx == 0 && rwx == 0) ? "CLEAN" : "DETECTED", tracer_pid == 0 ? "CLEAN" : "DETECTED",
         code_diffs == 0 ? "CLEAN" : (code_diffs < 0 ? "SKIP" : "DETECTED"),
         (hooked > 0 && s3_bad == 0) ? "CLEAN" : (hooked == 0 ? "no-hooks" : "DETECTED"));
}
static void RunDetectionProbe() {
    char v[PROP_VALUE_MAX] = {0};
    if (__system_property_get("persist.kpmhook.probe", v) <= 0 || v[0] != '1') return;
    std::thread([] {
        std::this_thread::sleep_for(std::chrono::seconds(6));  // let startup hooks install
        DetectionProbeScan();
    }).detach();
}

// Hide this process's anomalous rwxp anon regions (the LSPlant trampoline pool that every hook
// creates) from /proc/self/{maps,smaps} via the KPM. rwxp anon memory is the classic hook/
// trampoline signature — on a W^X system nothing legit is rwxp — so hiding all of them closes the
// trampoline leak in surface #2. mm-gated in the KPM; only acts in the gated process.
static void HideRwxpRegionsScan() {
    if (kpm_hook_init() != 0) return;  // gated process + bridge armed only
    FILE *f = fopen("/proc/self/maps", "re");
    if (!f) return;
    char line[512];
    int hid = 0;
    while (fgets(line, sizeof line, f)) {
        uintptr_t lo = 0, hi = 0;
        char perms[8] = {0}, path[256] = {0};
        int n = sscanf(line, "%lx-%lx %7s %*x %*x:%*x %*u %255[^\n]", &lo, &hi, perms, path);
        if (n < 3) continue;
        bool rwxp = perms[0] == 'r' && perms[1] == 'w' && perms[2] == 'x';
        bool anon = !(n >= 4 && path[0]);
        if (rwxp && anon)
            for (uintptr_t pg = lo; pg < hi; pg += 0x1000)
                if (kpm_hide_region(reinterpret_cast<void *>(pg))) hid++;
    }
    fclose(f);
    LOGI("[hidetramp] hid {} rwxp anon trampoline pages from maps/smaps", hid);
}
static void RunTrampolineHide() {
    char v[PROP_VALUE_MAX] = {0};
    if (!kUseKpmBackend || __system_property_get("persist.kpmhook.l2", v) <= 0 || v[0] != '1') return;
    std::thread([] {
        std::this_thread::sleep_for(std::chrono::seconds(5));  // after startup hooks install
        HideRwxpRegionsScan();
    }).detach();
}

// ---- L2a DBI-on-oat self-test (gated by persist.kpmhook.l2test=1) ----------------------
// The manager process hooks no Java methods, so to validate the traceless L2 mechanism on a
// real AOT framework method we deliberately trap java.lang.Math.max's compiled oat code via
// the KPM and check: (1) the DBI recompiled the real oat region (kpm_inline_hooker != null),
// (2) trap+redirect fires (max -> stub sentinel), (3) the in-clone copy of max executes
// faithfully (invoked via min's entry -> returns max's result), (4) max's ArtMethod stays
// byte-pristine. Then unhook so the manager's Math.max is left intact. ArtMethod entry_point
// is at +24 on this device (logged by LSPlant at init).
extern "C" __attribute__((used)) int l2_selftest_stub(int, int) { return 0x7777; }
static inline void *AmEntry(jmethodID m) {
    return *reinterpret_cast<void **>(reinterpret_cast<char *>(m) + 24);
}
static inline void AmSetEntry(jmethodID m, void *e) {
    *reinterpret_cast<void **>(reinterpret_cast<char *>(m) + 24) = e;
}
static void RunL2SelfTest(JNIEnv *env) {
    char v[PROP_VALUE_MAX] = {0};
    if (__system_property_get("persist.kpmhook.l2test", v) <= 0 || v[0] != '1') return;
    if (!kUseKpmBackend || kpm_hook_init() != 0) {
        LOGW("[l2test] KPM not gated/armed in this process; skip");
        return;
    }
    jclass mathC = env->FindClass("java/lang/Math");
    if (!mathC) { env->ExceptionClear(); LOGW("[l2test] no java.lang.Math"); return; }
    jmethodID maxId = env->GetStaticMethodID(mathC, "max", "(II)I");
    jmethodID minId = env->GetStaticMethodID(mathC, "min", "(II)I");
    if (!maxId || !minId) { env->ExceptionClear(); LOGW("[l2test] no max/min id"); return; }

    void *maxQc = AmEntry(maxId), *minQc = AmEntry(minId);
    jint base_max = env->CallStaticIntMethod(mathC, maxId, 5, 9);
    jint base_min = env->CallStaticIntMethod(mathC, minId, 5, 9);
    LOGI("[l2test] maxQc={} minQc={} baseline max(5,9)={} min(5,9)={}", maxQc, minQc, base_max,
         base_min);

    void *backup = kpm_inline_hooker(maxQc, reinterpret_cast<void *>(&l2_selftest_stub));
    if (!backup) {
        LOGE("[l2test] FAIL: kpm_inline_hooker NULL (DBI bailed or no clean region within 64p)");
        return;
    }
    LOGI("[l2test] PASS DBI-on-oat recompile: Math.max region cloned, in-clone backup={}", backup);

    jint hooked_max = env->CallStaticIntMethod(mathC, maxId, 5, 9);  // expect stub 0x7777
    void *maxQcAfter = AmEntry(maxId);                                // expect == maxQc (pristine)

    // clone executes faithfully: run the in-clone copy of max via min's entry -> expect max(5,9)
    void *minOrig = AmEntry(minId);
    AmSetEntry(minId, backup);
    jint clone_max = env->CallStaticIntMethod(mathC, minId, 5, 9);  // expect 9 (=max via clone)
    AmSetEntry(minId, minOrig);

    kpm_inline_unhooker(maxQc);                                      // leave manager's Math.max intact
    jint post_max = env->CallStaticIntMethod(mathC, maxId, 5, 9);   // expect 9 again

    LOGI("[l2test] ===== L2a DBI-on-oat VALIDATION =====");
    LOGI("[l2test] trap+redirect:   max(5,9)={} expect 0x7777({}) -> {}", hooked_max, 0x7777,
         hooked_max == 0x7777 ? "PASS" : "FAIL");
    LOGI("[l2test] clone executes:  clone(5,9)={} expect 9        -> {}", clone_max,
         clone_max == 9 ? "PASS" : "FAIL");
    LOGI("[l2test] ArtMethod pristine: {} -> {}                   -> {}", maxQc, maxQcAfter,
         maxQc == maxQcAfter ? "PASS" : "FAIL");
    LOGI("[l2test] post-unhook:     max(5,9)={} expect 9          -> {}", post_max,
         post_max == 9 ? "PASS" : "FAIL");
}

enum RuntimeFlags : uint32_t {
    // Flags defined by NeoZygisk
    LATE_INJECT = 1 << 30,
};

// A simply ConfigBridge implemnetation holding obfuscation maps in memory
using obfuscation_map_t = std::map<std::string, std::string>;
class ConfigImpl : public ConfigBridge {
public:
    inline static void Init() { instance_ = std::make_unique<ConfigImpl>(); }

    virtual obfuscation_map_t &obfuscation_map() override { return obfuscation_map_; }

    virtual void obfuscation_map(obfuscation_map_t m) override { obfuscation_map_ = std::move(m); }

private:
    ConfigImpl() = default;

    friend std::unique_ptr<ConfigImpl> std::make_unique<ConfigImpl>();
    obfuscation_map_t obfuscation_map_;
};

/**
 * @class VectorModule
 * @brief The core implementation of the Zygisk module for the Vector framework.
 *
 * This class is the main entry point for Zygisk. It inherits from:
 * - zygisk::ModuleBase:      To receive lifecycle callbacks from the Zygisk loader.
 * - vector::native::Context: To gain the core injection capabilities (DEX loading, ART hooking)
 *                            from the 'native' library.
 *
 * It orchestrates the injection process by deciding which processes to target,
 * using the IPCBridge to fetch the framework from the manager service, and then
 * using the Context base to perform the actual injection.
 */
class VectorModule : public zygisk::ModuleBase, public vector::native::Context {
public:
    void onLoad(zygisk::Api *api, JNIEnv *env) override;
    void preAppSpecialize(zygisk::AppSpecializeArgs *args) override;
    void postAppSpecialize(const zygisk::AppSpecializeArgs *args) override;
    void preServerSpecialize(zygisk::ServerSpecializeArgs *args) override;
    void postServerSpecialize(const zygisk::ServerSpecializeArgs *args) override;

protected:
    /**
     * @brief Provides the concrete implementation for loading the framework DEX.
     *
     * This method is a pure virtual in the native::core::Context base class and
     * must be implemented here.
     * It uses an InMemoryDexClassLoader to load our framework into the target process.
     */
    void LoadDex(JNIEnv *env, PreloadedDex &&dex) override;

    /**
     * @brief Provides the concrete implementation for finding the Java entry
     * class.
     *
     * This method is also a pure virtual in the base class.
     * It uses the obfuscation map to determine the real entry class name and
     * finds it in the ClassLoader we created in LoadDex.
     */
    void SetupEntryClass(JNIEnv *env) override;

private:
    /**
     * @brief Encapsulates the logic for telling Zygisk whether to unload our library.
     *
     * If we don't inject into a process, we allow Zygisk to dlclose our .so.
     * Otherwise, we MUST prevent this.
     * @param unload True to allow unloading, false to prevent it.
     */
    void SetAllowUnload(bool unload);

    zygisk::Api *api_ = nullptr;
    JNIEnv *env_ = nullptr;

    // --- ART Hooker Configuration ---
    const lsplant::InitInfo init_info_{
        .inline_hooker =
            [](auto target, auto replace) {
                void *backup = nullptr;
                return HookInline(target, replace, &backup) == 0 ? backup : nullptr;
            },
        .inline_unhooker = [](auto target) { return UnhookInline(target) == 0; },
        .art_symbol_resolver =
            [](auto symbol) { return ElfSymbolCache::GetArt()->getSymbAddress(symbol); },
        .art_symbol_prefix_resolver =
            [](auto symbol) { return ElfSymbolCache::GetArt()->getSymbPrefixFirstAddress(symbol); },
        // L2a traceless Java-method hooking (KPM-only, NO Dobby fallback). Ships OFF: engages
        // only when persist.kpmhook.l2=1 AND in a KPM-gated process (kpm_inline_hooker self-gates
        // via proc_is_target and returns null elsewhere). On null, DoHook falls back to its normal
        // in-place entry swap -- it NEVER routes a Java-method hook through Dobby, which would
        // inline-patch the shared CoW oat page (CRC-detectable AND corrupting).
        .traceless_inline_hooker =
            [](auto target, auto replace) -> void * {
                char v[PROP_VALUE_MAX] = {0};
                if (!kUseKpmBackend ||
                    __system_property_get("persist.kpmhook.l2", v) <= 0 || v[0] != '1')
                    return nullptr;
                if (!QcIsTraceable(target)) {
                    LOGI("[l2] qc={} not a traceable AOT body (interp/jit/shared stub) -> in-place",
                         target);
                    return nullptr;
                }
                void *bk = kpm_inline_hooker(target, replace);
                LOGI("[l2] traceless Java hook: qc={} -> trampoline {}, clone-backup={} ({})", target,
                     replace, bk, bk ? "TRACELESS" : "in-place fallback");
                return bk;
            },
        // M-C (EXPERIMENTAL, default OFF via persist.kpmhook.fc): force-compile a non-AOT target
        // so the traceless path has a unique body to trap. KNOWN ISSUE: a synchronous compile-wait
        // in DoHook hangs app init (postAppSpecialize runs before the JIT thread is up, so the
        // compile never completes and the wait blocks until AMS kills the app). Needs a deferred
        // post-init upgrade design -- gated off until then so it never breaks a real app.
        .force_compile =
            [](void *method, void *thread) {
                char v[PROP_VALUE_MAX] = {0};
                if (!kUseKpmBackend ||
                    __system_property_get("persist.kpmhook.fc", v) <= 0 || v[0] != '1')
                    return;
                if (kpm_hook_init() != 0) return;  // gated process + bridge armed only
                ForceCompileMethod(method, thread);
            },
        // Detection-probe surface #3: record every hooked method so the probe can verify each
        // one's ArtMethod is pristine (entry in legit oat/jit, no kAccCompileDontBother).
        .on_method_hooked = [](void *method) { RecordHookedMethod(method); },
        .generated_class_name = "Vector_",
        .generated_source_name = "Dobby",
    };

    // State managed within the class instance for each forked process.
    bool should_inject_ = false;
    bool is_manager_app_ = false;
};

// =========================================================================================
// Implementation of VectorModule
// =========================================================================================

void VectorModule::LoadDex(JNIEnv *env, PreloadedDex &&dex) {
    LOGV("Loading framework DEX into memory (size: {}).", dex.size());

    // Get the system ClassLoader. This will be the parent of our new loader.
    auto classloader_class = lsplant::JNI_FindClass(env, "java/lang/ClassLoader");
    if (!classloader_class) {
        LOGE("Failed to find java.lang.ClassLoader");
        return;
    }
    auto getsyscl_mid = lsplant::JNI_GetStaticMethodID(
        env, classloader_class.get(), "getSystemClassLoader", "()Ljava/lang/ClassLoader;");
    auto system_classloader =
        lsplant::JNI_CallStaticObjectMethod(env, classloader_class.get(), getsyscl_mid);
    if (!system_classloader) {
        LOGE("Failed to get SystemClassLoader");
        return;
    }

    // Create a Java ByteBuffer wrapping our in-memory DEX data.
    auto byte_buffer_class = lsplant::JNI_FindClass(env, "java/nio/ByteBuffer");
    if (!byte_buffer_class) {
        LOGE("Failed to find java.nio.ByteBuffer");
        return;
    }
    auto dex_buffer =
        lsplant::ScopedLocalRef(env, env->NewDirectByteBuffer(dex.data(), dex.size()));
    if (!dex_buffer) {
        LOGE("Failed to create DirectByteBuffer for DEX.");
        return;
    }

    // Create an InMemoryDexClassLoader instance.
    auto in_memory_cl_class = lsplant::JNI_FindClass(env, "dalvik/system/InMemoryDexClassLoader");
    if (!in_memory_cl_class) {
        LOGE("Failed to find InMemoryDexClassLoader.");
        return;
    }
    auto init_mid = lsplant::JNI_GetMethodID(env, in_memory_cl_class.get(), "<init>",
                                             "(Ljava/nio/ByteBuffer;Ljava/lang/ClassLoader;)V");
    if (!init_mid) {
        LOGE("Failed to find InMemoryDexClassLoader constructor.");
        return;
    }

    auto new_cl =
        lsplant::ScopedLocalRef(env, env->NewObject(in_memory_cl_class.get(), init_mid,
                                                    dex_buffer.get(), system_classloader.get()));
    if (env->ExceptionCheck() || !new_cl) {
        LOGE("Failed to create InMemoryDexClassLoader instance.");
        env->ExceptionClear();
        return;
    }

    // Store a global reference to our new ClassLoader.
    inject_class_loader_ = env->NewGlobalRef(new_cl.get());
    LOGV("Framework ClassLoader created successfully.");
}

void VectorModule::SetupEntryClass(JNIEnv *env) {
    if (!inject_class_loader_) {
        LOGE("Cannot setup entry class: ClassLoader is null.");
        return;
    }

    // Use the obfuscation map from the config to get the real class name.
    const auto &obfs_map = ConfigBridge::GetInstance()->obfuscation_map();
    std::string entry_class_name;
    entry_class_name = obfs_map.at("org.matrix.vector.core.") + "Main";

    // We must find the class through our custom ClassLoader.
    auto entry_class = this->FindClassFromLoader(env, inject_class_loader_, entry_class_name);
    if (!entry_class) {
        LOGE("Failed to find entry class '{}' in the loaded DEX.", entry_class_name.c_str());
        return;
    }

    // Store a global reference to the entry class.
    entry_class_ = lsplant::JNI_NewGlobalRef(env, entry_class);
    LOGV("Framework entry class '{}' located.", entry_class_name.c_str());
}

void VectorModule::onLoad(zygisk::Api *api, JNIEnv *env) {
    this->api_ = api;
    this->env_ = env;

    // Create two singlton instances for classes Context and ConfigBridge
    instance_.reset(this);
    ConfigImpl::Init();
    LOGD("Vector Zygisk module loaded");
}

void VectorModule::preAppSpecialize(zygisk::AppSpecializeArgs *args) {
    // Reset state for this new process fork.
    should_inject_ = false;
    is_manager_app_ = false;

    // --- Manager App Special Handling ---
    // We identify our manager app by a special UID and
    // grant it internet permissions by adding it to the INET group.
    if (args->uid == kHostPackageUid) {
        lsplant::JUTFString nice_name_str(env_, args->nice_name);
        if (nice_name_str.get() == std::string(kManagerPackageName)) {
            LOGI("Manager app detected. Granting internet permissions.");
            is_manager_app_ = true;

            // Add GID_INET to the GID list.
            int original_gids_count = env_->GetArrayLength(args->gids);
            jintArray new_gids = env_->NewIntArray(original_gids_count + 1);
            if (env_->ExceptionCheck()) {
                LOGE("Failed to create new GID array for manager.");
                env_->ExceptionClear();  // Clear exception to prevent a crash.
                return;
            }

            jint *gids_array = env_->GetIntArrayElements(args->gids, nullptr);
            env_->SetIntArrayRegion(new_gids, 0, original_gids_count, gids_array);
            env_->ReleaseIntArrayElements(args->gids, gids_array, JNI_ABORT);

            jint inet_gid = GID_INET;
            env_->SetIntArrayRegion(new_gids, original_gids_count, 1, &inet_gid);

            args->nice_name = env_->NewStringUTF(VEC_STR(INJECTED_PACKAGE_NAME));
            args->gids = new_gids;
        }
    }

    IPCBridge::GetInstance().Initialize(env_);

    // --- Injection Decision Logic ---
    // Determine if the current process is a valid target for injection.
    lsplant::JUTFString nice_name_str(env_, args->nice_name);

    // An app without a data directory cannot be a target.
    if (!args->app_data_dir) {
        LOGD("Skipping injection for '{}': no app_data_dir.", nice_name_str.get());
        return;
    }

    // Child Zygotes are specialized zygotes for apps like WebView and are not targets.
    if (args->is_child_zygote && *args->is_child_zygote) {
        LOGD("Skipping injection for '{}': is a child zygote.", nice_name_str.get());
        return;
    }

    // Skip isolated processes, which are heavily sandboxed.
    const uid_t app_id = args->uid % PER_USER_RANGE;
    if ((app_id >= FIRST_ISOLATED_UID && app_id <= LAST_ISOLATED_UID) ||
        (app_id >= FIRST_APP_ZYGOTE_ISOLATED_UID && app_id <= LAST_APP_ZYGOTE_ISOLATED_UID) ||
        app_id == SHARED_RELRO_UID) {
        LOGV("Skipping injection for '{}': is an isolated process (UID: {}).", nice_name_str.get(),
             app_id);
        return;
    }

    // If we passed all checks, mark this process for injection.
    should_inject_ = true;
    LOGV("Process '{}' (UID: {}) is marked for injection.", nice_name_str.get(), args->uid);
}

void VectorModule::postAppSpecialize(const zygisk::AppSpecializeArgs *args) {
    if (!should_inject_) {
        SetAllowUnload(true);  // Not a target, allow module to be unloaded.
        return;
    }

    if (is_manager_app_) {
        args->nice_name = env_->NewStringUTF(kManagerPackageName);
    }

    // --- Framework Injection ---
    lsplant::JUTFString nice_name_str(env_, args->nice_name);
    LOGD("Attempting injection into '{}'.", nice_name_str.get());

    auto &ipc_bridge = IPCBridge::GetInstance();
    auto binder = ipc_bridge.RequestAppBinder(env_, args->nice_name);
    if (!binder) {
        LOGD("No IPC binder obtained for '{}'. Skipping injection.", nice_name_str.get());
        SetAllowUnload(true);
        return;
    }

    // Fetch resources from the manager service.
    auto [dex_fd, dex_size] = ipc_bridge.FetchFrameworkDex(env_, binder.get());
    if (dex_fd < 0) {
        LOGE("Failed to fetch framework DEX for '{}'.", nice_name_str.get());
        SetAllowUnload(true);
        return;
    }

    auto obfs_map = ipc_bridge.FetchObfuscationMap(env_, binder.get());
    ConfigBridge::GetInstance()->obfuscation_map(std::move(obfs_map));

    {
        PreloadedDex dex(dex_fd, dex_size);
        this->LoadDex(env_, std::move(dex));
    }
    close(dex_fd);  // The FD is duplicated by mmap, we can close it now.

    // Tell the KPM gate which app this is BEFORE LSPlant installs its inline hooks --
    // at hook time /proc/self/cmdline is still "zygote64". Only the build's injection
    // target engages the traceless backend; every other process falls back to Dobby.
    kpm_hook_set_process_name(nice_name_str.get());

    // Initialize ART hooks via the native library.
    this->InitArtHooker(env_, init_info_);
    // L2a DBI-on-oat self-test (no-op unless persist.kpmhook.l2test=1 AND KPM-gated process).
    RunL2SelfTest(env_);
    // Hide the LSPlant trampoline pool (rwxp anon) from this process's maps/smaps (no-op unless
    // persist.kpmhook.l2=1 AND gated). Closes surface #2's trampoline leak.
    RunTrampolineHide();
    // Detection probe (no-op unless persist.kpmhook.probe=1): the GOAL judge, scans this
    // process's hook-detection surfaces on a delayed thread.
    RunDetectionProbe();
    // Initialize JNI hooks via the native library.
    this->InitHooks(env_);
    // Find the Java entrypoint.
    this->SetupEntryClass(env_);

    // Hand off control to the Java side of the framework.
    this->FindAndCall(
        env_, "forkCommon", "(ZZLjava/lang/String;Ljava/lang/String;Landroid/os/IBinder;)V",
        JNI_FALSE, JNI_FALSE, args->nice_name, args->app_data_dir, binder.get(), is_manager_app_);

    LOGV("Injected Vector framework into '{}'.", nice_name_str.get());
    SetAllowUnload(false);  // We are injected, PREVENT module unloading.
}

void VectorModule::preServerSpecialize(zygisk::ServerSpecializeArgs *args) {
    // The system server is always a target for injection.
    should_inject_ = true;
    LOGI("System server process detected. Marking for injection.");

    // Initialize our IPC bridge singleton.
    IPCBridge::GetInstance().Initialize(env_);
}

void VectorModule::postServerSpecialize(const zygisk::ServerSpecializeArgs *args) {
    if (!should_inject_) {
        SetAllowUnload(true);
        return;
    }

    LOGD("Attempting injection into system_server.");

    // --- Device-Specific Workaround ---
    // Some ZTE devices require argv[0] to be explicitly set to "system_server"
    // for certain services to function correctly after modification.
    if (__system_property_find("ro.vendor.product.ztename")) {
        LOGV("Applying ZTE-specific workaround: setting argv[0] to system_server.");
        auto process_class = lsplant::ScopedLocalRef(env_, env_->FindClass("android/os/Process"));
        if (process_class) {
            auto set_argv0_mid =
                env_->GetStaticMethodID(process_class.get(), "setArgV0", "(Ljava/lang/String;)V");
            auto name_str = lsplant::ScopedLocalRef(env_, env_->NewStringUTF("system_server"));
            if (set_argv0_mid && name_str) {
                env_->CallStaticVoidMethod(process_class.get(), set_argv0_mid, name_str.get());
            }
        }
        if (env_->ExceptionCheck()) {
            LOGW("Exception occurred during ZTE workaround.");
            env_->ExceptionClear();
        }
    }

    // --- Framework Injection for System Server ---
    auto &ipc_bridge = IPCBridge::GetInstance();
    std::string bridgeServiceName = "serial";
    bool is_late_inject = (args->runtime_flags & RuntimeFlags::LATE_INJECT) != 0;
    if (is_late_inject) bridgeServiceName = "serial_vector";
    auto system_binder = ipc_bridge.RequestSystemServerBinder(env_, bridgeServiceName);
    if (!system_binder) {
        LOGE("Failed to get system server IPC binder. Aborting injection.");
        SetAllowUnload(true);  // Allow unload on failure.
        return;
    }

    auto manager_binder =
        ipc_bridge.RequestManagerBinderFromSystemServer(env_, system_binder.get());

    // Use either the direct manager binder if available,
    // otherwise proxy through the system binder.
    jobject effective_binder = manager_binder ? manager_binder.get() : system_binder.get();

    auto [dex_fd, dex_size] = ipc_bridge.FetchFrameworkDex(env_, effective_binder);
    if (dex_fd < 0) {
        LOGE("Failed to fetch framework DEX for system_server.");
        SetAllowUnload(true);
        return;
    }

    auto obfs_map = ipc_bridge.FetchObfuscationMap(env_, effective_binder);
    ConfigBridge::GetInstance()->obfuscation_map(std::move(obfs_map));

    {
        PreloadedDex dex(dex_fd, dex_size);
        this->LoadDex(env_, std::move(dex));
    }
    close(dex_fd);

    ipc_bridge.HookBridge(env_);

    this->InitArtHooker(env_, init_info_);
    this->InitHooks(env_);
    this->SetupEntryClass(env_);

    auto system_name = lsplant::ScopedLocalRef(env_, env_->NewStringUTF("system"));
    this->FindAndCall(env_, "forkCommon",
                      "(ZZLjava/lang/String;Ljava/lang/String;Landroid/os/IBinder;)V", JNI_TRUE,
                      is_late_inject, system_name.get(), nullptr, manager_binder.get(),
                      is_manager_app_);

    LOGI("Injected Vector framework into system_server.");
    SetAllowUnload(false);  // We are injected, PREVENT module unloading.
}

void VectorModule::SetAllowUnload(bool unload) {
    if (api_ && unload) {
        LOGD("Allowing Zygisk to unload module library.");
        api_->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);

        // Release the pointer from the unique_ptr's control. This prevents the
        // static unique_ptr's destructor from calling delete on our object, which
        // would cause a double-free when the Zygisk framework cleans up.
        if (instance_.release() != nullptr) {
            LOGD("Module context singleton released.");
        }
    } else {
        LOGD("Preventing Zygisk from unloading module library.");
    }
}

}  // namespace vector::native::module

// =========================================================================================
// Zygisk Module Registration
// =========================================================================================
REGISTER_ZYGISK_MODULE(vector::native::module::VectorModule);
