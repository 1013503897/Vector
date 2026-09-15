#include <common/config.h>
#include <common/logging.h>
#include <core/context.h>
#include <core/native_api.h>
#include <elf/elf_image.h>
#include <elf/symbol_cache.h>
#include <jni/jni_bridge.h>
#include <unpack/unpacker.h>
#include <sys/system_properties.h>
#include <unistd.h>

#include <cstdio>
#include <cstring>
#include <atomic>
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
// reads it to verify surface #3, and the traceless-convert worker reads it to upgrade them.
static constexpr int kMaxHookedMethods = 512;
static void *g_hooked_methods[kMaxHookedMethods];
static volatile int g_hooked_count = 0;
static JavaVM *g_vm = nullptr;
// Traceless-convert worker lifecycle, so the detection probe scans AFTER the conversion finishes
// instead of using a brittle fixed delay. NONE=not launched (fc off / not gated), RUNNING=in flight,
// DONE=finished (success or bail).
enum { CONVERT_NONE = 0, CONVERT_RUNNING = 1, CONVERT_DONE = 2 };
static std::atomic<int> g_convert_state{CONVERT_NONE};
// Byte offset of `entry_point_from_quick_compiled_code_` in an ART ArtMethod, as resolved by
// LSPlant from the runtime's own layout (lsplant::GetArtMethodEntryPointOffset(), never a
// hardcoded constant). Filled in right after lsplant::Init and handed to the shared-stub router
// (B.7.2), whose HIT path reads a replacement's entry point to enter it the way ART itself would,
// instead of resuming the shared nterp stub with x0 rewritten -- see the block comment in
// native/src/kpm/kpmhook.c. Read by the hooker callback below, which runs long after Init.
static uint32_t g_art_entry_point_offset = 0;
static void RecordHookedMethod(void *method) {
    int i = g_hooked_count;
    if (i < kMaxHookedMethods) {
        g_hooked_methods[i] = method;
        g_hooked_count = i + 1;
    }
}

// ---- qc site classification (Phase B.7.3) ------------------------------------------------------
//
// WHERE does a method's quick-compiled entry (qc) live? That is the only question this classifier
// asks, and the answer decides which backend may own the method.
//
// It used to ask a different one -- "is the word at qc-4 a sane OatQuickMethodHeader::code_size?" --
// and that premise is NOT universally true. Measured on device: five methods that consequently fell
// all the way through to the detectable in-place hook had their qc in
// /system/framework/arm64/boot-framework.oat with qc-4 holding an INSTRUCTION word (0x97f3562e, a
// BL encoding) or 0x00000000 -- not a size at all. A shared stub is by definition ONE address
// shared by everyone who uses it; those five addresses are all different from each other and all
// inside boot-framework.oat, so they are those methods' OWN AOT bodies, and the code_size test was
// rejecting real bodies. The FILE a qc lives in is the reliable question: ART's shared stubs
// (quick_to_interpreter_bridge, the resolution trampolines, nterp) are functions COMPILED INTO
// libart.so, while a method's body lives in the .oat/.odex/.art file dex2oat wrote.
//
//   qc site                                meaning                          backend
//   -------------------------------------  -------------------------------  -----------------------
//   == nterp_entry_point                   ART's shared interpreter stub    router (B.7.2)
//   == nterp_with_clinit_entry_point       same page; one W^X patch/page    refuse -> in-place
//   executable, in libart.so               SHARED stub -- no exported       in-place ONLY: a patch
//                                          symbol, so location is the only  on one reroutes EVERY
//                                          way to recognise it               method that uses it
//   executable, in .oat/.odex/.art         the method's OWN AOT body        R^X
//   executable, ART's JIT code cache       own body, but a page ART keeps   in-place (B.7.0 guard)
//                                          writing
//   anything else (no VMA, non-executable, uncertain                        in-place + the reason
//   maps unreadable, unrecognised file)                                     (fail closed)
//
// The two nterp rows use the RESOLVED SYMBOL VALUES (WxRouterSharedStubKind), never a location
// guess -- red line 4. Everything else is file identity from /proc/self/maps. Nothing is inferred
// from the bytes at qc-4 any more, and the JIT cache is recognised BEFORE libart/.oat so that a
// path naming both can never be armed.
//
// THIS RULE IS A CONTRACT WITH native/src/kpm/kpmhook.c (wx_site_of, and the per-method arm gate in
// kpm_wx_java_hooker that consumes it). The mirror there is deliberately a second, independent
// implementation: it is the backstop that keeps a shared-stub address away from the kernel-adjacent
// arm even if the decision made here is wrong. CHANGE THE TWO TOGETHER.
enum class QcSite {
    kUnknown,  // no VMA / not executable / maps unreadable / unrecognised file -> fail closed
    kInterp,   // ART's shared interpreter entry (nterp or nterp_with_clinit)
    kLibart,   // executable libart.so: a SHARED stub, never a per-method body
    kOat,      // executable .oat/.odex/.art: the method's OWN file-backed AOT body
    kJit,      // ART's JIT code cache: an own body, but never an R^X target (B.7.0)
};

// Classify `qc` by location. `*why` is set to a static reason string for EVERY answer (including
// the permissive one), so a caller can report a refusal without re-deriving anything.
static QcSite QcSiteOf(const void *qc, const char **why) {
    const char *unused = nullptr;
    if (!why) why = &unused;
    auto a = reinterpret_cast<uintptr_t>(qc);
    if (a < 0x2000) {
        *why = "not a plausible code address (null / below the first page)";
        return QcSite::kUnknown;
    }
    // Red line 4: ART's two shared interpreter entries are identified by the values RESOLVED FROM
    // ART'S SYMBOLS, never by where they happen to sit -- they live in libart.so and would
    // otherwise be indistinguishable from any other shared stub there.
    switch (vector::native::WxRouterSharedStubKind(const_cast<void *>(qc))) {
        case 1:
            *why = "qc == nterp_entry_point (ART's shared interpreter entry, resolved from ART's "
                   "symbols): every interpreted method of the process enters here, so it belongs to "
                   "the B.7.2 router, not to a per-method backend";
            return QcSite::kInterp;
        case 2:
            *why = "qc == nterp_with_clinit_entry_point (ART's static-method interpreter entry, "
                   "resolved from ART's symbols): it shares nterp_entry_point's page and the R^X "
                   "backend allows one patch per page, so it cannot be routed either";
            return QcSite::kInterp;
        default:
            break;
    }
    FILE *f = fopen("/proc/self/maps", "re");
    if (!f) {
        *why = "/proc/self/maps unreadable: the file behind this address cannot be determined";
        return QcSite::kUnknown;
    }
    char line[512], perms[8] = {0}, path[256] = {0};
    uintptr_t lo = 0, hi = 0;
    bool found = false;
    while (fgets(line, sizeof line, f)) {
        path[0] = '\0';
        if (sscanf(line, "%lx-%lx %7s %*x %*x:%*x %*u %255[^\n]", &lo, &hi, perms, path) >= 3 &&
            a >= lo && a < hi) {
            found = true;
            break;  // maps regions are disjoint and sorted: this is the only one that can describe a
        }
    }
    fclose(f);
    if (!found) {
        *why = "no /proc/self/maps region covers this address (a VMA-less ghost page -- e.g. one of "
               "this module's own stubs -- is not a method body)";
        return QcSite::kUnknown;
    }
    if (perms[2] != 'x') {
        *why = "the covering mapping is not executable";
        return QcSite::kUnknown;
    }
    if (strstr(path, "jit-code-cache") || strstr(path, "jit-cache")) {
        *why = "the qc page is ART's JIT code cache, which ART keeps writing: an R^X shadow page is "
               "a SNAPSHOT of it (stale bytes -> SIGILL, B.7.0 device-measured)";
        return QcSite::kJit;
    }
    if (strstr(path, "libart")) {
        *why = "the qc page is executable libart.so, where ART's SHARED stubs live "
               "(quick_to_interpreter_bridge / resolution trampolines / nterp): they have no "
               "per-method identity, so an R^X patch on this page would reroute every method that "
               "uses the stub -- process-wide and irreversible";
        return QcSite::kLibart;
    }
    if (strstr(path, ".oat") || strstr(path, ".odex") || strstr(path, ".art") ||
        strstr(path, "/oat/")) {
        *why = "the qc page is a file-backed .oat/.odex/.art mapping: the method's own AOT code";
        return QcSite::kOat;
    }
    *why = "the qc page is executable but its file is neither libart.so nor a .oat/.odex/.art "
           "mapping (in-memory dex / anonymous code)";
    return QcSite::kUnknown;
}

// "Does this qc carry a compiled body OF ITS OWN?" -- the question the L2 clone backend, the
// force-compile probe and the S3 detection probe ask. AOT and JIT bodies BOTH answer yes: the JIT
// code cache holds one compiled body per method and never a shared stub. The R^X-specific
// restriction (never arm a page ART keeps writing) is deliberately NOT imposed here -- the R^X call
// sites ask QcIsRxArmable, and kpmhook.c's B.7.0 guard is the backstop for them.
static bool QcHasOwnBody(const void *qc, const char **why) {
    QcSite s = QcSiteOf(qc, why);
    return s == QcSite::kOat || s == QcSite::kJit;
}
static bool QcIsTraceable(const void *qc) { return QcHasOwnBody(qc, nullptr); }

// "May the R^X shadow backend arm a page over this qc?" -- ONLY a file-backed AOT body. libart.so
// is where ART's shared stubs live and a patch there reroutes every user of the stub. EVERY refusal
// logs its reason: the phase's coverage acceptance is counted from these lines, and an "in-place"
// with no reason is not diagnosable. Fail closed (red line 3): never guess.
static bool QcIsRxArmable(const void *qc) {
    const char *why = nullptr;
    QcSite s = QcSiteOf(qc, &why);
    if (s == QcSite::kOat) return true;
    LOGI("[wx] qc={} NOT R^X-armable -> in-place (red line: only a file-backed AOT body may be "
         "patched). reason: {}",
         qc, why);
    return false;
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
    // set -> DETECTED; a traceless hook leaves entry==real oat/jit code, flag clear -> CLEAN.
    // B.7.2: a SHARED-STUB-ROUTED method's entry is ART's own shared interpreter stub (nterp) --
    // which is what ART sets for any method it has not compiled, so it is pristine, not a mutation.
    // It is also a state no hook path can produce (every backend that writes the ArtMethod writes a
    // trampoline/clone/stub there instead), so accepting it cannot mask a real in-place hook. ----
    constexpr uint32_t kAccCompileDontBother = 0x02000000u;
    int hooked = g_hooked_count, s3_bad = 0, s3_routed = 0;
    for (int i = 0; i < hooked && i < kMaxHookedMethods; i++) {
        void *m = g_hooked_methods[i];
        if (!m) continue;
        void *entry = *reinterpret_cast<void **>(reinterpret_cast<char *>(m) + 24);
        uint32_t flags = *reinterpret_cast<uint32_t *>(reinterpret_cast<char *>(m) + 4);
        // points at a legit unique oat/jit body, OR at ART's shared interpreter entry (a method the
        // router took over: no compiled body exists to point at, and the router leaves it alone)
        bool entry_ok = QcIsTraceable(entry) || vector::native::WxRouterOwnsSharedStub(entry);
        bool flags_ok = !(flags & kAccCompileDontBother);  // not marked non-compilable by a hook
        if (entry_ok && !QcIsTraceable(entry)) {
            s3_routed++;
            if (s3_routed <= 6)
                LOGI("[probe] S3 shared-stub-routed ArtMethod {}: entry={} is ART's shared "
                     "interpreter stub (no per-method body exists) flags={:#x} -> pristine",
                     m, entry, flags);
        }
        if (!entry_ok || !flags_ok) {
            s3_bad++;
            if (s3_bad <= 6)
                LOGW("[probe] S3 mutated ArtMethod {}: entry={} ({}) flags={:#x} ({})", m, entry,
                     entry_ok ? "legit" : "ANOMALOUS", flags, flags_ok ? "ok" : "DontBother-set");
        }
    }

    LOGI("[probe] ===== DETECTION PROBE ===== S2 anon-rx={} rwxp={}  S5 TracerPid={}  S1/4 "
         "libart-patched-pages={}  S3 hooked={} mutated={} (of which {} shared-stub-routed, "
         "entry = ART's nterp stub by construction)",
         anon_rx, rwx, tracer_pid, code_diffs, hooked, s3_bad, s3_routed);
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
        // If a traceless convert is in flight, scan only AFTER it finishes -- no brittle fixed delay
        // (which raced the worker). Cap the wait so a stuck convert can never block the probe forever.
        for (int i = 0; i < 300 && g_convert_state.load() == CONVERT_RUNNING; i++)
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        std::this_thread::sleep_for(std::chrono::seconds(1));  // settle after the convert
        DetectionProbeScan();
    }).detach();
}

// Hide this process's anomalous anon EXECUTABLE regions from /proc/self/{maps,smaps} via the KPM.
// Two signatures: rwxp anon (the LSPlant trampoline pool every hook creates) AND r-xp anon (the KPM
// region clones, incl. any the auto-hide missed because a VMA merge moved its start). On a W^X
// system nothing legit is anon+executable, so hiding such regions closes surface #2. The scan
// itself lives in the native layer (kpm_hide_all_anon_exec) so it has ONE implementation shared
// with the host. It hides ONE hide-set entry PER REGION (B.4): the KPM's filter matches an entry
// against a VMA's vm_start, so a single registration covers a whole region. The old per-page walk
// spent 315 entries on ART's single 1.29MB in-memory-dex code region and filled the KPM's 64-entry
// set by itself, leaving the actual hook pools visible. That region is part of Vector's injected
// footprint (ART compiles the framework dex Vector loads in memory), so hiding it is intended.
// Budget now: on the order of the number of unnamed exec regions (a handful), not their pages.
// mm-gated in the KPM; only acts in the gated process. Safe to call repeatedly (dedups, so a
// repeat costs no new entry).
static void HideRwxpRegionsScan() {
    if (kpm_hook_init() != 0) return;  // gated process + bridge armed only
    int hid = kpm_hide_all_anon_exec();
    LOGI("[hidetramp] hid {} anon-exec region(s) (trampoline pool/in-memory-dex/clones) from "
         "maps/smaps", hid);
}
// Gate: the maps-hide exists FOR the traceless backends, so engage it when EITHER is requested.
// It used to key off l2 alone, which meant an operator who only wanted B.2 (wx) had to switch on
// l2 as well -- and l2 also arms the legacy SSOL branch, which DoHook falls through to for any
// method the wx backend refuses (a refusal wx makes can still pass SSOL's QcIsTraceable check, so
// that fallthrough is the original SSOL crash). wx alone now gets the hiding, no l2 needed.
// Returns true when hiding is engaged, so postAppSpecialize can also run the scan synchronously
// after InitHooks() through the SAME gate (one gate, one pair of log lines).
static bool RunTrampolineHide() {
    char l2[PROP_VALUE_MAX] = {0}, wx[PROP_VALUE_MAX] = {0};
    bool want_l2 = __system_property_get("persist.kpmhook.l2", l2) > 0 && l2[0] == '1';
    bool want_wx = __system_property_get("persist.kpmhook.wx", wx) > 0 && wx[0] == '1';
    if (!kUseKpmBackend || !(want_l2 || want_wx)) {
        LOGI("[hidetramp] gate: l2={} wx={} kpm_backend={} -> hiding OFF", want_l2 ? 1 : 0,
             want_wx ? 1 : 0, kUseKpmBackend ? 1 : 0);
        return false;  // gated process + bridge armed only (HideRwxpRegionsScan re-checks anyway)
    }
    // The +5s delayed rescan stays as the backstop: the arm path closes the pool window in
    // milliseconds, but regions minted LATER (a lazily-loaded dex, a late hook) would otherwise
    // stay visible until the app's next self-check. It costs one entry per region now, so it is
    // cheap; kpm_hide_all_anon_exec's dedup means a repeat finds nothing new to register.
    LOGI("[hidetramp] gate: l2={} wx={} kpm_backend=1 -> hiding ON (per-region scan at arm time + "
         "synchronously after InitHooks; +5s rescan as backstop)",
         want_l2 ? 1 : 0, want_wx ? 1 : 0);
    std::thread([] {
        std::this_thread::sleep_for(std::chrono::seconds(5));  // after startup hooks install
        HideRwxpRegionsScan();
    }).detach();
    return true;
}

// M-C: post-init worker that upgrades the early in-place hooks to traceless (force-compile + KPM
// trap, leaving each ArtMethod pristine -> closes surface #3). Gated by persist.kpmhook.fc.
// Runs as an ATTACHED ART thread (the conversion uses ScopedSuspendAll + art::Thread::Current)
// AFTER the JIT thread is up and startup hooks are installed.
static void RunTracelessConvert() {
    char v[PROP_VALUE_MAX] = {0};
    if (!kUseKpmBackend || __system_property_get("persist.kpmhook.fc", v) <= 0 || v[0] != '1') return;
    if (kpm_hook_init() != 0 || !g_vm) return;  // gated process + have a JavaVM
    g_convert_state = CONVERT_RUNNING;           // synchronous: the probe will wait for us to finish
    std::thread([] {
        std::this_thread::sleep_for(std::chrono::seconds(6));  // JIT up + startup hooks installed
        JNIEnv *env = nullptr;
        if (g_vm->AttachCurrentThread(&env, nullptr) == JNI_OK) {
            // The conversion needs the live art::jit::Jit instance -- captured the first time ART
            // checks/JITs ANY method (via the MaybeEnqueueCompilation/CompileMethod hooks), which
            // happens during ordinary Java execution even in a quiet process. POLL until it fires
            // (up to ~18s) then bail gracefully if it never does (methods keep their in-place hook).
            for (int i = 0; i < 180 && !lsplant::HasCapturedJit(); i++)
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            LOGI("[convert] capture wait done; captured_jit={}", (int)lsplant::HasCapturedJit());

            int n = g_hooked_count, ok = 0;
            for (int i = 0; i < n && i < kMaxHookedMethods; i++) {
                void *m = g_hooked_methods[i];
                if (m && lsplant::ConvertToTraceless(m)) ok++;
            }
            LOGI("[convert] traceless-converted {}/{} in-place hooks", ok, n);
            // Belt-and-suspenders: the conversion just minted KPM clones (r-xp anon). They're
            // auto-hidden by the KPM, but a VMA merge can move a clone's start so the auto-hide's
            // start-match misses it. Re-scan the post-convert maps and hide every anon-exec VMA by
            // its (post-merge) start page -> surface #2 stays clean deterministically.
            HideRwxpRegionsScan();
            g_vm->DetachCurrentThread();
        } else {
            LOGW("[convert] AttachCurrentThread failed");
        }
        g_convert_state = CONVERT_DONE;  // signal the probe regardless of outcome
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
                    const char *why = nullptr;
                    (void)QcHasOwnBody(target, &why);
                    LOGI("[l2] qc={} not a traceable AOT body (no per-method body of its own) -> "
                         "in-place. reason: {}",
                         target, why);
                    return nullptr;
                }
                // xp_on_demo: use the VERIFIED region-clone backend (L1d/L1e: 6 simultaneous
                // libart inline hooks through region clones, zero Dobby fallback, .text
                // untouched) instead of the SSOL single-step backend. This is exactly the L2a
                // design in docs/L2-java-traceless.md ("kpm_inline_hooker(M.GetEntryPoint(),
                // trampoline) ... the KPM needs NO change for L2a"), and it returns the
                // in-clone faithful copy as the call-original backup.
                void *bk = kpm_inline_hooker(target, replace);
                LOGI("[l2] traceless Java hook (REGION-CLONE): qc={} -> trampoline {}, bk={} ({})",
                     target, replace, bk, bk ? "TRACELESS" : "in-place fallback");
                return bk;
            },
        // Paired traceless un-hooker: disarm the SSOL trap by its qc. LSPlant uses this to follow
        // JIT-cache moves -- when a GC relocates/evicts a traceless-hooked method, the stale trap on
        // its old (recycled) page is disarmed here before re-arming at the new entry.
        .traceless_inline_unhooker =
            [](auto func) -> bool { return kpm_inline_unhooker(func) != 0; },
        // Phase B.2 R^X shadow-page backend (Java methods only). Ships OFF: it engages only when
        // persist.kpmhook.wx=1 AND this is a KPM-gated process AND the qc is a file-backed AOT body
        // (B.7.3 location rule: R^X is for .oat/.odex/.art only -- a libart.so qc is a SHARED stub,
        // a JIT-cache qc is a page ART keeps writing, and both are refused here with their reason,
        // as is anything unclassifiable). On null, DoHook falls through to the L2 path and then to
        // the normal in-place entry swap -- the reason is in logcat under the "kpmhook" tag.
        // This is the backend that keeps ART's unwinder happy (the patched code still runs at
        // its own address, so no clone/SSOL PC ever enters a stack frame).
        .wx_inline_hooker =
            [](auto target, auto replace) -> void * {
                char v[PROP_VALUE_MAX] = {0};
                if (!kUseKpmBackend ||
                    __system_property_get("persist.kpmhook.wx", v) <= 0 || v[0] != '1')
                    return nullptr;
                if (!QcIsRxArmable(target)) return nullptr;  // logs the site + the reason itself
                void *stub = kpm_wx_java_hooker(target, replace);
                LOGI("[wx] R^X shadow-page Java hook: qc={} -> trampoline {}, call-original "
                     "stub={} ({})",
                     target, replace, stub, stub ? "TRACELESS" : "in-place fallback");
                return stub;
            },
        // Paired un-hooker: put the original PTE back for the shadow page armed over `func`
        // (a quick-compiled entry -- never rewritten by this backend, so always recoverable from
        // the ArtMethod). Not property-gated: it is a no-op unless the entry is in the backend's
        // table, and gating it would leak an armed page if the property were flipped off between
        // hook and unhook.
        .wx_inline_unhooker =
            [](auto func) -> bool {
                // A shared-stub entry belongs to the ROUTER, never to a per-method shadow page.
                // This address is `target->GetEntryPoint()` for the method being unhooked, and for
                // a router-routed method that IS the shared interpreter stub -- releasing the patch
                // keyed on it would disarm the router for every routed method at once. Refuse and
                // say so (SharedRouterUnhook already claimed this method; this is the belt for a
                // method that reached here some other way).
                if (vector::native::WxRouterOwnsSharedStub(func)) {
                    LOGI("[router] wx unhook skipped for {}: it is ART's shared interpreter entry, "
                         "i.e. the router's patch, not a per-method shadow page",
                         func);
                    return false;
                }
                return kpm_wx_java_unhooker(func) != 0;
            },
        // Phase B.7.2 SHARED-STUB ROUTER -- the backend for methods with NO compiled body of their
        // own (their entry point is ART's SHARED nterp stub). Asked FIRST: it is the only backend
        // that can cover that case tracelessly, and its eligibility test (qc == the nterp entry
        // resolved from ART's symbols) is mutually exclusive with the per-method backends' tests.
        // It decides and logs; null on anything it will not take, and DoHook then runs the
        // R^X / clone / in-place chain exactly as before. Ships OFF (persist.kpmhook.router=1):
        // taking this path arms a GLOBAL entry point, so it must be an explicit choice.
        // NOTE the arguments: target and hook as ArtMethod* (a swap of x0 needs the hook's Art
        // Method, not a code address), plus the target's current entry for the symbol comparison.
        .shared_router_hooker =
            [](void *target, void *hook, void *qc) -> void * {
                // g_art_entry_point_offset is read, not captured: it is resolved from LSPlant once
                // the hooker is initialized, and this callback only ever runs after that.
                return vector::native::SharedRouterHook(target, hook, qc, g_art_entry_point_offset);
            },
        // Paired un-hooker. TRUE = the router owned this method (now unrouted) and the R^X
        // un-hooker must not be asked about its entry point (see the guard above). Not
        // property-gated, for the same reason as wx_inline_unhooker: a property flip between hook
        // and unhook must not be able to strand a routed entry in the table.
        .shared_router_unhooker =
            [](void *target) -> bool { return vector::native::SharedRouterUnhook(target); },
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

    // Stealth unpacker (no-op unless persist.kpmhook.unpack=1 AND nice_name==target). Runs in
    // ANY injected-marked process -- it only needs to be in-process (dump dexes), so it is
    // INDEPENDENT of Vector's hooking scope / the IPC binder below. Must precede the no-binder
    // early-return. If it spawns a worker (which runs this library's code), keep the module
    // mapped regardless of scope.
    bool unpack_started = false;
    {
        JavaVM *uvm = nullptr;
        env_->GetJavaVM(&uvm);
        lsplant::JUTFString app_dir(env_, args->app_data_dir);
        unpack_started = vector::native::unpack::StartIfEnabled(uvm, env_, app_dir.get(),
                                                                nice_name_str.get());
    }

    auto &ipc_bridge = IPCBridge::GetInstance();
    auto binder = ipc_bridge.RequestAppBinder(env_, args->nice_name);
    if (!binder) {
        LOGD("No IPC binder obtained for '{}'. Skipping injection.", nice_name_str.get());
        SetAllowUnload(!unpack_started);  // keep loaded if the unpacker worker is running
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
    // LSPlant has now resolved ART's ArtMethod layout, so the shared-stub router's one piece of
    // ArtMethod knowledge -- where `entry_point_from_quick_compiled_code_` lives -- is available.
    // It is asked for HERE, once, and never assumed: the router's hit path uses it to enter a
    // replacement through the replacement's own entry point (see the block comment in
    // native/src/kpm/kpmhook.c). A 0 (unresolved) makes every router install fail closed.
    g_art_entry_point_offset =
        static_cast<uint32_t>(lsplant::GetArtMethodEntryPointOffset());
    LOGI("[router] ArtMethod entry-point offset = 0x{:x} (from LSPlant's ArtMethod layout)",
         g_art_entry_point_offset);
    // L2a DBI-on-oat self-test (no-op unless persist.kpmhook.l2test=1 AND KPM-gated process).
    RunL2SelfTest(env_);
    if (env_) env_->GetJavaVM(&g_vm);  // for the traceless-convert worker thread (needs ART attach)
    // M-C: upgrade the early in-place hooks to traceless post-init (no-op unless persist.kpmhook.fc=1).
    RunTracelessConvert();
    // (The stealth unpacker is started earlier in postAppSpecialize -- before the IPC-binder
    // scope check -- so it runs even for apps outside Vector's hooking scope.)
    // Engage the maps-hide (no-op unless persist.kpmhook.{l2,wx}=1 AND gated). Closes surface #2
    // for EITHER traceless backend: the wx path hides its own trampoline pool region the instant
    // it arms (and its stub pool is VMA-less, so it is never visible at all); the in-place
    // fallback and any late-minted region are covered by the per-region scans below.
    bool hide_engaged = RunTrampolineHide();
    // Detection probe (no-op unless persist.kpmhook.probe=1): the GOAL judge, scans this
    // process's hook-detection surfaces on a delayed thread.
    RunDetectionProbe();
    // Phase B.7.1 POC (no-op unless persist.kpmhook.routerpoc=1): resolve ART's shared
    // interpreter entry from symbols and R^X-patch it ONCE with the shared-stub router. NOT the
    // hook path -- it routes nothing by itself; the 1-entry table decides, so an empty table
    // makes every interpreted call take the miss path, which is the red-line-4 test.
    // See native/src/kpm/wx_router_poc.cpp and PHASE-B7-1-ROUTER-POC.md.
    vector::native::WxRouterPocArmIfEnabled(g_art_entry_point_offset);
    // Initialize JNI hooks via the native library.
    this->InitHooks(env_);
    // B.3/B.4: scan SYNCHRONOUSLY, right after the Java hooks are installed, so it lands before
    // postAppSpecialize returns (i.e. before the target's startup self-check). A successful wx arm
    // already re-scanned on kpm_wx_java_hooker's return path (LSPlant's trampoline exists by then),
    // but methods the wx backend REFUSES fall back to the in-place path, which allocates trampolines
    // too -- those never pass through kpm_wx_java_hooker, so this is their cover at the same
    // per-region cost. The +5s scan started in RunTrampolineHide stays as the backstop for regions
    // minted later (and for the framework dex Vector loads in memory). Same gate, so hiding stays
    // off when disabled.
    if (hide_engaged) HideRwxpRegionsScan();
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
