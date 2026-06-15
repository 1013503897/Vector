// unpacker.cpp — see unpacker.h. INERT until VECTOR_UNPACK_ENABLED.
//
// Orchestration mirrors module.cpp RunTracelessConvert (module.cpp:307): a detached
// worker thread attaches to the ART runtime post-init, does the ART-touching work, then
// exits. Default OFF (gated by persist.kpmhook.unpack); fail-safe to no-op everywhere.

#ifdef VECTOR_UNPACK_ENABLED

#include "unpack/unpacker.h"

#include <sys/system_properties.h>
#include <unistd.h>

#include <thread>

#include <common/logging.h>

#include "unpack/codeitem_sink.h"

namespace vector::native::unpack {

namespace {

bool PropIs(const char *name, char want) {
    char v[PROP_VALUE_MAX] = {0};
    return __system_property_get(name, v) > 0 && v[0] == want;
}

Tier ParseTier() {
    char v[PROP_VALUE_MAX] = {0};
    if (__system_property_get("persist.kpmhook.unpack.tier", v) <= 0) return Tier::kForceCompile;
    switch (v[0]) {
        case 'A': case 'a': return Tier::kPassive;
        case 'C': case 'c': return Tier::kInvoke;
        case 'B': case 'b': default: return Tier::kForceCompile;
    }
}

ChokePoint ParseChoke() {
    char v[PROP_VALUE_MAX] = {0};
    if (__system_property_get("persist.kpmhook.unpack.choke", v) <= 0)
        return ChokePoint::kArtMethodInvoke;
    if (v[0] == 'b') return ChokePoint::kInterpreterBridge;
    if (v[0] == 'e') return ChokePoint::kExecute;
    return ChokePoint::kArtMethodInvoke;
}

void WorkerMain(JavaVM *vm, Config cfg) {
    // Attach to the ART runtime so we hold a valid art::Thread* for the driver.
    JNIEnv *env = nullptr;
    if (vm->AttachCurrentThread(&env, nullptr) != JNI_OK || !env) {
        LOGW("[unpack] worker: AttachCurrentThread failed");
        return;
    }
    void *art_thread = env->functions->reserved3;  // TODO(P1): the real art::Thread* (JNIEnv cookie / __get_tls)

    static CodeItemSink sink;
    // TODO(P0): derive the app-writable out dir from the package (e.g. /data/data/<pkg>/unpack).
    sink.Init("/data/local/tmp/unpack");

    if (!InstallChokeHook(cfg.choke, cfg.stealth, &sink)) {
        LOGW("[unpack] worker: choke hook install failed; aborting (no-op)");
        vm->DetachCurrentThread();
        return;
    }

    size_t driven = EnumerateAndDrive(cfg.tier, art_thread);
    LOGI("[unpack] worker: driven={} methods; letting captures settle", driven);

    // TODO(P0): give the JIT/restore + natural execution time to flush through the choke
    // hook, then snapshot. A signal/condvar from the driver is cleaner than a sleep
    // (cf. the convert-done signal in module.cpp bfee2de5).
    sleep(5);
    sink.Flush();

    // Leave the choke hook installed for the app's lifetime (more passive captures), or
    // RemoveChokeHook() here for a one-shot. P0: one-shot.
    RemoveChokeHook();
    vm->DetachCurrentThread();
    LOGI("[unpack] worker done: dex={} captures={}", sink.dex_count(), sink.capture_count());
}

}  // namespace

Config ReadConfigFromProps() {
    Config c;
    c.enabled = PropIs("persist.kpmhook.unpack", '1');
    c.tier = ParseTier();
    c.stealth = PropIs("persist.kpmhook.unpack.stealth", '1');
    c.choke = ParseChoke();
    return c;
}

void StartIfEnabled(JavaVM *vm, JNIEnv *env) {
    (void)env;
    Config cfg = ReadConfigFromProps();
    if (!cfg.enabled) return;  // default path: no-op
    if (!vm) {
        LOGW("[unpack] StartIfEnabled: no JavaVM");
        return;
    }
    // NOTE: the per-app KPM gate (persist.kpmhook.target) is enforced by kpm_inline_hooker
    // itself when stealth=1; for stealth=0 add an explicit package check here.
    LOGI("[unpack] enabled: tier={} stealth={} choke={} -> spawning worker",
         static_cast<int>(cfg.tier), cfg.stealth, static_cast<int>(cfg.choke));
    std::thread(WorkerMain, vm, cfg).detach();
}

}  // namespace vector::native::unpack

#endif  // VECTOR_UNPACK_ENABLED
