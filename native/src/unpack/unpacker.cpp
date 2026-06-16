// unpacker.cpp — see unpacker.h. INERT until VECTOR_UNPACK_ENABLED.
//
// Orchestration mirrors module.cpp RunTracelessConvert (module.cpp:307): a detached
// worker thread attaches to the ART runtime post-init, does the ART-touching work, then
// exits. Default OFF (gated by persist.kpmhook.unpack); fail-safe to no-op everywhere.

#ifdef VECTOR_UNPACK_ENABLED

#include "unpack/unpacker.h"

#include <fcntl.h>
#include <sys/system_properties.h>
#include <unistd.h>

#include <cstdlib>
#include <cstring>
#include <string>
#include <thread>

#include <common/logging.h>

#include "unpack/choke_hook.h"        // ChokePoint
#include "unpack/codeitem_sink.h"
#include "unpack/method_enumerator.h" // Tier, EnumerateAndDrive

namespace vector::native::unpack {

namespace {

// Prop-gated run config (fully internal; the public header exposes only StartIfEnabled).
struct Config {
    bool enabled = false;                                  // persist.kpmhook.unpack = 1
    Tier tier = Tier::kPassive;                            // .tier = A|B|C (P0 = A)
    bool stealth = false;                                  // .stealth = 0|1
    ChokePoint choke = ChokePoint::kArtMethodGetCodeItem;  // .choke = getcodeitem|invoke|bridge|execute
};

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
    void *art_thread = env->functions->reserved3;  // TODO(P1): the real art::Thread* (JNIEnv cookie / __get_tls)

    static CodeItemSink sink;
    sink.Init(out_dir.c_str());

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
    int rounds = PropInt("persist.kpmhook.unpack.rounds", 40);
    int interval_ms = PropInt("persist.kpmhook.unpack.interval_ms", 400);
    if (rounds < 1) rounds = 1;
    if (interval_ms < 1) interval_ms = 1;
    LOGI("[unpack] scanning {} round(s) every {}ms (immediate start)", rounds, interval_ms);
    for (int r = 0; r < rounds; r++) {
        sink.ScanProcessForDexes();                       // scan FIRST -> catch fast-exit packers
        if (r + 1 < rounds) usleep((useconds_t)interval_ms * 1000);
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
    std::string out_dir = (app_data_dir && app_data_dir[0]) ? std::string(app_data_dir) + "/unpack"
                                                            : std::string("/data/local/tmp/unpack");
    LOGI("[unpack] enabled: tier={} stealth={} choke={} dir={} -> spawning worker",
         static_cast<int>(cfg.tier), cfg.stealth, static_cast<int>(cfg.choke), out_dir.c_str());
    std::thread(WorkerMain, vm, cfg, std::move(out_dir)).detach();
    return true;
}

}  // namespace vector::native::unpack

#endif  // VECTOR_UNPACK_ENABLED
