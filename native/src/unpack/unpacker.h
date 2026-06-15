#pragma once

// unpacker — public entry point for the stealth unpacker. Orchestrates: read prop-gated
// config -> install the choke hook -> spawn a post-init worker that drives active
// invocation -> flush the sink. Design §3/§6. Wired (later) from module.cpp's post-init
// worker, right after RunTracelessConvert() (module.cpp:755). Default OFF.

#include <jni.h>

#include "unpack/choke_hook.h"        // ChokePoint
#include "unpack/method_enumerator.h" // Tier

namespace vector::native::unpack {

struct Config {
    bool enabled = false;                       // persist.kpmhook.unpack = 1
    Tier tier = Tier::kForceCompile;            // persist.kpmhook.unpack.tier = A|B|C
    bool stealth = false;                       // persist.kpmhook.unpack.stealth = 0|1
    ChokePoint choke = ChokePoint::kArtMethodInvoke;  // persist.kpmhook.unpack.choke = invoke|bridge|execute
};

// Read the persist.kpmhook.unpack* props into a Config (all default-safe / OFF).
Config ReadConfigFromProps();

// No-op unless gated in (config.enabled AND this process is the KPM target). Spawns a
// worker thread that attaches to the ART runtime, installs the choke hook, runs the
// enumerator/driver for the configured tier, and flushes captured CodeItems to disk.
// Safe to call unconditionally from the post-init worker.
void StartIfEnabled(JavaVM *vm, JNIEnv *env);

}  // namespace vector::native::unpack
