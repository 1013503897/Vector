#pragma once

// unpacker — PUBLIC entry point for the stealth unpacker (the only header the zygisk module
// includes; all internals live in native/src/unpack/, PRIVATE to the native lib). Wired from
// module.cpp's post-init, right after RunTracelessConvert(). Default OFF
// (persist.kpmhook.unpack != 1) -> StartIfEnabled is a no-op.

#include <jni.h>

namespace vector::native::unpack {

// No-op unless gated in (persist.kpmhook.unpack=1 AND process_name == persist.kpmhook.target).
// Spawns a detached worker that dumps each app dex to <app_data_dir>/unpack (or
// /data/local/tmp/unpack if null). `process_name` is the app's nice name (caller passes it;
// /proc/self/cmdline is still "zygote64" at postAppSpecialize time). Safe to call
// unconditionally. Returns true iff a worker was spawned -> the caller must keep the module
// mapped (SetAllowUnload(false)) because the detached worker runs this library's code. The
// unpacker only needs to be in-process, so this is independent of Vector's hooking scope.
bool StartIfEnabled(JavaVM *vm, JNIEnv *env, const char *app_data_dir, const char *process_name);

}  // namespace vector::native::unpack
