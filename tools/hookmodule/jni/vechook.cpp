// vechook.cpp — a Vector native hook module (route 1: the NativeAPIEntries ABI).
//
// This is a STANDALONE, self-contained example: it re-declares Vector's native-module ABI
// (see native/include/core/native_api.h) so it builds with nothing but the NDK. Vector
// intercepts dlopen of this .so, calls native_init(), hands us hook/unhook function pointers,
// and we return a callback invoked on every subsequent library load.
//
// The hooks installed here are inline hooks; they automatically run on Vector's TRACELESS KPM
// backend when its bridge is armed, and silently fall back to Dobby otherwise. The module does
// not know or care which — that is the whole point of going through entries->hookFunc.
//
// What it demonstrates, against com.moneydd.goodmoney (a DexProtector-packed Flutter loan app):
//   1. Loader observability   — log EVERY library the app dlopen()s (needs zero target knowledge).
//   2. libc openat hook        — log every file the app opens (DexProtector asset reads, etc.).
//   3. __system_property_get   — log every system property the app reads (fingerprint / anti-emu).
//   4. Late-hook template      — when a target lib loads, resolve a symbol in it and hook it.
//
// Build: see ../README.md (ndk-build). Logs: adb logcat -s vechook:V

#include <android/log.h>
#include <dlfcn.h>
#include <cstdint>
#include <cstring>

#define LOG_TAG "vechook"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)

// ============================================================================================
//  Vector native-module ABI  (mirror of native/include/core/native_api.h — keep in sync)
// ============================================================================================
using HookFunType   = int (*)(void *func, void *replace, void **backup);
using UnhookFunType = int (*)(void *func);
using NativeOnModuleLoaded = void (*)(const char *name, void *handle);

struct NativeAPIEntries {
    uint32_t version;          // Vector currently passes version = 2
    HookFunType hookFunc;      // inline hook  (KPM-traceless when armed, else Dobby)
    UnhookFunType unhookFunc;  // inline unhook
};

// ============================================================================================
//  Saved API entry points
// ============================================================================================
static HookFunType   g_hook   = nullptr;
static UnhookFunType g_unhook = nullptr;

// Re-entrancy guard: our hooks call __android_log_print, which may itself touch openat the very
// first time it connects to logd. Without this, openat -> log -> openat would recurse.
static thread_local bool g_in_hook = false;

struct ReentryGuard {
    bool engaged;
    ReentryGuard() : engaged(!g_in_hook) { if (engaged) g_in_hook = true; }
    ~ReentryGuard() { if (engaged) g_in_hook = false; }
};

// ============================================================================================
//  Hook 1: openat — every file the app opens
// ============================================================================================
using OpenatFn = int (*)(int dirfd, const char *path, int flags, int mode);
static OpenatFn g_orig_openat = nullptr;

static int openat_hook(int dirfd, const char *path, int flags, int mode) {
    int fd = g_orig_openat(dirfd, path, flags, mode);
    ReentryGuard g;
    if (g.engaged && path) LOGI("openat(%s) flags=0x%x -> fd=%d", path, flags, fd);
    return fd;
}

// ============================================================================================
//  Hook 2: __system_property_get — every system property the app reads (fingerprint / anti-emu)
// ============================================================================================
using PropGetFn = int (*)(const char *name, char *value);
static PropGetFn g_orig_prop_get = nullptr;

static int prop_get_hook(const char *name, char *value) {
    int n = g_orig_prop_get(name, value);
    ReentryGuard g;
    if (g.engaged && name) LOGI("__system_property_get(%s) = \"%s\"", name, n > 0 ? value : "");
    return n;
}

// ============================================================================================
//  Helper: install an inline hook on an already-loaded symbol, by name, via RTLD_DEFAULT.
// ============================================================================================
static bool hook_symbol(const char *sym, void *replacement, void **backup) {
    void *target = dlsym(RTLD_DEFAULT, sym);
    if (!target) { LOGW("dlsym(%s) failed: %s", sym, dlerror()); return false; }
    if (g_hook(target, replacement, backup) != 0) {
        LOGW("hook(%s @ %p) failed", sym, target);
        return false;
    }
    LOGI("hooked %s @ %p (backup=%p)", sym, target, *backup);
    return true;
}

// ============================================================================================
//  Late-hook example: fires when a specific library is loaded into the process.
//  Demonstrates the pattern for hooking a target lib's OWN exported symbol once it is mapped.
// ============================================================================================
using JniOnLoadFn = int (*)(void *vm, void *reserved);
static JniOnLoadFn g_orig_flutter_jni_onload = nullptr;

static int flutter_jni_onload_hook(void *vm, void *reserved) {
    { ReentryGuard g; if (g.engaged) LOGI("libflutter.so JNI_OnLoad(vm=%p) — Flutter runtime init", vm); }
    return g_orig_flutter_jni_onload(vm, reserved);
}

// Called by Vector on EVERY dlopen in the target process (after the original dlopen returns).
static void on_module_loaded(const char *name, void *handle) {
    ReentryGuard g;
    if (!g.engaged) return;
    LOGI("dlopen: %s (handle=%p)", name ? name : "(null)", handle);

    // ---- Late-hook template: hook a symbol exported by a lib once it is mapped. -------------
    // Here: hook libflutter.so's JNI_OnLoad. Swap the lib name / symbol for your own target.
    if (name && strstr(name, "libflutter.so") && handle && !g_orig_flutter_jni_onload) {
        void *fn = dlsym(handle, "JNI_OnLoad");
        if (fn && g_hook(fn, reinterpret_cast<void *>(&flutter_jni_onload_hook),
                         reinterpret_cast<void **>(&g_orig_flutter_jni_onload)) == 0) {
            LOGI("late-hooked libflutter.so!JNI_OnLoad @ %p", fn);
        }
    }
}

// ============================================================================================
//  native_init — Vector's entry point. Save the API, install immediate hooks, return callback.
// ============================================================================================
extern "C" __attribute__((visibility("default")))
NativeOnModuleLoaded native_init(const NativeAPIEntries *entries) {
    if (!entries || !entries->hookFunc) {
        LOGW("native_init: bad entries");
        return nullptr;
    }
    g_hook   = entries->hookFunc;
    g_unhook = entries->unhookFunc;
    LOGI("native_init: Vector native API v%u, hook=%p", entries->version,
         reinterpret_cast<void *>(g_hook));

    // Immediate hooks on already-loaded libc symbols.
    hook_symbol("openat", reinterpret_cast<void *>(&openat_hook),
                reinterpret_cast<void **>(&g_orig_openat));
    hook_symbol("__system_property_get", reinterpret_cast<void *>(&prop_get_hook),
                reinterpret_cast<void **>(&g_orig_prop_get));

    // The callback fires on every future dlopen — that is the loader observability + the
    // hook point for late hooks on libs that are not loaded yet at native_init time.
    return &on_module_loaded;
}
