#pragma once

#include <dlfcn.h>
#include <dobby.h>

#include <string>
#include <utils/hook_helper.hpp>

#include "common/config.h"
#include "common/logging.h"

/**
 * @file native_api.h
 * @brief Manages the native module ecosystem and provides a stable API for them.
 *
 * This component is responsible for hooking the dynamic library loader (`dlopen`) to
 * detect when registered native modules are loaded.
 * It then provides these modules with a set of function pointers for
 * interacting with the Vector core, primarily for creating native hooks.
 */

// NOTE: The following type definitions form a public ABI for native modules.
// Do not change them without careful consideration for backward compatibility.

/*
 * =========================================================================================
 *  Vector Native API Interface
 * =========================================================================================
 *
 * This following function types and data structures allow a native library (your module) to
 * interface with the Vector framework.
 * The core idea is that Vector provides a set of powerful tools (like function hooking),
 * and your module consumes these tools through a well-defined entry point.
 *
 * The interaction flow is as follows:
 *
 *   1. Vector intercepts the loading of your native library (e.g., libnative.so).
 *   2. Vector looks for and calls the `native_init` function within your library.
 *   3. Vector passes a `NativeAPIEntries` struct to your `native_init`,
 *      which contains function pointers to Vector's hooking and unhooking
 *      implementations (KPM traceless backend first, Dobby as the fallback).
 *   4. Your `native_init` function saves these function pointers for later use
 *      and returns a callback function (`NativeOnModuleLoaded`).
 *   5. Vector will then invoke your returned callback every time
 *      a new native library is loaded into the target process,
 *      allowing you to perform "late" hooks on specific libraries.
 *
 *
 * Initialization Flow
 *
 *   Vector Framework                    Your Native Module (e.g., libnative.so)
 *   -----------------                    -------------------------------------
 *
 *        |                                            |
 * [ Intercepts dlopen("libnative.so") ]               |
 *        |                                            |
 *        |----------> [ Finds & Calls native_init() ] |
 *        |                                            |
 *   [ Passes NativeAPIEntries* ]  ---> [ Stores function pointers ]
 *   (Contains hook/unhook funcs)                      |
 *        |                                            |
 *        |                                            |
 *        |             <-----------[ Returns `NativeOnModuleLoaded` callback ]
 *        |                                            |
 *        |                                            |
 *   [ Stores your callback ]                          |
 *        |                                            |
 *
 */

// Function pointer type for a native hooking implementation.
using HookFunType = int (*)(void *func, void *replace, void **backup);

// Function pointer type for a native unhooking implementation.
using UnhookFunType = int (*)(void *func);

// Callback function pointer that modules receive, invoked when any library is loaded.
using NativeOnModuleLoaded = void (*)(const char *name, void *handle);

/**
 * @struct NativeAPIEntries
 * @brief A struct containing function pointers exposed to native modules.
 */
struct NativeAPIEntries {
    uint32_t version;          // The version of this API struct.
    HookFunType hookFunc;      // Pointer to the function for inline  hooking.
    UnhookFunType unhookFunc;  // Pointer to the function for unhooking.
};

// NOTE: Module developers should not include the following INTERNAL definitions.

/*
 * Stealth-hook backend (vendored in native/src/kpm, from ../stealth-core). These map
 * LSPlant's inline_hooker/unhooker onto our KernelPatch module over the no-superkey
 * syscall bridge, so the libart inline hooks become traceless (the target .text is
 * never modified -- CRC-clean). kpm_hook_init() returns 0 only when the bridge is
 * armed (privileged boot-time bootstrap: shctl <KEY> load shpte.kpm; control shpte
 * probe; control shpte bridge); otherwise HookInline falls back to Dobby so Vector
 * keeps working without the KPM. See lib/kpmhook.h for the full contract.
 */
extern "C" {
// Identify the app to the KPM process gate before LSPlant installs its inline hooks
// (at hook time /proc/self/cmdline is still "zygote64"). Only the build's injection
// target then engages the KPM; every other process stays on Dobby.
void kpm_hook_set_process_name(const char *name);
int kpm_hook_init(void);
void *kpm_inline_hooker(void *target, void *hooker);
int kpm_inline_unhooker(void *func);
// Traceless Java-method (qc) hook via SSOL -- distinct from kpm_inline_hooker (which clones hot
// libart-FUNCTION pages). Used by LSPlant's traceless_inline_hooker; returns the unmapped backup VA.
void *kpm_ssol_hooker(void *target, void *hooker);
int kpm_ssol_unhooker(void *func);
// Hide an anomalous region (page of `addr`) from this process's /proc/self/{maps,smaps} via
// the KPM's mm-gated maps-hide -- e.g. the LSPlant trampoline pool (rwxp anon). Gated process only.
int kpm_hide_region(void *addr);
}

/*
 * ================== Backend-selection strategy matrix (single source of truth) ==================
 * There are THREE distinct hook-install strategies in this tree. They deliberately differ; do NOT
 * "unify" them -- each fallback is chosen for its threat model. Recorded here so the divergence is
 * intentional and visible instead of being flattened by a well-meaning refactor.
 *
 *   1. libart inline (HookInline / UnhookInline below; LSPlant InitInfo.inline_hooker in
 *      native_api.cpp): KPM region-clone FIRST, then Dobby on failure. Hot libart .text; a Dobby
 *      trampoline here is acceptable (these processes have no anti-tamper self-check) so falling
 *      back keeps the framework working when the bridge is down.
 *
 *   2. Java-method `qc` traceless (LSPlant InitInfo.traceless_inline_hooker -> kpm_ssol_hooker):
 *      KPM SSOL FIRST, then the in-place ArtMethod entry swap on failure. NEVER Dobby -- a clone of
 *      dense framework JIT corrupts (code/data interleave) and a Dobby inline on a cold qc is both
 *      wrong and pointless. See kpm/kpmhook.c for the clone-vs-SSOL split rationale.
 *
 *   3. Unpacker / anti-tamper targets (unpack/choke_hook.cpp InstallBackend, class_dex_finder.cpp,
 *      the unpacker.cpp gcashfix + openat probes): stealth XOR dobby, selected per call. The
 *      traceless-ONLY sites (openat/gcashfix/FindClass) call kpm_inline_hooker with NO Dobby
 *      fallback -- a Dobby/inline patch there gets the process SIGKILL'd by the app's anti-tamper
 *      guard, so "no hook" is safer than "traced hook". choke_hook's `stealth` flag picks Dobby
 *      only for benign shells with no self-check.
 * ==============================================================================================
 */

namespace vector::native {

// Use the traceless KPM backend for inline hooks when its bridge is available; flip
// to false to force the stock Dobby backend everywhere.
inline constexpr bool kUseKpmBackend = true;

// The entry point function that native modules must export (`native_init`).
using NativeInit = NativeOnModuleLoaded (*)(const NativeAPIEntries *entries);

/**
 * @brief Installs the hooks required for the native API to function.
 * @param handler The LSPlant hook handler.
 * @return True on success, false on failure.
 */
bool InstallNativeAPI(const lsplant::HookHandler &handler);

/**
 * @brief Registers a native library by its filename for module initialization.
 *
 * When a library with a matching filename is loaded via `dlopen`, the runtime will attempt to
 * initialize it as a native module by calling its `native_init` function.
 *
 * @param library_name The filename of the native module's .so file (e.g., "libmymodule.so").
 */
void RegisterNativeLib(const std::string &library_name);

/**
 * @brief Install a traceless inline hook: KPM region-clone backend first, Dobby fallback.
 *
 * Routes through the KPM traceless engine (the target's .text is never modified) when its bridge
 * is armed; falls back to DobbyHook when the bridge is down or this particular target can't be
 * KPM-hooked. See strategy matrix above (case 1). `backup` receives the call-original pointer.
 */
inline int HookInline(void *original, void *replace, void **backup) {
    if constexpr (kIsDebugBuild) {
        Dl_info info;
        if (dladdr(original, &info)) {
            LOGD("inline hooking {} ({}) from {} ({})",
                 info.dli_sname ? info.dli_sname : "(unknown symbol)",
                 info.dli_saddr ? info.dli_saddr : original,
                 info.dli_fname ? info.dli_fname : "(unknown file)", info.dli_fbase);
        }
    }
    // Traceless first: route through our KPM when its bridge is armed. The returned
    // backup is the in-clone faithful copy of the target (call-original). Fall back
    // to Dobby if the bridge is down or this particular target can't be KPM-hooked.
    if constexpr (kUseKpmBackend) {
        if (kpm_hook_init() == 0) {
            if (void *bk = kpm_inline_hooker(original, replace)) {
                *backup = bk;
                return 0;
            }
            LOGW("KPM inline hook failed for {}; falling back to Dobby", original);
        }
    }
    return DobbyHook(original, reinterpret_cast<dobby_dummy_func_t>(replace),
                     reinterpret_cast<dobby_dummy_func_t *>(backup));
}

/**
 * @brief Remove an inline hook installed by HookInline: KPM unhook first, Dobby fallback.
 *
 * Tears down the KPM region hook if this target was KPM-hooked; otherwise removes the Dobby hook.
 * See strategy matrix above (case 1). Returns 0 on success.
 */
inline int UnhookInline(void *original) {
    if constexpr (kIsDebugBuild) {
        Dl_info info;
        if (dladdr(original, &info)) {
            LOGD("inline unhooking {} ({}) from {} ({})",
                 info.dli_sname ? info.dli_sname : "(unknown symbol)",
                 info.dli_saddr ? info.dli_saddr : original,
                 info.dli_fname ? info.dli_fname : "(unknown file)", info.dli_fbase);
        }
    }
    // kpm_inline_unhooker is TRI-STATE (see kpm/kpmhook.h): 1 = KPM hook torn down cleanly;
    // 0 = it WAS a KPM hook but bridge teardown failed (the KPM trap may still be armed -- must
    // NOT DobbyDestroy an address that was never Dobby-hooked); -1 = not a KPM hook -> Dobby.
    if constexpr (kUseKpmBackend) {
        int rc = kpm_inline_unhooker(original);
        if (rc == 1) return 0;
        if (rc == 0) {
            LOGW("KPM unhook FAILED for {} (trap may still be armed); NOT falling back to Dobby",
                 original);
            return -1;
        }
        // rc == -1: not a KPM hook -> fall through to Dobby.
    }
    return DobbyDestroy(original);
}

}  // namespace vector::native
