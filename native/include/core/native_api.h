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
 *      which contains function pointers to Vector's hooking
 *      and unhooking implementations (powered by Dobby).
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
 * Stealth-hook backend (vendored in native/src/kpm, from ../stealth-poc). These map
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
// Hide an anomalous region (page of `addr`) from this process's /proc/self/{maps,smaps} via
// the KPM's mm-gated maps-hide -- e.g. the LSPlant trampoline pool (rwxp anon). Gated process only.
int kpm_hide_region(void *addr);
}

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
 * @brief A wrapper around DobbyHook.
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
 * @brief A wrapper around DobbyDestroy.
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
    // If this target was KPM-hooked, kpm_inline_unhooker tears it down and returns 1;
    // otherwise (Dobby-hooked, or bridge down) it returns 0 and we use DobbyDestroy.
    if constexpr (kUseKpmBackend) {
        if (kpm_inline_unhooker(original)) return 0;
    }
    return DobbyDestroy(original);
}

}  // namespace vector::native
