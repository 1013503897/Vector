// method_enumerator.cpp — see method_enumerator.h. INERT until VECTOR_UNPACK_ENABLED.

#ifdef VECTOR_UNPACK_ENABLED

#include "unpack/method_enumerator.h"

#include <unistd.h>

#include <common/logging.h>

#include "unpack/art_internal.h"

namespace vector::native::unpack {

namespace {

// Drive ONE method so the shell restores its CodeItem.
//   kForceCompile: reuse ForceCompileMethod's mechanism (EnqueueOptimizedCompilation +
//                  poll the entry). See module.cpp:116 — duplicate the minimum here so the
//                  unpacker stays self-contained in native/.
//   kInvoke      : TODO(P4) ArtMethod::Invoke with a fabricated arg frame (FART-style).
void DriveMethod(const art::Internal &I, void *method, void *art_thread, Tier tier) {
    switch (tier) {
        case Tier::kPassive:
            return;  // nothing to do; capture happens on natural execution
        case Tier::kForceCompile: {
            if (!I.ok_for_forcecompile()) return;
            void *jit = nullptr;
            if (I.runtime_get_jit) {
                jit = I.runtime_get_jit(*I.runtime_instance);
            } else {
                // TODO(P1): Runtime::GetJit is inlined on this device -> read the jit_
                // member offset out of *runtime_instance instead (see kpm-ultimate-goal
                // notes: GetJit unexported, derive via Runtime::instance_ + jit_ offset).
                return;
            }
            if (!jit) return;
            I.jit_enqueue_optimized_compilation(jit, method, art_thread);
            // NOTE: the actual restore is observed by the choke hook, not here; no poll
            // needed for capture (poll only matters for M-C's trap-the-JIT-body path).
            break;
        }
        case Tier::kInvoke:
            // TODO(P4): fabricate a frame and Invoke. High crash risk; isolate.
            break;
    }
}

}  // namespace

size_t EnumerateAndDrive(Tier tier, void *art_thread) {
    const auto &I = art::Get();
    if (tier == Tier::kPassive) {
        LOGI("[unpack] tier=passive: no active driving");
        return 0;
    }
    if (!I.ok_for_enumerate()) {
        LOGW("[unpack] VisitClasses unresolved; cannot enumerate (tier downgraded to passive)");
        return 0;
    }

    // TODO(P1): build a ClassVisitor-ABI shim whose virtual operator()(mirror::Class*)
    //   - reads the class's ArtMethod array (add NumMethods/GetMethodsPtr to art_internal,
    //     or resolve mirror::Class accessors), and for each method calls DriveMethod().
    // ClassLinker* comes from Runtime (Runtime::GetClassLinker, or instance_ + offset).
    // Throttle/yield between classes so the JIT keeps up and the app stays responsive.
    (void)art_thread;
    (void)I;
    LOGW("[unpack] EnumerateAndDrive: visitor shim not implemented (P1 stub)");
    return 0;
}

}  // namespace vector::native::unpack

#endif  // VECTOR_UNPACK_ENABLED
