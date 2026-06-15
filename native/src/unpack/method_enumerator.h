#pragma once

// method_enumerator — walks every ArtMethod via ClassLinker::VisitClasses and, per the
// active-invocation tier, drives the shell to restore each method's CodeItem. Design §3.
//
//   Tier A (passive)       : no driving; rely on natural execution through the choke hook.
//   Tier B (force-compile) : reuse the ForceCompileMethod path (EnqueueOptimizedCompilation)
//                            -> ART reads the CodeItem to compile. Does NOT run app code -> safe.
//   Tier C (invoke)        : ArtMethod::Invoke with a fabricated frame. FART-style; risky.

namespace vector::native::unpack {

enum class Tier { kPassive, kForceCompile, kInvoke };

// Enumerate all loaded classes' methods and apply the tier's driver. Must run on a
// thread attached to the ART runtime (the unpacker worker), after app init / JIT is up
// (mirror RunTracelessConvert's scheduling). `thread` is the current art::Thread* (the
// attached JNIEnv's cookie) needed by the force-compile / invoke paths.
// Returns the number of methods driven (best-effort; 0 on missing ART symbols).
size_t EnumerateAndDrive(Tier tier, void *art_thread);

}  // namespace vector::native::unpack
