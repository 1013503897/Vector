#pragma once

// active_invoke — Tier-C (FART's fartwithClassloader). Reflectively invokes every declared method
// and constructor of every app class, forcing a RESTORE-ON-INVOKE extraction shell to refill each
// method's CodeItem the instant it is called. This is the coverage that active_load (restore at
// DefineClass) and the GetCodeItem trigger (restore on read) both miss: shells that only restore a
// method when it is actually invoked.
//
// SAFE-by-construction (the reflection route, not native ArtMethod::Invoke):
//   - static methods         -> Method.invoke(null, defaultArgs)
//   - instance methods       -> Method.invoke(Unsafe.allocateInstance(clazz), defaultArgs)  (a blank
//                               object, no <init> side effects; the body usually NPEs -> caught)
//   - constructors           -> Constructor.newInstance(defaultArgs)
// Every call is wrapped so ONLY Java exceptions are raised (IllegalArgument / NPE / InvocationTarget
// / InstantiationException) — all cleared — so the process survives. Args are built to match the
// parameter count/types (primitives -> boxed zero, refs -> null); a mismatched arg array would make
// Method.invoke throw at marshalling BEFORE entering the body, triggering no restore.
//
// CAPTURE: the restored CodeItems are grabbed by interp_capture's art::interpreter::Execute hook,
// which MUST be actively capturing while this runs — so call this as the in-window driver of
// CaptureInterpreted (see unpacker.cpp). abstract/native methods are skipped (no CodeItem).

#include <cstddef>

namespace vector::native::unpack {

// Reflectively invoke every method/constructor of every app class located via `classdefs` (same
// input as ActiveLoadAllClasses — used only to find the app's /proc/self/maps dex regions).
// `jni_env` is the worker's attached JNIEnv (invoked code runs on this thread). `budget_ms` bounds
// total wall time, checked BETWEEN classes (a single hung method can still overrun it). Returns the
// number of methods + constructors invoked. Fail-safe: 0 if the reflection surface / ClassLoader is
// unavailable. When Unsafe is unreachable, instance methods are skipped and static methods +
// constructors still run.
size_t ActiveInvokeAllMethods(void *jni_env, const void *const *classdefs, size_t n, int budget_ms);

}  // namespace vector::native::unpack
