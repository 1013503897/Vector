#pragma once

// active_load — increment-2d. Forces every class of the app's loaded dex(es) to load+link via
// Class.forName, so a PER-CLASS extraction shell (dpt-shell) restores ALL of a class's CodeItems
// in place — including classes the app never reached at runtime (dead/conditional code that
// interaction + interp-capture both miss). dpt restores at class load (DefineClass), so this is the
// SAFE coverage path: it loads classes (no arbitrary method invocation, no constructed args).

#include <cstddef>

namespace vector::native::unpack {

// `classdefs` are the dex::ClassDef* the finder enumerated (used only to locate the app's dex
// regions in /proc/self/maps — framework/system dexes are skipped). For each app dex found, every
// class descriptor is enumerated and Class.forName'd through the app ClassLoader. `jni_env` is the
// worker's JNIEnv. Returns the number of classes successfully loaded. Run BEFORE the region dump so
// the dump captures the restored code. Exceptions per class are swallowed; failure is fail-safe (0).
size_t ActiveLoadAllClasses(void *jni_env, const void *const *classdefs, size_t n);

}  // namespace vector::native::unpack
