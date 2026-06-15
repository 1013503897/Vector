#pragma once

// art_internal — the single home for ART (libart.so) internals the unpacker needs:
// mangled-symbol-resolved function pointers + ABI struct offsets. Centralizing them
// here mirrors (and should eventually subsume) the ad-hoc resolution in
// module.cpp ForceCompileMethod (Runtime::instance_ / GetJit / EnqueueOptimizedCompilation,
// and the hardcoded entry_point offset +24).
//
// Resolution strategy = the established Vector pattern: ElfSymbolCache::GetArt()->
// getSymbAddress("_ZN3art..."), NOT lsplant's C++20 ART module wrappers (those are
// internal to lsplant's own build and not exported to this TU). Several names vary by
// Android version -> use a candidate list and take the first hit (cf. the multi-symbol
// `|` fallbacks in external/lsplant .../art/runtime/dex_file.cxx).

#include <cstddef>
#include <cstdint>

namespace vector::native::unpack::art {

// Resolved libart surface. Any pointer may be null if unresolved on this build/version;
// callers MUST null-check and fail-safe (mirror ForceCompileMethod's "symbols missing").
struct Internal {
    // ---- per-method CodeItem / DexFile access (capture path, §2/§5) ----
    // ArtMethod::GetCodeItem() -> const dex::CodeItem* (the restored bytecode header).
    const void *(*art_method_get_code_item)(void *art_method) = nullptr;
    // ArtMethod::GetDexFile() -> const DexFile* (to reach the whole-dex image).
    const void *(*art_method_get_dex_file)(void *art_method) = nullptr;
    // ArtMethod::GetDexMethodIndex() -> uint32_t (where this CodeItem belongs in the dex).
    uint32_t (*art_method_get_dex_method_index)(void *art_method) = nullptr;

    // ---- whole-dex image (§5) ----
    const uint8_t *(*dex_file_begin)(const void *dex_file) = nullptr;  // DexFile::Begin()
    size_t (*dex_file_size)(const void *dex_file) = nullptr;           // DexFile::Size()

    // ---- enumeration (§3) ----
    // ClassLinker::VisitClasses(ClassVisitor*). The visitor is an ART-ABI object whose
    // operator() is called per mirror::Class; see method_enumerator for the shim.
    void (*class_linker_visit_classes)(void *class_linker, void *visitor) = nullptr;

    // ---- active driver: force-compile (Tier-B, reuse of ForceCompileMethod, §3) ----
    void **runtime_instance = nullptr;                          // art::Runtime::instance_
    void *(*runtime_get_jit)(void *runtime) = nullptr;          // Runtime::GetJit (often INLINED -> null; then derive jit_ via offset, see .cpp)
    void (*jit_enqueue_optimized_compilation)(void *jit, void *method, void *thread) = nullptr;  // Jit::EnqueueOptimizedCompilation

    // ---- ABI offsets (device-measured; cf. module.cpp +24) ----
    // ArtMethod.entry_point_from_quick_compiled_code_ byte offset within ArtMethod.
    size_t entry_point_off = 24;

    // Read the method's quick-compiled entry (pure read; same as ForceCompileMethod).
    void *entry_point_of(void *art_method) const;

    // True if the minimum-viable set for the requested phase is present.
    bool ok_for_capture() const;   // P0: get_code_item + get_dex_file + dex begin/size
    bool ok_for_enumerate() const; // P1: + visit_classes
    bool ok_for_forcecompile() const; // P1 Tier-B: + runtime_instance + enqueue
};

// Lazily resolves once and caches. Thread-safe one-time init (cf. ElfSymbolCache).
const Internal &Get();

}  // namespace vector::native::unpack::art
