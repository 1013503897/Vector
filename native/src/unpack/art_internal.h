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

    // ---- direction-1 increment-1: per-class dex discovery (offset-free) ----
    // mirror::Class::GetClassDef() -> const dex::ClassDef* — a pointer INTO the live dex image
    // (the class_defs section). Resolvable on this libart even though GetDexFile is inlined; the
    // containing /proc/self/maps region IS the real dex (dump it header-agnostically). Lets us
    // recover Yidun's mangled-header in-memory dex that the whole-dex maps scan skips.
    const void *(*mirror_class_get_class_def)(void *klass) = nullptr;
    // ClassLinker::FindClass — raw address, hooked transiently by the finder to capture the
    // ClassLinker* `this` (arg0). Needed because Runtime::GetClassLinker is INLINED (null) and
    // the Runtime.class_linker_ offset is unknown on this Android-16 build. FindClass fires on
    // every class load, so the capture is immediate; the finder unhooks right after.
    void *class_linker_find_class = nullptr;

    // ---- direction-1 increment-2c: interpreter-point capture (FART-style) ----
    // art::interpreter::Execute(Thread*, const CodeItemDataAccessor&, ShadowFrame&, JValue, bool,
    // bool) — the unified switch-interpreter entry every interpreted method passes through.
    // Resolved by PREFIX (the symbol carries a build-specific `.__uniq.N.llvm.N` suffix, and lives
    // in the LZMA .symtab inside .gnu_debugdata, not .dynsym). Hooking it captures the REAL CodeItem
    // (via the accessor arg) at the instant a method interprets — the ONLY point a side-cache /
    // DefineClass-restore extraction shell (dpt-shell) exposes real code; ArtMethod::GetCodeItem
    // returns the nop'd in-place stub there. Stored as void*; called via a local typedef.
    void *interpreter_execute = nullptr;

    // ---- active driver: force-compile (Tier-B, reuse of ForceCompileMethod, §3) ----
    void **runtime_instance = nullptr;                          // art::Runtime::instance_
    void *(*runtime_get_jit)(void *runtime) = nullptr;          // Runtime::GetJit (often INLINED -> null; then derive jit_ via offset, see .cpp)
    void (*jit_enqueue_optimized_compilation)(void *jit, void *method, void *thread) = nullptr;  // Jit::EnqueueOptimizedCompilation

    // ---- ABI offsets (device-measured; cf. module.cpp +24) ----
    // ArtMethod.entry_point_from_quick_compiled_code_ byte offset within ArtMethod.
    size_t entry_point_off = 24;

    // ---- direction-1 increment-2: per-method enumeration ABI (calibrated at runtime) ----
    // ArtMethod stride (== sizeof(ArtMethod)); calibrated via two adjacent Throwable ctors
    // (lsplant trick). declaring_class_ is at +0 (u32 compressed ref) and dex_method_index_ at
    // +8 on modern ART. mirror::Class.methods_ (a LengthPrefixedArray<ArtMethod>*, stored as a
    // raw u64) offset + its element-0 byte offset are SELF-CALIBRATED by scanning a sample Class
    // for a pointer whose first ArtMethod's declaring_class == that Class.
    size_t art_method_size = 0;            // 0 until CalibrateArtMethodSize succeeds
    size_t art_method_declaring_class_off = 0;   // ArtMethod.declaring_class_ (u32)
    size_t art_method_dex_index_off = 8;         // ArtMethod.dex_method_index_ (u32)
    size_t class_methods_off = 0;          // mirror::Class.methods_ (u64) — 0 until calibrated
    size_t class_methods_data_off = 0;     // LengthPrefixedArray<ArtMethod> element-0 offset

    // ---- increment-2c: ShadowFrame ABI ----
    // ShadowFrame.method_ byte offset. Layout is { ShadowFrame* link_@+0; ArtMethod* method_@+8;
    // ... }, stable across modern ART; ShadowFrame::GetMethod() is inlined so there's no symbol.
    size_t shadow_frame_method_off = 8;

    bool methods_calibrated() const { return art_method_size && class_methods_off; }

    // Read the method's quick-compiled entry (pure read; same as ForceCompileMethod).
    void *entry_point_of(void *art_method) const;

    // True if the minimum-viable set for the requested phase is present.
    bool ok_for_capture() const;   // P0: get_code_item + get_dex_file + dex begin/size
    bool ok_for_enumerate() const; // P1: + visit_classes
    bool ok_for_forcecompile() const; // P1 Tier-B: + runtime_instance + enqueue
    bool ok_for_dexfind() const;   // Increment-1: visit_classes + get_class_def + find_class
    bool ok_for_interp_capture() const;  // Increment-2c: interpreter_execute + get_class_def
};

// Lazily resolves once and caches. Thread-safe one-time init (cf. ElfSymbolCache).
const Internal &Get();

// Mutable accessor for the calibration writers below (same singleton as Get()).
Internal &GetMutable();

// increment-2 ABI calibration (idempotent; safe to call repeatedly until they succeed):
//   CalibrateArtMethodSize — needs a JNIEnv on an ART-attached thread; measures sizeof(ArtMethod)
//     from two adjacent java.lang.Throwable constructors (lsplant's method).
//   CalibrateClassMethods  — needs ONE sample mirror::Class* that has >=1 declared method; finds
//     mirror::Class.methods_ + the element-0 offset by the declaring_class==klass invariant. Must
//     run while the mutator lock is held (the sample class must be stable) — i.e. from the visitor.
// Both write into GetMutable(); return true once the value is known.
bool CalibrateArtMethodSize(void *jni_env);
bool CalibrateClassMethods(void *sample_klass);

// One-shot orchestration: calibrate art_method_size, derive a stable sample Class* (the declaring
// class of java.lang.String.length, a non-moving boot class), then calibrate the methods_ offset.
// Call once from the worker (needs a JNIEnv). Returns true iff methods_calibrated() afterwards.
bool CalibrateForMethodEnum(void *jni_env);

}  // namespace vector::native::unpack::art
