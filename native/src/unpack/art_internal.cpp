// art_internal.cpp — lazy resolution of the libart surface (see art_internal.h).
//
// INERT until VECTOR_UNPACK_ENABLED is defined (the native CMake GLOBs src/*.cpp, so
// this file is compiled; the guard keeps it an empty TU so it cannot affect the build).

#ifdef VECTOR_UNPACK_ENABLED

#include "unpack/art_internal.h"

#include <mutex>

#include <common/logging.h>
#include <elf/elf_image.h>
#include <elf/symbol_cache.h>

namespace vector::native::unpack::art {

namespace {

using vector::native::ElfImage;
using vector::native::ElfSymbolCache;

// Resolve the first candidate mangled name that exists in libart. Names differ across
// Android versions (e.g. uint32 vs size_t length params), so pass a small candidate set
// just like external/lsplant .../art/runtime/dex_file.cxx does with its `|` fallbacks.
template <typename Fn>
Fn ResolveFirst(const ElfImage *art, std::initializer_list<const char *> candidates) {
    if (!art) return nullptr;
    for (const char *name : candidates) {
        if (auto *addr = art->getSymbAddress(name)) return reinterpret_cast<Fn>(addr);
    }
    return nullptr;
}

Internal g_internal;
std::once_flag g_once;

void DoResolve() {
    const ElfImage *art = ElfSymbolCache::GetArt();
    if (!art) {
        LOGW("[unpack] libart ElfImage unavailable; ART surface unresolved");
        return;
    }
    auto &I = g_internal;

    // TODO(P0): verify these mangled names on the target device's libart .dynsym before
    // trusting them (use stealth-poc/kpm/elf_syms.py). GetCodeItem / GetDexFile are
    // frequently INLINED -> may resolve null; then fall back to a struct-offset read of
    // ArtMethod.dex_code_item_offset_ / declaring-class -> dex_cache -> dex_file.
    I.art_method_get_code_item = ResolveFirst<const void *(*)(void *)>(
        art, {"_ZN3art9ArtMethod11GetCodeItemEv"});
    I.art_method_get_dex_file = ResolveFirst<const void *(*)(void *)>(
        art, {"_ZNK3art9ArtMethod10GetDexFileEv"});
    I.art_method_get_dex_method_index = ResolveFirst<uint32_t (*)(void *)>(
        art, {"_ZNK3art9ArtMethod17GetDexMethodIndexEv"});

    I.dex_file_begin = ResolveFirst<const uint8_t *(*)(const void *)>(
        art, {"_ZNK3art7DexFile5BeginEv"});
    I.dex_file_size = ResolveFirst<size_t (*)(const void *)>(
        art, {"_ZNK3art7DexFile4SizeEv"});

    I.class_linker_visit_classes = ResolveFirst<void (*)(void *, void *)>(
        art, {"_ZN3art11ClassLinker12VisitClassesEPNS_12ClassVisitorE"});

    // Force-compile driver — identical symbols to module.cpp ForceCompileMethod.
    I.runtime_instance = reinterpret_cast<void **>(
        art->getSymbAddress("_ZN3art7Runtime9instance_E"));
    I.runtime_get_jit = ResolveFirst<void *(*)(void *)>(
        art, {"_ZNK3art7Runtime6GetJitEv"});  // NOTE: often INLINED on recent ART -> null
    I.jit_enqueue_optimized_compilation = ResolveFirst<void (*)(void *, void *, void *)>(
        art, {"_ZN3art3jit3Jit27EnqueueOptimizedCompilationEPNS_9ArtMethodEPNS_6ThreadE"});

    // TODO(P0): entry_point_off is device-measured (+24 on the Pixel 6, per module.cpp).
    // Re-derive per device rather than hardcode (disasm an exported ArtMethod accessor,
    // or compute from sizeof fields). Left at the documented default for now.
    I.entry_point_off = 24;

    LOGI("[unpack] ART surface resolved: code_item={} dex_file={} visit_classes={} "
         "rt_inst={} get_jit={} enqueue={}",
         (void *)I.art_method_get_code_item, (void *)I.art_method_get_dex_file,
         (void *)I.class_linker_visit_classes, (void *)I.runtime_instance,
         (void *)I.runtime_get_jit, (void *)I.jit_enqueue_optimized_compilation);
}

}  // namespace

void *Internal::entry_point_of(void *art_method) const {
    if (!art_method) return nullptr;
    return *reinterpret_cast<void **>(reinterpret_cast<char *>(art_method) + entry_point_off);
}

bool Internal::ok_for_capture() const {
    return art_method_get_code_item && art_method_get_dex_file && dex_file_begin && dex_file_size;
}
bool Internal::ok_for_enumerate() const { return class_linker_visit_classes != nullptr; }
bool Internal::ok_for_forcecompile() const {
    return runtime_instance && *runtime_instance && jit_enqueue_optimized_compilation;
}

const Internal &Get() {
    std::call_once(g_once, DoResolve);
    return g_internal;
}

}  // namespace vector::native::unpack::art

#endif  // VECTOR_UNPACK_ENABLED
