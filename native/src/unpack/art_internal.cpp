// art_internal.cpp — lazy resolution of the libart surface (see art_internal.h).
//
// INERT until VECTOR_UNPACK_ENABLED is defined (the native CMake GLOBs src/*.cpp, so
// this file is compiled; the guard keeps it an empty TU so it cannot affect the build).

#ifdef VECTOR_UNPACK_ENABLED

#include "unpack/art_internal.h"

#include <jni.h>

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <utility>
#include <vector>

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

    // Increment-1 dex discovery: GetClassDef (resolvable) + FindClass (for ClassLinker* capture).
    I.mirror_class_get_class_def = ResolveFirst<const void *(*)(void *)>(
        art, {"_ZN3art6mirror5Class11GetClassDefEv"});
    // FindClass(Thread*, const char* descriptor, size_t hash, Handle<ClassLoader>) — the
    // by-descriptor entry (fires on every named class load). NOTE the `m` (size_t hash) param;
    // the no-hash variant does not exist on this build.
    I.class_linker_find_class = art->getSymbAddress(
        "_ZN3art11ClassLinker9FindClassEPNS_6ThreadEPKcmNS_6HandleINS_6mirror11ClassLoaderEEE");

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
    LOGI("[unpack] dexfind surface: get_class_def={} find_class={}",
         (void *)I.mirror_class_get_class_def, (void *)I.class_linker_find_class);
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
bool Internal::ok_for_dexfind() const {
    return class_linker_visit_classes && mirror_class_get_class_def && class_linker_find_class;
}

const Internal &Get() {
    std::call_once(g_once, DoResolve);
    return g_internal;
}

Internal &GetMutable() {
    std::call_once(g_once, DoResolve);
    return g_internal;
}

namespace {

// A tiny readable-range table from /proc/self/maps so calibration can probe candidate pointers
// without risking a SIGSEGV (no signal machinery; just a bounds check). Built once per call.
struct ReadMap {
    std::vector<std::pair<uintptr_t, uintptr_t>> r;  // sorted [start,end) readable ranges
    void load() {
        FILE *f = fopen("/proc/self/maps", "re");
        if (!f) return;
        char line[512];
        while (fgets(line, sizeof(line), f)) {
            uintptr_t s = 0, e = 0;
            char perms[5] = {0};
            if (sscanf(line, "%lx-%lx %4s", &s, &e, perms) != 3) continue;
            if (perms[0] == 'r') r.emplace_back(s, e);
        }
        fclose(f);
    }
    bool ok(uintptr_t a, size_t n) const {
        for (auto &p : r)
            if (a >= p.first && a + n <= p.second) return true;
        return false;
    }
};

}  // namespace

// Resolve the java.lang.reflect.Executable.artMethod field once. Reading it (GetLongField) yields
// the RAW ArtMethod* regardless of the runtime's jniIdType — unlike env->FromReflectedMethod, which
// returns a swapable/indexed id when the app is debuggable (e.g. dpt-packed) and gave a bogus
// art_method_size=2. This is lsplant's method.
static jfieldID ArtMethodField(JNIEnv *env) {
    static jfieldID f = nullptr;
    if (f) return f;
    jclass exec = env->FindClass("java/lang/reflect/Executable");
    if (!exec) { env->ExceptionClear(); return nullptr; }
    f = env->GetFieldID(exec, "artMethod", "J");
    if (!f) env->ExceptionClear();
    return f;
}

static void *ArtMethodFromReflected(JNIEnv *env, jobject m) {
    jfieldID f = ArtMethodField(env);
    if (f) return reinterpret_cast<void *>(static_cast<uintptr_t>(env->GetLongField(m, f)));
    return reinterpret_cast<void *>(env->FromReflectedMethod(m));  // pre-O fallback
}

bool CalibrateArtMethodSize(void *jni_env) {
    Internal &I = GetMutable();
    if (I.art_method_size) return true;
    JNIEnv *env = reinterpret_cast<JNIEnv *>(jni_env);
    if (!env) return false;

    jclass throwable = env->FindClass("java/lang/Throwable");
    jclass clazz = env->FindClass("java/lang/Class");
    if (!throwable || !clazz) { env->ExceptionClear(); return false; }
    jmethodID get_ctors = env->GetMethodID(clazz, "getDeclaredConstructors",
                                           "()[Ljava/lang/reflect/Constructor;");
    if (!get_ctors) { env->ExceptionClear(); return false; }
    jobjectArray ctors = (jobjectArray)env->CallObjectMethod(throwable, get_ctors);
    if (env->ExceptionCheck() || !ctors) { env->ExceptionClear(); return false; }
    if (env->GetArrayLength(ctors) < 2) return false;

    jobject c0 = env->GetObjectArrayElement(ctors, 0);
    jobject c1 = env->GetObjectArrayElement(ctors, 1);
    void *m0 = ArtMethodFromReflected(env, c0);
    void *m1 = ArtMethodFromReflected(env, c1);
    if (!m0 || !m1) return false;
    ptrdiff_t d = reinterpret_cast<char *>(m1) - reinterpret_cast<char *>(m0);
    if (d < 0) d = -d;
    if (d < 16 || d > 128) {
        LOGW("[unpack] art_method_size implausible ({}); abandoning method enum", (long)d);
        return false;
    }
    I.art_method_size = (size_t)d;
    LOGI("[unpack] calibrated art_method_size={} (entry_point_off stays {})", I.art_method_size,
         I.entry_point_off);
    return true;
}

bool CalibrateClassMethods(void *sample_klass) {
    Internal &I = GetMutable();
    if (I.class_methods_off) return true;
    if (!I.art_method_size || !sample_klass) return false;

    ReadMap rm;
    rm.load();
    const uintptr_t k = reinterpret_cast<uintptr_t>(sample_klass);
    const uint32_t kref = (uint32_t)k;  // compressed object ref (heap is low-4GB)

    // Scan the Class object after its 8-byte object header for a u64 that points at a
    // LengthPrefixedArray<ArtMethod> whose element-0 declaring_class_ == this class.
    for (size_t off = 8; off <= 0x160; off += 4) {
        if (!rm.ok(k + off, 8)) continue;
        uint64_t mptr = *reinterpret_cast<uint64_t *>(k + off);
        if (mptr < 0x1000 || (mptr & 7)) continue;
        if (!rm.ok((uintptr_t)mptr, 4)) continue;
        uint32_t size = *reinterpret_cast<uint32_t *>((uintptr_t)mptr);
        if (size < 1 || size > 20000) continue;
        for (size_t doff : {(size_t)4, (size_t)8}) {
            uintptr_t m0 = (uintptr_t)mptr + doff;
            if (!rm.ok(m0 + I.art_method_declaring_class_off, 4)) continue;
            uint32_t dc = *reinterpret_cast<uint32_t *>(m0 + I.art_method_declaring_class_off);
            if (dc == kref) {
                I.class_methods_off = off;
                I.class_methods_data_off = doff;
                LOGI("[unpack] calibrated class_methods_off={} data_off={} (n_methods={})", off,
                     doff, size);
                return true;
            }
        }
    }
    LOGW("[unpack] CalibrateClassMethods: no methods_ offset matched for sample {}", sample_klass);
    return false;
}

bool CalibrateForMethodEnum(void *jni_env) {
    Internal &I = GetMutable();
    if (I.methods_calibrated()) return true;
    if (!CalibrateArtMethodSize(jni_env)) return false;

    JNIEnv *env = reinterpret_cast<JNIEnv *>(jni_env);
    // Derive a stable sample mirror::Class*: the declaring class of String.length(). String is a
    // boot class (non-moving), so its Class* is stable. FromReflectedMethod returns the raw
    // ArtMethod* regardless of the jniIdType config; declaring_class_ at +0 is its (compressed)
    // class ref, zero-extended into a low-4GB pointer.
    jclass sc = env->FindClass("java/lang/String");
    if (!sc) { env->ExceptionClear(); return false; }
    jmethodID lm = env->GetMethodID(sc, "length", "()I");
    if (!lm) { env->ExceptionClear(); return false; }
    jobject refm = env->ToReflectedMethod(sc, lm, JNI_FALSE);
    if (!refm) { env->ExceptionClear(); return false; }
    void *am = ArtMethodFromReflected(env, refm);  // raw ArtMethod* via the artMethod field
    if (reinterpret_cast<uintptr_t>(am) < 0x10000) return false;
    uint32_t dcref = *reinterpret_cast<uint32_t *>(reinterpret_cast<uintptr_t>(am) +
                                                   I.art_method_declaring_class_off);
    void *str_class = reinterpret_cast<void *>(static_cast<uintptr_t>(dcref));
    return CalibrateClassMethods(str_class);
}

}  // namespace vector::native::unpack::art

#endif  // VECTOR_UNPACK_ENABLED
