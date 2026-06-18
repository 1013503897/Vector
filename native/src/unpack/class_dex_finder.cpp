// class_dex_finder.cpp — see class_dex_finder.h. INERT until VECTOR_UNPACK_ENABLED.

#ifdef VECTOR_UNPACK_ENABLED

#include "unpack/class_dex_finder.h"

#include <dobby.h>
#include <jni.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <atomic>
#include <csetjmp>
#include <csignal>
#include <cstring>
#include <vector>

#include <common/logging.h>

#include "unpack/active_load.h"  // ActiveLoadAllClasses (increment-2d)
#include "unpack/art_internal.h"
#include "unpack/codeitem_sink.h"
#include "unpack/dex_layout.h"  // CodeItemLength

namespace vector::native::unpack {

namespace {

// ---- thread-scoped fault guard for the GetCodeItem trigger ------------------------------
// VisitClasses visits classes in EVERY load state, incl. ones not yet linked (null dex_cache);
// ArtMethod::GetCodeItem on such a method null-derefs (crash at +56, fault 0x3d). We can't cheaply
// pre-filter without the class-status offset, so each GetCodeItem runs under a per-call SIGSEGV/
// SIGBUS guard: a fault on OUR trigger thread siglongjmp's back and we skip that method; a fault on
// any other thread (or outside the trigger window) chains to the app's/Yidun's handler untouched.
sigjmp_buf g_tg_jmp;
volatile sig_atomic_t g_tg_active = 0;
pid_t g_tg_tid = 0;
struct sigaction g_tg_old_segv, g_tg_old_bus;
bool g_tg_installed = false;

inline pid_t tg_cur_tid() { return (pid_t)syscall(SYS_gettid); }

void tg_fault_handler(int sig, siginfo_t *info, void *uctx) {
    if (g_tg_active && tg_cur_tid() == g_tg_tid) siglongjmp(g_tg_jmp, 1);
    struct sigaction *old = (sig == SIGBUS) ? &g_tg_old_bus : &g_tg_old_segv;
    if (old->sa_flags & SA_SIGINFO) {
        if (old->sa_sigaction) old->sa_sigaction(sig, info, uctx);
    } else if (old->sa_handler == SIG_DFL || old->sa_handler == SIG_IGN) {
        signal(sig, SIG_DFL);
        raise(sig);
    } else if (old->sa_handler) {
        old->sa_handler(sig);
    }
}

void tg_install() {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = tg_fault_handler;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGSEGV, &sa, &g_tg_old_segv);
    sigaction(SIGBUS, &sa, &g_tg_old_bus);
    g_tg_tid = tg_cur_tid();
    g_tg_installed = true;
}

void tg_remove() {
    if (!g_tg_installed) return;
    sigaction(SIGSEGV, &g_tg_old_segv, nullptr);
    sigaction(SIGBUS, &g_tg_old_bus, nullptr);
    g_tg_installed = false;
}

// ---- ClassVisitor ABI shim (Itanium C++ ABI) --------------------------------------------
// art::ClassVisitor = { virtual ~ClassVisitor(); virtual bool operator()(ObjPtr<Class>); }.
// Its vtable is { [0]=~D1, [1]=~D0, [2]=operator() }; the object is just a vptr. ART calls
// vptr[2](visitor, klass). ObjPtr<mirror::Class> is a raw pointer in release ART (object-ptr
// poisoning is OFF on production builds) so `klass` arrives as a plain mirror::Class*.
struct VisitorVtable {
    void *dtor_complete;  // [0] — never called by VisitClasses (it borrows the visitor)
    void *dtor_deleting;  // [1]
    bool (*call)(void *self, void *klass);  // [2] — operator()
};

// One enumerated method + the dex::ClassDef* of its owning class (locates the dex region for
// increment-2b capture). ArtMethod* live in LinearAlloc (GC-stable); cd points into the dex.
struct MethodRef {
    void *method;
    const void *cd;
};

struct Visitor {
    const VisitorVtable *vptr;
    std::vector<const void *> *defs;
    std::vector<MethodRef> *methods;  // increment-2: collected (method, classdef) (null if off)
    const art::Internal *I;
};

void VisitorDtorNoop(void * /*self*/) {}

// Collect a class's ArtMethods (with the owning classdef) into `out`. Reads only LinearAlloc, so
// the pointers stay valid after the mutator lock is released -> the heavy GetCodeItem trigger can
// run later on this same runnable hook thread.
void CollectMethods(const art::Internal *I, void *klass, const void *cd, std::vector<MethodRef> *out) {
    if (!I->methods_calibrated()) return;
    uint64_t mptr = *reinterpret_cast<uint64_t *>(reinterpret_cast<uintptr_t>(klass) +
                                                  I->class_methods_off);
    if (mptr < 0x1000 || (mptr & 7)) return;  // null/garbage methods_ (array/primitive classes)
    uint32_t n = *reinterpret_cast<uint32_t *>((uintptr_t)mptr);
    if (n == 0 || n > 20000) return;          // sanity cap (mis-calibration guard)
    uintptr_t arr = (uintptr_t)mptr + I->class_methods_data_off;
    for (uint32_t i = 0; i < n; i++)
        out->push_back({reinterpret_cast<void *>(arr + i * I->art_method_size), cd});
}

bool VisitorCall(void *self, void *klass) {
    auto *v = reinterpret_cast<Visitor *>(self);
    if (klass && v->I->mirror_class_get_class_def) {
        // GetClassDef is a const accessor (reads Class fields + the dex class_defs); safe under
        // the shared mutator lock VisitClasses holds. Returns a pointer INTO the live dex.
        const void *cd = v->I->mirror_class_get_class_def(klass);
        if (cd) v->defs->push_back(cd);
        if (v->methods && cd) CollectMethods(v->I, klass, cd, v->methods);
    }
    return true;  // keep visiting
}

const VisitorVtable g_vtable = {
    reinterpret_cast<void *>(&VisitorDtorNoop),
    reinterpret_cast<void *>(&VisitorDtorNoop),
    &VisitorCall,
};

// ---- transient ClassLinker::FindClass hook (captures ClassLinker* + a runnable thread) ----
// Signature on this libart: mirror::Class* FindClass(ClassLinker* thiz, Thread* self,
// const char* descriptor, size_t hash, Handle<ClassLoader> loader). arg0 = the ClassLinker* we
// need; the rest are passed through untouched.
using FindClassFn = void *(*)(void *thiz, void *self, const char *desc, size_t hash, void *loader);
FindClassFn g_orig_find_class = nullptr;
std::atomic<bool> g_enum_started{false};
std::atomic<bool> g_enum_done{false};
// increment-2b: a restored CodeItem, copied to g_capbuf at [off, off+len). The bytes are copied
// the instant GetCodeItem returns because a side-cache shell (dpt) recycles the restored CodeItem.
struct CapRec {
    const void *cd;
    uint32_t midx;
    uint32_t off;
    uint32_t len;
};

std::vector<const void *> *g_defs = nullptr;       // owned by FindAndDumpClassDexes
std::vector<MethodRef> *g_methods = nullptr;       // increment-2: (method, classdef) (or null)
std::vector<uint8_t> *g_capbuf = nullptr;          // increment-2b: concatenated CodeItem bytes
std::vector<CapRec> *g_caprecs = nullptr;          // increment-2b: (cd, idx, off, len)
const art::Internal *g_I = nullptr;
std::atomic<size_t> g_triggered{0};           // methods whose CodeItem materialized
std::atomic<size_t> g_tg_skipped{0};          // methods skipped (GetCodeItem faulted)

void *FindClassHook(void *thiz, void *self, const char *desc, size_t hash, void *loader) {
    // First call only: run the enumeration HERE. FindClass is REQUIRES_SHARED(mutator_lock_),
    // so this thread is RUNNABLE with the shared mutator lock held (VisitClasses needs it) and
    // classlinker_classes_lock_ is still free at hook entry (orig acquires it later). thiz is
    // the ClassLinker* `this`.
    if (!g_enum_started.exchange(true)) {
        if (g_I && g_I->class_linker_visit_classes && g_defs) {
            Visitor v{&g_vtable, g_defs, g_methods, g_I};
            g_I->class_linker_visit_classes(thiz, &v);

            // increment-2 trigger — run GetCodeItem RIGHT HERE, still on this runnable thread,
            // AFTER VisitClasses released classlinker_classes_lock_ (so an extraction shell's
            // restore can load/lock without deadlocking). GetCodeItem is
            // REQUIRES_SHARED(mutator_lock_) — must NOT run on the (non-runnable) worker thread,
            // which faulted. ArtMethod* + the dex stay put: we still hold the shared mutator lock,
            // so the compacting GC pause can't move anything mid-hook.
            if (g_methods && g_I->art_method_get_code_item) {
                size_t got = 0, skipped = 0;
                static uint8_t tmp[65536];  // staging copy so a faulting read can't corrupt capbuf
                tg_install();
                for (const MethodRef &mr : *g_methods) {
                    bool have = false;
                    uint32_t clen = 0, cmidx = 0;
                    if (sigsetjmp(g_tg_jmp, 1) == 0) {
                        g_tg_active = 1;
                        const void *ci = g_I->art_method_get_code_item(mr.method);
                        if (ci) {
                            got++;
                            if (g_capbuf) {  // increment-2b: copy the CodeItem bytes RIGHT NOW
                                const uint8_t *p = reinterpret_cast<const uint8_t *>(ci);
                                size_t len = dex::CodeItemLength(p);   // under this fault guard
                                if (len > 0 && len <= sizeof(tmp)) {
                                    memcpy(tmp, p, len);               // faulting read -> longjmp
                                    cmidx = *reinterpret_cast<uint32_t *>(
                                        reinterpret_cast<uintptr_t>(mr.method) +
                                        g_I->art_method_dex_index_off);
                                    clen = (uint32_t)len;
                                    have = true;
                                }
                            }
                        }
                    } else {
                        skipped++;  // GetCodeItem/read faulted (unlinked class / cdex) -> skip
                    }
                    g_tg_active = 0;
                    if (have) {  // append from the safe staging buffer (no live read here)
                        uint32_t off = (uint32_t)g_capbuf->size();
                        g_capbuf->insert(g_capbuf->end(), tmp, tmp + clen);
                        g_caprecs->push_back({mr.cd, cmidx, off, clen});
                    }
                }
                tg_remove();
                g_triggered.store(got);
                g_tg_skipped.store(skipped);
            }
        }
        g_enum_done.store(true);
    }
    return g_orig_find_class(thiz, self, desc, hash, loader);
}

}  // namespace

size_t FindAndDumpClassDexes(CodeItemSink *sink, void *jni_env, int wait_ms, bool trigger,
                             bool active_load) {
    if (!sink) return 0;
    const auto &I = art::Get();
    if (!I.ok_for_dexfind()) {
        LOGW("[unpack] dexfind: ART surface unresolved (visit={} classdef={} findclass={})",
             (void *)I.class_linker_visit_classes, (void *)I.mirror_class_get_class_def,
             (void *)I.class_linker_find_class);
        return 0;
    }
    if (trigger && !I.methods_calibrated()) {
        LOGW("[unpack] dexfind: trigger requested but ArtMethod ABI not calibrated; "
             "falling back to dump-only");
        trigger = false;
    }

    static std::vector<const void *> defs;   // static: outlives any in-flight hook call
    static std::vector<MethodRef> methods;
    static std::vector<uint8_t> capbuf;
    static std::vector<CapRec> caprecs;
    defs.clear();
    defs.reserve(8192);
    methods.clear();
    capbuf.clear();
    caprecs.clear();
    if (trigger) {
        methods.reserve(1 << 18);
        caprecs.reserve(1 << 18);
        capbuf.reserve(1 << 22);  // 4 MB of CodeItem bytes
    }
    g_defs = &defs;
    g_methods = trigger ? &methods : nullptr;
    g_capbuf = trigger ? &capbuf : nullptr;
    g_caprecs = trigger ? &caprecs : nullptr;
    g_I = &I;
    g_triggered.store(0);
    g_tg_skipped.store(0);
    g_enum_started.store(false);
    g_enum_done.store(false);

    // Let the app load its own classes before enumerating — VisitClasses only sees LOADED classes,
    // so for a small/idle app an immediate enumeration catches mostly shell+framework. A short
    // pre-delay materially improves coverage; harmless for big apps that load fast. (Full coverage
    // for cold methods needs active class-loading — increment-2c.)
    int pre_ms = 6000;
    for (int w = 0; w < pre_ms; w += 200) usleep(200 * 1000);

    if (DobbyHook(I.class_linker_find_class,
                  reinterpret_cast<dobby_dummy_func_t>(&FindClassHook),
                  reinterpret_cast<dobby_dummy_func_t *>(&g_orig_find_class)) != 0) {
        LOGW("[unpack] dexfind: DobbyHook(FindClass) failed @ {}", I.class_linker_find_class);
        g_defs = nullptr;
        g_I = nullptr;
        return 0;
    }
    LOGI("[unpack] dexfind: FindClass hooked @ {}; self-triggering", I.class_linker_find_class);

    // SELF-TRIGGER: call JNI FindClass from this worker -> routes through ClassLinker::FindClass
    // (our hook), which fires the enumeration. JNI FindClass transitions this attached thread to
    // RUNNABLE (shared mutator lock held), so VisitClasses + GetCodeItem run in a valid state. This
    // does NOT depend on the app loading a class after we hook (an idle/small app loads none), and
    // captures every class loaded by now (after the pre-delay above).
    if (jni_env) {
        JNIEnv *e = reinterpret_cast<JNIEnv *>(jni_env);
        jclass c = e->FindClass("java/lang/Object");
        if (e->ExceptionCheck()) e->ExceptionClear();
        (void)c;
    }
    int waited = 0;
    while (!g_enum_done.load() && waited < wait_ms) {  // fallback wait if self-trigger didn't fire
        usleep(10000);
        waited += 10;
    }
    // Leave a short grace so any in-flight hook invocation exits before we unpatch.
    usleep(20000);
    DobbyDestroy(I.class_linker_find_class);

    if (!g_enum_done.load()) {
        LOGW("[unpack] dexfind: enumeration did not fire within {}ms", wait_ms);
        g_defs = nullptr;
        g_I = nullptr;
        return 0;
    }
    LOGI("[unpack] dexfind: enumerated {} class-def(s), {} method(s); triggered {} CodeItem(s), "
         "{} skipped(faulted)",
         defs.size(), methods.size(), g_triggered.load(), g_tg_skipped.load());

    // increment-2d: force-load every class of the app dex(es) so a per-class extraction shell
    // restores ALL CodeItems in place (incl. classes the app never reached), THEN dump.
    if (active_load && jni_env) {
        size_t loaded = ActiveLoadAllClasses(jni_env, defs.data(), defs.size());
        LOGI("[unpack] dexfind: active-loaded {} class(es) before dump", loaded);
    }

    size_t before = sink->dex_count();
    sink->DumpRegionsForPointers(defs.data(), defs.size());  // single maps snapshot + dedup
    size_t dumped = sink->dex_count() - before;
    LOGI("[unpack] dexfind: {} new region(s) dumped from {} class-defs", dumped, defs.size());

    // increment-2b: write the restored CodeItems (side-cache shells like dpt) for the offline
    // splicer to graft into the structure-only dexes just dumped. Bytes are the safe copies in
    // capbuf; build the MethodCapture view (pointers stable now that capbuf is fully grown).
    if (trigger && !caprecs.empty()) {
        static std::vector<CodeItemSink::MethodCapture> mc;
        mc.clear();
        mc.reserve(caprecs.size());
        const uint8_t *cbase = capbuf.data();
        for (const CapRec &r : caprecs)
            mc.push_back({r.cd, r.midx, cbase + r.off, r.len});
        sink->DumpMethodCaptures(mc.data(), mc.size());
    }

    g_defs = nullptr;
    g_methods = nullptr;
    g_capbuf = nullptr;
    g_caprecs = nullptr;
    g_I = nullptr;
    return dumped;
}

}  // namespace vector::native::unpack

#endif  // VECTOR_UNPACK_ENABLED
