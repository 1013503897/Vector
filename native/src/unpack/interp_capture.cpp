// interp_capture.cpp — see interp_capture.h. INERT until VECTOR_UNPACK_ENABLED.

#ifdef VECTOR_UNPACK_ENABLED

#include "unpack/interp_capture.h"

#include <dobby.h>
#include <unistd.h>

#include <atomic>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <unordered_set>
#include <vector>

#include <common/logging.h>

#include "unpack/art_internal.h"
#include "unpack/codeitem_sink.h"

namespace vector::native::unpack {

namespace {

// art::interpreter::Execute(Thread* self, const CodeItemDataAccessor& accessor,
//                           ShadowFrame& shadow_frame, JValue result_register,
//                           bool stay_in_interpreter, bool from_deoptimize) -> JValue
// AArch64 AAPCS: x0=self, x1=&accessor, x2=&shadow_frame, x3=result_register (JValue, an 8-byte
// union, by value), w4/w5 = the bools; returns JValue (8 bytes) in x0. uint64_t models the 8-byte
// JValue in/out exactly.
using ExecuteFn = uint64_t (*)(void *self, const void *accessor, void *shadow_frame,
                               uint64_t result_register, bool stay_in_interpreter,
                               bool from_deoptimize);

ExecuteFn g_orig_execute = nullptr;
const art::Internal *g_I = nullptr;
std::atomic<bool> g_capturing{false};

// Capture state (guarded by g_mu). Dedup by ArtMethod* (stable LinearAlloc pointer, unique/method).
std::mutex g_mu;
std::unordered_set<void *> g_seen;
struct Rec {
    const void *cd;     // owning class's dex::ClassDef* (locates the dex region for the sink)
    uint32_t midx;      // dex_method_index
    uint32_t off;       // offset into g_buf
    uint32_t len;       // CodeItem length
};
std::vector<Rec> g_recs;
std::vector<uint8_t> g_buf;

// CodeItemDataAccessor layout (CodeItemInstructionAccessor base + 4 u16):
//   +0  uint32_t insns_size_in_code_units_
//   +8  const uint16_t* insns_
//   +16 uint16_t registers_size_ ; +18 ins_size_ ; +20 outs_size_ ; +22 tries_size_
inline uint32_t AccInsnsSize(const void *a) {
    return *reinterpret_cast<const uint32_t *>(reinterpret_cast<const uint8_t *>(a));
}
inline const uint16_t *AccInsns(const void *a) {
    return *reinterpret_cast<const uint16_t *const *>(reinterpret_cast<const uint8_t *>(a) + 8);
}
inline uint16_t AccU16(const void *a, size_t off) {
    return *reinterpret_cast<const uint16_t *>(reinterpret_cast<const uint8_t *>(a) + off);
}

// Synthesize a standard CodeItem (16-byte header + insns) into `out` from the LIVE accessor.
// Reads only the insns region — exactly what ART is about to execute, hence guaranteed mapped — so
// there's no insns-16 probe, no /proc/self/maps snapshot, and no per-call signal guard (Execute is
// hot + multi-threaded, so a signal guard would be unsafe/expensive anyway). tries is forced to 0:
// the try_items/handlers trailer sits PAST the insns region (possibly unmapped if the shell only
// restored insns), and dropping it still yields a self-consistent CodeItem that jadx decodes — we
// keep the method body, lose only exception-handler metadata (a known limitation; refine later).
// Returns the appended length, or 0 on implausible input (caller rolls back).
size_t BuildCodeItem(const void *acc, std::vector<uint8_t> &out) {
    uint32_t insns_size = AccInsnsSize(acc);
    const uint16_t *insns = AccInsns(acc);
    if (!insns || insns_size == 0 || insns_size > (1u << 20)) return 0;
    uint16_t regs = AccU16(acc, 16), ins = AccU16(acc, 18), outs = AccU16(acc, 20);

    size_t start = out.size();
    auto put16 = [&](uint16_t v) {
        out.push_back((uint8_t)(v & 0xff));
        out.push_back((uint8_t)(v >> 8));
    };
    auto put32 = [&](uint32_t v) {
        for (int i = 0; i < 4; i++) out.push_back((uint8_t)((v >> (8 * i)) & 0xff));
    };
    put16(regs);
    put16(ins);
    put16(outs);
    put16(0);          // tries_size = 0
    put32(0);          // debug_info_off
    put32(insns_size);
    const uint8_t *ip = reinterpret_cast<const uint8_t *>(insns);
    out.insert(out.end(), ip, ip + (size_t)insns_size * 2);
    return out.size() - start;
}

uint64_t ExecuteHook(void *self, const void *accessor, void *shadow_frame, uint64_t result_register,
                     bool stay_in_interpreter, bool from_deoptimize) {
    if (g_capturing.load(std::memory_order_relaxed) && accessor && shadow_frame && g_I) {
        // ShadowFrame.method_ -> the ArtMethod being interpreted.
        void *method = *reinterpret_cast<void **>(reinterpret_cast<uint8_t *>(shadow_frame) +
                                                  g_I->shadow_frame_method_off);
        if (method) {
            bool fresh;
            {
                std::lock_guard<std::mutex> lk(g_mu);
                fresh = g_seen.insert(method).second;
            }
            if (fresh) {
                uint32_t midx = *reinterpret_cast<uint32_t *>(reinterpret_cast<uint8_t *>(method) +
                                                             g_I->art_method_dex_index_off);
                uint32_t dcref = *reinterpret_cast<uint32_t *>(reinterpret_cast<uint8_t *>(method) +
                                                              g_I->art_method_declaring_class_off);
                void *klass = reinterpret_cast<void *>((uintptr_t)dcref);
                // GetClassDef is a const accessor; we're on a runnable app thread mid-interpret
                // (mutator lock held), so calling it here is valid — it's what the interpreter does.
                const void *cd = (klass && g_I->mirror_class_get_class_def)
                                     ? g_I->mirror_class_get_class_def(klass)
                                     : nullptr;
                if (cd) {
                    std::lock_guard<std::mutex> lk(g_mu);
                    uint32_t off = (uint32_t)g_buf.size();
                    size_t len = BuildCodeItem(accessor, g_buf);
                    if (len > 0)
                        g_recs.push_back({cd, midx, off, (uint32_t)len});
                    else
                        g_buf.resize(off);  // roll back the partial append
                }
            }
        }
    }
    return g_orig_execute(self, accessor, shadow_frame, result_register, stay_in_interpreter,
                          from_deoptimize);
}

}  // namespace

size_t CaptureInterpreted(CodeItemSink *sink, int window_ms) {
    if (!sink) return 0;
    const auto &I = art::Get();
    if (!I.ok_for_interp_capture()) {
        LOGW("[unpack] interp: surface unresolved (execute={} get_class_def={})",
             (void *)I.interpreter_execute, (void *)I.mirror_class_get_class_def);
        return 0;
    }
    g_I = &I;
    g_seen.clear();
    g_recs.clear();
    g_buf.clear();
    g_buf.reserve(1 << 22);   // 4 MB of CodeItem bytes
    g_recs.reserve(1 << 16);

    if (DobbyHook(I.interpreter_execute, reinterpret_cast<dobby_dummy_func_t>(&ExecuteHook),
                  reinterpret_cast<dobby_dummy_func_t *>(&g_orig_execute)) != 0) {
        LOGW("[unpack] interp: DobbyHook(Execute) failed @ {}", I.interpreter_execute);
        g_I = nullptr;
        return 0;
    }
    LOGI("[unpack] interp: Execute hooked @ {}; capturing for {}ms", I.interpreter_execute,
         window_ms);
    g_capturing.store(true, std::memory_order_relaxed);
    for (int waited = 0; waited < window_ms; waited += 200) usleep(200 * 1000);
    g_capturing.store(false, std::memory_order_relaxed);
    usleep(100 * 1000);  // let in-flight hook bodies drain

    // Do NOT DobbyDestroy here. Execute is the hot, every-thread switch-interpreter core; unpatching
    // it while app threads are running inside the trampoline hangs the worker (DobbyDestroy spins).
    // With g_capturing=false the hook is already a near-zero-cost pass-through (one relaxed atomic
    // load -> tail-call orig), so leaving it installed for the process's lifetime is harmless — and
    // far safer than a live unhook of the interpreter.

    size_t n;
    {
        std::lock_guard<std::mutex> lk(g_mu);
        n = g_recs.size();
        static std::vector<CodeItemSink::MethodCapture> mc;
        mc.clear();
        mc.reserve(g_recs.size());
        const uint8_t *base = g_buf.data();
        for (const Rec &r : g_recs) mc.push_back({r.cd, r.midx, base + r.off, r.len});
        sink->DumpMethodCaptures(mc.data(), mc.size());
    }
    LOGI("[unpack] interp: captured {} distinct method CodeItem(s)", n);
    g_I = nullptr;
    return n;
}

}  // namespace vector::native::unpack

#endif  // VECTOR_UNPACK_ENABLED
