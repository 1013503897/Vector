// choke_hook.cpp — see choke_hook.h. INERT until VECTOR_UNPACK_ENABLED.

#ifdef VECTOR_UNPACK_ENABLED

#include "unpack/choke_hook.h"

#include <common/logging.h>
#include <elf/elf_image.h>
#include <elf/symbol_cache.h>

#include "kpm/kpmhook.h"          // kpm_inline_hooker / kpm_inline_unhooker (traceless backend)
#include "unpack/art_internal.h"
#include "unpack/codeitem_sink.h"

namespace vector::native::unpack {

namespace {

CodeItemSink *g_sink = nullptr;
void *g_choke_target = nullptr;       // resolved choke fn (for unhook)
void *(*g_orig_invoke)(void *, void *, void *, uint32_t, void *, const char *) = nullptr;  // call-original

// Resolve the chosen choke function's code address in libart.
void *ResolveChoke(ChokePoint cp) {
    const auto *art = ElfSymbolCache::GetArt();
    if (!art) return nullptr;
    switch (cp) {
        case ChokePoint::kArtMethodInvoke:
            // TODO(P0): verify the mangled name on-device; ArtMethod::Invoke signature is
            // (Thread*, uint32_t* args, uint32_t args_size, JValue* result, const char* shorty).
            return art->getSymbAddress(
                "_ZN3art9ArtMethod6InvokeEPNS_6ThreadEPjjPNS_6JValueEPKc");
        case ChokePoint::kInterpreterBridge:
            return art->getSymbAddress("artInterpreterToInterpreterBridge");
        case ChokePoint::kExecute:
            // Discouraged (design §2/§4). Multi-page; needs a DBI correctness pass first.
            return art->getSymbAddress(
                "_ZN3art11interpreter7ExecuteEPNS_6ThreadERKNS_20CodeItemDataAccessorERNS_11ShadowFrameENS_6JValueEb");
        default:
            return nullptr;
    }
}

// The capture callback. Runs in place of the choke fn: read the (now-restored) CodeItem
// off the ArtMethod, hand it to the sink, then chain to the original.
// Shown for kArtMethodInvoke; bridge/Execute need their own trampoline signatures.
void *InvokeCaptureHook(void *method, void *thread, void *args, uint32_t args_size,
                        void *result, const char *shorty) {
    const auto &I = art::Get();
    if (g_sink && I.ok_for_capture() && method) {
        if (const void *dex = I.art_method_get_dex_file(method)) {
            const uint8_t *base = I.dex_file_begin(dex);
            size_t dsize = I.dex_file_size(dex);
            uint32_t midx = I.art_method_get_dex_method_index
                                ? I.art_method_get_dex_method_index(method)
                                : 0;
            const void *ci = I.art_method_get_code_item(method);
            uint32_t dex_id = g_sink->RegisterDex(base, dsize);
            // TODO(P0): compute CodeItem length (parse header: insns_size + tries/handlers).
            g_sink->Capture({dex_id, midx, ci, /*len=*/0});
        }
    }
    // call-original (g_orig_invoke = kpm_inline_hooker's in-clone backup, or Dobby backup).
    return g_orig_invoke
               ? g_orig_invoke(method, thread, args, args_size, result, shorty)
               : nullptr;
}

}  // namespace

bool InstallChokeHook(ChokePoint cp, bool stealth, CodeItemSink *sink) {
    g_sink = sink;
    void *target = ResolveChoke(cp);
    if (!target) {
        LOGW("[unpack] choke fn unresolved (cp={})", static_cast<int>(cp));
        return false;
    }
    g_choke_target = target;

    if (cp != ChokePoint::kArtMethodInvoke) {
        // TODO(P0): bridge/Execute trampolines have different signatures than InvokeCaptureHook.
        LOGW("[unpack] only kArtMethodInvoke trampoline implemented (P0)");
        return false;
    }

    if (stealth) {
        // Traceless: KPM region-clone-trap the choke fn's page; backup = in-clone copy.
        void *backup = kpm_inline_hooker(target, reinterpret_cast<void *>(&InvokeCaptureHook));
        if (!backup) {
            LOGW("[unpack] kpm_inline_hooker failed (gated out / no clean region / DBI bail)");
            return false;
        }
        g_orig_invoke = reinterpret_cast<decltype(g_orig_invoke)>(backup);
        LOGI("[unpack] stealth choke hook installed at {} (backup={})", target, backup);
    } else {
        // TODO(P0): plain Dobby inline hook for shells with no anti-dump self-check.
        LOGW("[unpack] non-stealth (Dobby) path not wired (P0 stub)");
        return false;
    }
    return true;
}

bool RemoveChokeHook() {
    if (!g_choke_target) return false;
    // TODO: distinguish stealth vs Dobby; for stealth:
    int ok = kpm_inline_unhooker(g_choke_target);
    g_choke_target = nullptr;
    g_orig_invoke = nullptr;
    g_sink = nullptr;
    return ok == 1;
}

}  // namespace vector::native::unpack

#endif  // VECTOR_UNPACK_ENABLED
