// choke_hook.cpp — see choke_hook.h. INERT until VECTOR_UNPACK_ENABLED.

#ifdef VECTOR_UNPACK_ENABLED

#include "unpack/choke_hook.h"

#include <dobby.h>

#include <common/logging.h>
#include <elf/elf_image.h>
#include <elf/symbol_cache.h>

#include "kpm/kpmhook.h"          // kpm_inline_hooker / kpm_inline_unhooker (traceless backend)
#include "unpack/codeitem_sink.h"

namespace vector::native::unpack {

namespace {

using vector::native::ElfSymbolCache;

CodeItemSink *g_sink = nullptr;
void *g_choke_target = nullptr;       // resolved choke fn (for unhook)
bool g_stealth = false;               // which backend installed the hook (for RemoveChokeHook)

// ---- kArtMethodGetCodeItem (P0 default) -------------------------------------------------
// const dex::CodeItem* ArtMethod::GetCodeItem(ArtMethod* this)
using GetCodeItemFn = const void *(*)(void *);
GetCodeItemFn g_orig_get_code_item = nullptr;

const void *GetCodeItemHook(void *method) {
    const void *ci = g_orig_get_code_item ? g_orig_get_code_item(method) : nullptr;
    // ci is the (restored) CodeItem pointer, inside the dex data section. Hand it to the
    // sink, which recovers + dumps the whole dex once (range-deduped). Cheap on the hot path.
    if (g_sink && ci) g_sink->ObserveCodeItem(ci);
    return ci;
}

// ---- kArtMethodInvoke (P0-design, kept) -------------------------------------------------
using InvokeFn = void *(*)(void *, void *, void *, uint32_t, void *, const char *);
InvokeFn g_orig_invoke = nullptr;

void *InvokeHook(void *method, void *thread, void *args, uint32_t args_size, void *result,
                 const char *shorty) {
    // P0-design will capture the per-method CodeItem here (needs the offset walks); for now
    // mirror the GetCodeItem observation so Invoke is a usable alternate choke too.
    if (g_sink && method) {
        // No resolvable GetCodeItem call here without a method->codeitem accessor; the
        // GetCodeItem choke is the supported P0 path. Left minimal on purpose.
    }
    return g_orig_invoke
               ? g_orig_invoke(method, thread, args, args_size, result, shorty)
               : nullptr;
}

// Resolve the chosen choke function's code address in libart (.dynsym ∪ .gnu_debugdata).
void *ResolveChoke(ChokePoint cp) {
    const auto *art = ElfSymbolCache::GetArt();
    if (!art) return nullptr;
    switch (cp) {
        case ChokePoint::kArtMethodGetCodeItem:
            // Verified present in this device's MiniDebugInfo @0x49706c.
            return art->getSymbAddress("_ZN3art9ArtMethod11GetCodeItemEv");
        case ChokePoint::kArtMethodInvoke:
            return art->getSymbAddress(
                "_ZN3art9ArtMethod6InvokeEPNS_6ThreadEPjjPNS_6JValueEPKc");
        case ChokePoint::kInterpreterBridge:
            return art->getSymbAddress("artInterpreterToInterpreterBridge");
        case ChokePoint::kExecute:
            return art->getSymbAddress(
                "_ZN3art11interpreter7ExecuteEPNS_6ThreadERKNS_20CodeItemDataAccessorERNS_11ShadowFrameENS_6JValueEb");
        default:
            return nullptr;
    }
}

// Install `hook` over `target`, capturing the call-original pointer into *orig_out.
// stealth=true -> traceless KPM region-clone; stealth=false -> plain Dobby inline hook.
bool InstallBackend(void *target, void *hook, void **orig_out, bool stealth) {
    if (stealth) {
        void *backup = kpm_inline_hooker(target, hook);
        if (!backup) {
            LOGW("[unpack] kpm_inline_hooker failed (gated out / no clean region / DBI bail)");
            return false;
        }
        *orig_out = backup;
        LOGI("[unpack] stealth choke hook @ {} (backup={})", target, backup);
        return true;
    }
    if (DobbyHook(target, reinterpret_cast<dobby_dummy_func_t>(hook),
                  reinterpret_cast<dobby_dummy_func_t *>(orig_out)) != 0) {
        LOGW("[unpack] DobbyHook failed @ {}", target);
        return false;
    }
    LOGI("[unpack] dobby choke hook @ {} (orig={})", target, *orig_out);
    return true;
}

}  // namespace

bool InstallChokeHook(ChokePoint cp, bool stealth, CodeItemSink *sink) {
    g_sink = sink;
    g_stealth = stealth;
    void *target = ResolveChoke(cp);
    if (!target) {
        LOGW("[unpack] choke fn unresolved (cp={})", static_cast<int>(cp));
        return false;
    }
    g_choke_target = target;

    switch (cp) {
        case ChokePoint::kArtMethodGetCodeItem:
            return InstallBackend(target, reinterpret_cast<void *>(&GetCodeItemHook),
                                  reinterpret_cast<void **>(&g_orig_get_code_item), stealth);
        case ChokePoint::kArtMethodInvoke:
            return InstallBackend(target, reinterpret_cast<void *>(&InvokeHook),
                                  reinterpret_cast<void **>(&g_orig_invoke), stealth);
        default:
            LOGW("[unpack] only GetCodeItem/Invoke trampolines implemented (P0); cp={}",
                 static_cast<int>(cp));
            g_choke_target = nullptr;
            return false;
    }
}

bool RemoveChokeHook() {
    if (!g_choke_target) return false;
    bool ok;
    if (g_stealth) {
        ok = kpm_inline_unhooker(g_choke_target) == 1;
    } else {
        ok = DobbyDestroy(g_choke_target) == 0;
    }
    g_choke_target = nullptr;
    g_orig_get_code_item = nullptr;
    g_orig_invoke = nullptr;
    g_sink = nullptr;
    return ok;
}

}  // namespace vector::native::unpack

#endif  // VECTOR_UNPACK_ENABLED
