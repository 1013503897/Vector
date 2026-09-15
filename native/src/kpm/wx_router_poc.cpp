// SPDX-License-Identifier: GPL-2.0-or-later
//
// Phase B.7.1 POC + Phase B.7.2 wiring -- the userspace half of the shared-stub router: resolve
// ART's shared interpreter entry (nterp_entry_point) from ART's OWN symbols, use that value to
// decide which methods the router may take over, and hand the entry to the R^X backend to arm once.
//
// This file exists because the resolution has to go through the resolver LSPlant is already
// given -- `InitInfo::art_symbol_resolver` (module.cpp) is exactly
// `ElfSymbolCache::GetArt()->getSymbAddress`, i.e. Vector's libart.so symbol tables. The R^X
// arming machinery, by contrast, is plain C in kpmhook.c and cannot see that resolver. So the
// split is: resolve and DECIDE here (C++), arm and route there (C), and the arm fails closed when
// it is handed a value this file did not validate.
//
// TWO CLIENTS, ONE MECHANISM:
//   * B.7.1's POC (`persist.kpmhook.routerpoc=1`, WxRouterPocArmIfEnabled below) arms the router
//     with an EMPTY table or with a test pair from properties. That is the mechanism test and it
//     routes no method of any app.
//   * B.7.2's hook backend (`persist.kpmhook.router=1`, SharedRouterHook/SharedRouterUnhook at the
//     bottom) is the wired-in path: LSPlant asks it FIRST for every Java hook, and it takes over
//     exactly the methods whose qc IS nterp_entry_point -- the ones that used to end in the
//     detectable in-place ArtMethod swap.
// See PHASE-B7-1-ROUTER-POC.md and PHASE-B7-2-DOHOOK-WIRING.md.

#include <android/log.h>
#include <sys/system_properties.h>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "core/native_api.h"
#include "elf/elf_image.h"    // ElfImage's definition: symbol_cache.h only forward-declares it
#include "elf/symbol_cache.h"
#include "kpmhook.h"

namespace vector::native {

namespace {

constexpr const char *kTag = "kpmhook";

// Property names. Kept short because bionic caps a property NAME at 32 bytes
// (PROP_NAME_MAX) -- "persist.kpmhook.routerpoc.replacement" would be 35 and silently fail to
// set on the device, which is a miserable way to discover a naming mistake.
constexpr const char *kPropEnable = "persist.kpmhook.routerpoc";
constexpr const char *kPropTarget = "persist.kpmhook.routerpoc.am";
constexpr const char *kPropRepl = "persist.kpmhook.routerpoc.repl";

// AArch64 pointer authentication / TBI: the top byte of a signed code pointer holds the PAC
// (and the tag, under MTE). Masking it off is free and keeps a signed pointer from failing the
// plausibility checks below. Bits 55:0 are left alone -- every Android user VA fits there.
constexpr uint64_t kPointerMask = 0x00FFFFFFFFFFFFFFULL;

uint64_t ReadHexProperty(const char *name)
{
    char v[PROP_VALUE_MAX] = {0};
    if (__system_property_get(name, v) <= 0 || v[0] == '\0') return 0;
    // base 0: accepts 0x-prefixed hex (the form logcat prints) and decimal alike.
    return static_cast<uint64_t>(strtoull(v, nullptr, 0));
}

struct Mapping {
    uint64_t lo = 0;
    uint64_t hi = 0;
    bool exec = false;
    char path[256] = {0};
};

bool FindMapping(uint64_t va, Mapping *out)
{
    FILE *f = fopen("/proc/self/maps", "re");
    if (!f) return false;
    char line[512];
    bool found = false;
    while (fgets(line, sizeof line, f)) {
        unsigned long lo = 0, hi = 0;
        char perms[8] = {0}, path[256] = {0};
        int n = sscanf(line, "%lx-%lx %7s %*x %*x:%*x %*u %255[^\n]", &lo, &hi, perms, path);
        if (n < 2) continue;
        if (va < static_cast<uint64_t>(lo) || va >= static_cast<uint64_t>(hi)) continue;
        out->lo = lo;
        out->hi = hi;
        out->exec = (n >= 3 && perms[2] == 'x');
        if (n >= 4) snprintf(out->path, sizeof out->path, "%s", path);
        found = true;
        break;
    }
    fclose(f);
    return found;
}

// Every candidate is checked against reality before it is used: a resolver bug, a version skew
// or a mistyped symbol must not be able to arm the global interpreter entry with garbage. The
// two conditions that matter are `executable` and `inside libart.so` -- nterp is part of the
// runtime, so anything outside libart's executable segments is by definition not it. The rest
// is logged rather than tested, because it is what the operator needs to see to judge the
// resolution (the offset inside the mapping is the honest, version-agnostic form of "where").
bool ValidateEntry(const char *label, uint64_t entry, uint64_t *off_in_mapping)
{
    if (entry == 0) {
        __android_log_print(ANDROID_LOG_WARN, kTag, "[wxr] %s resolved to 0 -- not armed", label);
        return false;
    }
    if (entry >= (1ULL << 48) || (entry & 3) != 0) {
        __android_log_print(ANDROID_LOG_WARN, kTag,
                            "[wxr] %s resolved to 0x%lx: not a plausible ARM64 code address "
                            "(>48 bits or misaligned) -- not armed",
                            label, static_cast<unsigned long>(entry));
        return false;
    }
    Mapping m;
    if (!FindMapping(entry, &m)) {
        __android_log_print(ANDROID_LOG_WARN, kTag,
                            "[wxr] %s resolved to 0x%lx, which is in NO /proc/self/maps region "
                            "-- not armed",
                            label, static_cast<unsigned long>(entry));
        return false;
    }
    if (!m.exec) {
        __android_log_print(ANDROID_LOG_WARN, kTag,
                            "[wxr] %s resolved to 0x%lx, which maps %s -- NOT executable; not "
                            "armed",
                            label, static_cast<unsigned long>(entry),
                            m.path[0] ? m.path : "(anonymous)");
        return false;
    }
    if (strstr(m.path, "libart") == nullptr) {
        __android_log_print(ANDROID_LOG_WARN, kTag,
                            "[wxr] %s resolved to 0x%lx, which is executable but in [%s], not "
                            "libart.so -- nterp lives in the runtime, so this is not it; not "
                            "armed",
                            label, static_cast<unsigned long>(entry),
                            m.path[0] ? m.path : "(anonymous)");
        return false;
    }
    *off_in_mapping = entry - m.lo;
    __android_log_print(ANDROID_LOG_INFO, kTag,
                        "[wxr] %s = 0x%lx  (mapping 0x%lx+0x%lx, executable, %s)",
                        label, static_cast<unsigned long>(entry),
                        static_cast<unsigned long>(m.lo),
                        static_cast<unsigned long>(*off_in_mapping), m.path);
    return true;
}

// Read the 64-bit code pointer a data symbol holds. `NterpImpl` / `NterpWithClinitImpl` are the
// storage ART itself keeps the nterp implementation in, so this is a load, not a call -- the
// least invasive way to ask libart where nterp is.
bool ReadPointerSymbol(const char *mangled, const char *label, uint64_t *out)
{
    auto *sym = ElfSymbolCache::GetArt()->getSymbAddress(mangled);
    if (sym == nullptr) {
        __android_log_print(ANDROID_LOG_INFO, kTag, "[wxr] symbol not found: %s (%s)", mangled,
                            label);
        return false;
    }
    uint64_t v = static_cast<uint64_t>(*reinterpret_cast<const volatile uint64_t *>(sym));
    *out = v & kPointerMask;
    __android_log_print(ANDROID_LOG_INFO, kTag,
                        "[wxr] %s: symbol %s at %p holds 0x%lx (raw 0x%lx)", label, mangled,
                        sym, static_cast<unsigned long>(*out),
                        static_cast<unsigned long>(v));
    return true;
}

struct NterpEntry {
    uint64_t value = 0;
    uint64_t clinit = 0;       // NterpWithClinitImpl's value (0 = not resolvable)
    const char *how = "unresolved";
};

// Resolve ART's nterp entry. NO OFFSET IS HARDCODED -- the value comes from libart's own symbol
// tables on every path, and the fallback order is chosen so the least invasive source is tried
// first:
//   1. `OatQuickMethodHeader::NterpImpl` -- the data symbol ART stores the nterp implementation
//      in, i.e. exactly the value an interpreted method's entry_point_ holds. A load.
//   2. `interpreter::GetNterpEntryPoint()` -- a pure getter returning the same value, for builds
//      where the data symbol is absent. A call into libart, so it is the FALLBACK (rustFrida's
//      order is the reverse; a load cannot have side effects and a call can).
// `NterpWithClinitImpl` is resolved too, but ONLY to be logged: it is a different entry (the
// static-method variant), it usually shares nterp's page, and arming two entries on one page is
// not possible anyway (one WX patch per page). A caller that needs it is B.7.2's problem.
NterpEntry ResolveNterpEntry()
{
    NterpEntry r;
    uint64_t v = 0, off = 0, clinit = 0;

    if (ReadPointerSymbol("_ZN3art20OatQuickMethodHeader9NterpImplE",
                          "OatQuickMethodHeader::NterpImpl", &v) &&
        ValidateEntry("nterp_entry_point", v, &off)) {
        r.value = v;
        r.how = "OatQuickMethodHeader::NterpImpl (data symbol -> deref)";
    } else {
        // Fallback: call the getter. Only the getter's RESULT is used, and it is validated the
        // same way below -- so a wrong signature (a build where this symbol means something
        // else) cannot arm anything.
        auto *fp = ElfSymbolCache::GetArt()->getSymbAddress(
            "_ZN3art11interpreter18GetNterpEntryPointEv");
        if (fp != nullptr) {
            auto get_nterp = reinterpret_cast<const void *(*)()>(fp);
            v = reinterpret_cast<uint64_t>(get_nterp()) & kPointerMask;
            __android_log_print(ANDROID_LOG_INFO, kTag,
                                "[wxr] interpreter::GetNterpEntryPoint() at %p returned 0x%lx", fp,
                                static_cast<unsigned long>(v));
            if (ValidateEntry("nterp_entry_point", v, &off)) {
                r.value = v;
                r.how = "interpreter::GetNterpEntryPoint() (getter call)";
            }
        } else {
            __android_log_print(ANDROID_LOG_INFO, kTag,
                                "[wxr] symbol not found: _ZN3art11interpreter18GetNterpEntryPointEv");
        }
    }

    // NEVER armed (one W^X patch per page, and nterp already owns this page -- measured 0x40
    // apart), but B.7.2 needs its VALUE: a method whose qc is this entry must be recognised and
    // refused explicitly, with that reason in the log, rather than silently falling through as
    // "not nterp". Resolved from symbols like the main entry, never inferred.
    if (ReadPointerSymbol("_ZN3art20OatQuickMethodHeader19NterpWithClinitImplE",
                          "OatQuickMethodHeader::NterpWithClinitImpl", &clinit) &&
        ValidateEntry("nterp_with_clinit_entry_point", clinit, &off)) {
        r.clinit = clinit;
    }
    return r;
}

/* Resolve ONCE per process. Called from the hook path (every DoHook asks the router first) and by
 * the B.7.1 POC arm, so the resolution -- which reads /proc/self/maps three times and logs the
 * result -- happens on the first question and never again. Deliberately a plain flag rather than a
 * function-local static: this runs inside DoHook, under ScopedSuspendAll, and a C++ magic-static
 * guard is an extra (if tiny) futex/alloc surface there. A benign race on the hooking thread is
 * impossible (DoHook is serialized by suspend-all) and would in any case resolve the same values.
 */
NterpEntry g_router_entry;
int g_router_entry_state;  // 0 = unresolved, 1 = resolved (successfully or not)

const NterpEntry &EnsureRouterEntry()
{
    if (!g_router_entry_state) {
        g_router_entry_state = 1;
        g_router_entry = ResolveNterpEntry();
    }
    return g_router_entry;
}

}  // namespace

// Opt-in arm. A no-op unless `persist.kpmhook.routerpoc=1`, so the default build's behaviour is
// unchanged; the R^X backend refuses anyway when the bridge is off or this process is not the
// gated injection target.
//
//   persist.kpmhook.routerpoc       1        enable the POC
//   persist.kpmhook.routerpoc.am    <hex>    ArtMethod* to match (optional)
//   persist.kpmhook.routerpoc.repl  <hex>    ArtMethod* to hand over instead (optional)
//
// With neither ArtMethod set the router is armed with an EMPTY table: every interpreted call in
// the process then takes the miss path, which is precisely the red-line-4 test (behaviour must
// be byte-identical to the unpatched path). Set both to exercise the hit branch; setting them
// equal to each other makes the hit enter the method through its own entry point, i.e. exactly
// what an unhooked call does -- a hit with no behavioural risk at all, and the safest way to see
// `hits` move before a real replacement exists.
//
// `quickcode_offset` is where an ArtMethod keeps `entry_point_from_quick_compiled_code_`
// (LSPlant's ArtMethod::GetEntryPointOffset()). The router's hit path reads it to enter the
// replacement through ART's own entry for that method rather than resuming the shared nterp stub
// with x0 rewritten -- see the block comment in kpmhook.c. A 0 offset refuses the arm.
void WxRouterPocArmIfEnabled(uint32_t quickcode_offset)
{
    char v[PROP_VALUE_MAX] = {0};
    if (!kUseKpmBackend) return;
    if (__system_property_get(kPropEnable, v) <= 0 || v[0] != '1') return;

    uint64_t target = ReadHexProperty(kPropTarget);
    uint64_t repl = ReadHexProperty(kPropRepl);

    __android_log_print(ANDROID_LOG_INFO, kTag,
                        "[wxr] POC requested (persist.kpmhook.routerpoc=1): resolving ART's shared "
                        "interpreter entry from symbols, table target=%s replacement=%s",
                        target ? "set" : "empty", repl ? "set" : "empty");

    NterpEntry entry = EnsureRouterEntry();
    if (entry.value == 0) {
        // Fail closed: no arm, no state, and the reason is in logcat. Vector keeps working on
        // whatever backend it was using -- this POC never has a fallback of its own.
        __android_log_print(ANDROID_LOG_ERROR, kTag,
                            "[wxr] FAIL-CLOSED: could not resolve nterp_entry_point from ART's "
                            "symbols -- nothing armed. (Android 11 and older have no nterp.)");
        return;
    }
    __android_log_print(ANDROID_LOG_INFO, kTag, "[wxr] nterp_entry_point resolved via %s",
                        entry.how);

    if ((target == 0) != (repl == 0)) {
        __android_log_print(ANDROID_LOG_ERROR, kTag,
                            "[wxr] FAIL-CLOSED: %s is set but %s is not -- both or neither "
                            "(0/0 = arm with an empty table)",
                            target ? kPropTarget : kPropRepl,
                            target ? kPropRepl : kPropTarget);
        return;
    }

    int rc = kpm_wx_router_poc_arm(entry.value, target, repl, quickcode_offset);
    __android_log_print(rc == 0 ? ANDROID_LOG_INFO : ANDROID_LOG_ERROR, kTag,
                        "[wxr] arm %s (entry=0x%lx target=0x%lx replacement=0x%lx%s, "
                        "ArtMethod entry offset=0x%x)",
                        rc == 0 ? "OK" : "REFUSED", static_cast<unsigned long>(entry.value),
                        static_cast<unsigned long>(target), static_cast<unsigned long>(repl),
                        target ? "" : ", empty table = pure miss path",
                        static_cast<unsigned>(quickcode_offset));
    kpm_wx_router_poc_dump();
}

// =============================================================================================
// PHASE B.7.2 -- the shared-stub router as a HOOK BACKEND (the userspace half of the wiring)
// =============================================================================================
//
// WHAT CHANGED FROM B.7.1. B.7.1 proved the mechanism: patch ART's shared interpreter entry once,
// redirect the call per method. What it did NOT do was route a method through it, so a Java method
// with no compiled body of its own still ended in LSPlant's in-place `target->SetEntryPoint(...)`
// swap, which is the detectable half of the coverage gap. This file now supplies the two InitInfo
// callbacks that close it: SharedRouterHook decides eligibility and installs the table entry,
// SharedRouterUnhook takes it back out.
//
// WHAT A HIT DOES (and why it is not an `x0` swap). The router redirects a routed call by entering
// the HOOK through the hook's OWN entry point -- `*(void **)((char *)hook +
// GetArtMethodEntryPointOffset())`, which is the entry ART itself installed for that method, be it
// nterp, the interpreter bridge, JIT code or a JNI trampoline. It does NOT put the hook into `x0`
// and resume the shared nterp stub: that stub reads the method's access flags and its dex/code-item
// data out of `x0` under a contract the CALLER fixed at its own compile time, so a hook ART would
// have entered another way is misinterpreted by it (device-measured: `nterp_op_unused_e4` SIGTRAP
// for a native ArtMethod, and silently wrong results for a routed framework method in a large app --
// while the miss path stayed clean). `quickcode_offset` (LSPlant's ArtMethod::GetEntryPointOffset)
// is what lets the router take the hook's own entry; see the block comment in kpmhook.c.
//
// ELIGIBILITY IS A SYMBOL COMPARISON, NOT A HEURISTIC (red line 5). The method's quick-compiled
// entry must EQUAL the `nterp_entry_point` resolved above from ART's own symbol tables. The
// tempting shortcut -- "does the code_size word before the entry look sane" -- is NOT used here:
// it infers from the shape of memory where this path can just ask ART, and it mis-answers in both
// directions (B.7.3 later retired it from the module's own classifier for rejecting real
// boot-framework.oat bodies). Being wrong towards "eligible" here means arming the process-global
// interpreter entry with a table that then never matches anything (harmless) or, worse, matching
// something it should not.
//
// THE CALL-ORIGINAL INVARIANT (red line 2, the recursion trap). DoHook gets `hook` and `target` as
// ArtMethod* values; the value returned here is installed as the BACKUP ArtMethod's entry. It is
// nterp itself, and that is safe for exactly one reason, which the caller must preserve:
//
//     the backup is a DISTINCT ArtMethod (DoHook does backup->CopyFrom(target)), so a call-original
//     arrives at the shared entry with x0 = backup != target -> a table MISS -> the original
//     bytecode runs through the untouched interpreter path.
//
// If a call-original ever went to `target` instead, that call would re-enter the router, match
// `target`, redirect to the hook and run the hook again -- unbounded recursion. The router needs no
// bypass flag for this: the identity check IS the bypass, and it only works because the backup is
// a different object. That is why returning `target` (or anything derived from it) here would be a
// bug even though it is the same address as nterp for an interpreted method.
//
// `target` IS NEVER WRITTEN on this path -- no SetEntryPoint, no SetNonCompilable, no BackupTo.
// The router's whole write set is: its own ghost page of code, its own .bss table, and the
// ArtMethod* values inside that table.

constexpr const char *kPropRouter = "persist.kpmhook.router";

// Eligibility + install. See the block comment above and InitInfo::shared_router_hooker.
void *SharedRouterHook(void *target, void *hook, void *qc, uint32_t quickcode_offset)
{
    char v[PROP_VALUE_MAX] = {0};
    if (!kUseKpmBackend) return nullptr;
    // Ships OFF, like every other KPM backend here: this one arms a GLOBAL entry point, so it must
    // never engage without an explicit opt-in.
    if (__system_property_get(kPropRouter, v) <= 0 || v[0] != '1') return nullptr;

    if (target == nullptr || hook == nullptr || qc == nullptr) {
        __android_log_print(ANDROID_LOG_WARN, kTag,
                            "[router] REFUSED -> in-place fallback. reason: null target/hook/qc "
                            "(target=%p hook=%p qc=%p)",
                            target, hook, qc);
        return nullptr;
    }
    if (quickcode_offset == 0) {
        // The hit path must enter the hook through the hook's OWN entry point (see the block
        // comment in kpmhook.c): without the ArtMethod entry-point offset the router cannot read
        // it, and the only alternative -- handing the shared nterp stub a rewritten x0 -- is the
        // defect this path was fixed for. Fail closed rather than route unsoundly.
        __android_log_print(ANDROID_LOG_ERROR, kTag,
                            "[router] REFUSED target=%p -> in-place fallback. reason: the ArtMethod "
                            "entry-point offset is 0 (LSPlant has not resolved its layout, or Init "
                            "has not run). The router needs it to enter the hook through ART's own "
                            "entry for it; routing without it would feed the shared nterp stub a "
                            "method it was never entered for",
                            target);
        return nullptr;
    }

    const NterpEntry &e = EnsureRouterEntry();
    if (e.value == 0) {
        // Fail closed, and say which of the two causes it is: no nterp at all (Android <= 10), or a
        // resolution that could not be trusted.
        __android_log_print(ANDROID_LOG_ERROR, kTag,
                            "[router] REFUSED target=%p -> in-place fallback. reason: "
                            "nterp_entry_point could not be resolved from ART's symbols, so no "
                            "method can be identified as a shared-stub method (Android 11 and "
                            "older have no nterp at all)",
                            target);
        return nullptr;
    }

    const uint64_t q = static_cast<uint64_t>(reinterpret_cast<uintptr_t>(qc));
    if (e.clinit != 0 && q == e.clinit) {
        // The known, deliberate coverage hole (spec §1.2): same page as nterp_entry_point, one W^X
        // patch per page, and the page is already spent on nterp_entry_point.
        __android_log_print(ANDROID_LOG_WARN, kTag,
                            "[router] REFUSED target=%p qc=0x%lx -> in-place fallback. reason: the "
                            "method's entry is nterp_with_clinit_entry_point (0x%lx), ART's "
                            "static-method variant, which shares nterp_entry_point's page "
                            "(measured 0x40 apart). The R^X backend allows ONE patch per page and "
                            "that page is already armed for nterp_entry_point, so this method "
                            "cannot be routed without a one-page-many-patches mechanism.",
                            target, static_cast<unsigned long>(q),
                            static_cast<unsigned long>(e.clinit));
        return nullptr;
    }
    if (q != e.value) {
        // Not a shared-stub method: it has its own compiled body (or points at some other stub), so
        // the R^X / clone backends are the right ones to ask. Logged at INFO because this is the
        // NORMAL answer for most hooks, and the reason the router is tried first is precisely that
        // it is the only backend that can cover the case below.
        __android_log_print(ANDROID_LOG_INFO, kTag,
                            "[router] not eligible: target=%p qc=0x%lx != nterp_entry_point=0x%lx "
                            "(own body / another stub) -> next backend",
                            target, static_cast<unsigned long>(q),
                            static_cast<unsigned long>(e.value));
        return nullptr;
    }

    // qc IS nterp_entry_point: an interpreted method with no body of its own -- exactly the case
    // that used to end in the in-place ArtMethod swap. `hook` (not `target`) is what a hit runs,
    // entered through `hook`'s own entry point; the target's ArtMethod is only ever COMPARED.
    //
    // This one read is the whole reason the hit path takes the hook's own entry instead of resuming
    // the shared stub with x0 rewritten, so it is logged every time: if HOOK_ENTRY is NOT the
    // shared stub, then a hit that resumed nterp with x0 = hook would be running nterp on a method
    // ART deliberately routes elsewhere (a JNI trampoline, the interpreter bridge, JIT code) --
    // i.e. exactly the case that mis-executes. Read through the same offset the router uses, from
    // the ArtMethod LSPlant is handing over, purely as a diagnostic.
    const uint64_t hook_entry =
        static_cast<uint64_t>(*reinterpret_cast<const volatile uint64_t *>(
            reinterpret_cast<uintptr_t>(hook) + quickcode_offset)) & kPointerMask;
    __android_log_print(ANDROID_LOG_INFO, kTag,
                        "[router] target=%p hook=%p HOOK_ENTRY=0x%lx %s nterp_entry_point=0x%lx "
                        "(a hit ENTERS the hook through HOOK_ENTRY; resuming the shared stub with "
                        "x0 = hook instead would hand nterp a method whose own entry is %s)",
                        target, hook, static_cast<unsigned long>(hook_entry),
                        hook_entry == e.value ? "==" : "!=",
                        static_cast<unsigned long>(e.value),
                        hook_entry == e.value ? "the same stub (the two paths agree)"
                                              : "somewhere else (the two paths do NOT agree -- "
                                                "this is the case the old x0 swap got wrong)");
    if (kpm_wx_router_add(e.value, static_cast<uint64_t>(reinterpret_cast<uintptr_t>(target)),
                          static_cast<uint64_t>(reinterpret_cast<uintptr_t>(hook)),
                          quickcode_offset) != 0) {
        __android_log_print(ANDROID_LOG_WARN, kTag,
                            "[router] ROUTE FAILED target=%p (qc == nterp_entry_point 0x%lx) -> "
                            "in-place fallback; the exact reason is the [wxr] line above (table "
                            "full / bridge off / arm refused)",
                            target, static_cast<unsigned long>(e.value));
        return nullptr;
    }
    __android_log_print(ANDROID_LOG_INFO, kTag,
                        "[router] ROUTED target=%p (interpreted: qc == nterp_entry_point 0x%lx) -> "
                        "hook %p, entered on a hit at [hook + 0x%x] (hook's OWN entry point -- the "
                        "entry ART itself would use for it, so nterp is never handed a method it "
                        "was not entered for). call-original entry = the shared nterp stub itself "
                        "(0x%lx), which is correct only because the backup is a distinct ArtMethod: "
                        "a call through it arrives with x0 = backup != target, misses the table and "
                        "runs the ORIGINAL bytecode. target is NOT written.",
                        target, static_cast<unsigned long>(e.value), hook,
                        static_cast<unsigned>(quickcode_offset),
                        static_cast<unsigned long>(e.value));
    return reinterpret_cast<void *>(static_cast<uintptr_t>(e.value));
}

// True if this target was routed by the router (and is now unrouted). False means "the router does
// not own this method", which is what DoUnHook uses to decide whether the per-method R^X un-hooker
// should be asked instead.
bool SharedRouterUnhook(void *target)
{
    if (target == nullptr) return false;
    const int was = kpm_wx_router_remove(static_cast<uint64_t>(reinterpret_cast<uintptr_t>(target)));
    if (was) {
        __android_log_print(ANDROID_LOG_INFO, kTag,
                            "[router] UNROUTED target=%p: its calls run the original code again "
                            "(the shared entry stays armed for the other routed methods)",
                            target);
        return true;
    }
    return false;
}

// True if `qc` is one of ART's shared interpreter entries -- i.e. this address belongs to the
// router, not to a per-method body. The module uses it to keep the R^X un-hooker away from the
// router's patch: a routed method's ArtMethod entry IS the shared stub, so an unhook keyed on the
// entry would otherwise find the router's shadow slot and release it, disarming every routed
// method at once. (kpm_wx_java_unhooker refuses that too; this is the same guard at the call site.)
// WHICH of ART's two shared interpreter entries is `qc`? 0 = neither, 1 = nterp_entry_point,
// 2 = nterp_with_clinit_entry_point. Both candidates are RESOLVED SYMBOL VALUES (red line 4 of
// B.7.3); nothing here is inferred from the shape of memory. Split from
// WxRouterOwnsSharedStub because the B.7.3 site classifier must NAME which entry it saw: they share
// a page but not a decision -- nterp_entry_point is the router's own entry, while
// nterp_with_clinit_entry_point is a refusal (one W^X patch per page).
int WxRouterSharedStubKind(void *qc)
{
    if (qc == nullptr) return 0;
    const NterpEntry &e = EnsureRouterEntry();
    const uint64_t q = static_cast<uint64_t>(reinterpret_cast<uintptr_t>(qc));
    if (e.value != 0 && q == e.value) return 1;
    if (e.clinit != 0 && q == e.clinit) return 2;
    return 0;
}

bool WxRouterOwnsSharedStub(void *qc) { return WxRouterSharedStubKind(qc) != 0; }

}  // namespace vector::native
