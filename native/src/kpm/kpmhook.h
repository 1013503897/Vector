/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * libkpmhook: userspace glue that maps LSPlant's InitInfo inline-hook callbacks
 * onto the stealth KPM (shpte) via the no-superkey syscall bridge.
 *
 * kpm_inline_hooker(target, hooker) == LSPlant InlineHookFunType. It UXN-traps the
 * target's whole code page (multi-page `pghook` table), routes every instruction
 * on that page through a position-independent whole-page DBI clone (lib/dbi), and
 * overrides the target's entry -> hooker. The returned `backup` is the in-clone
 * faithful copy of the target -- call it to run the original. Several targets on
 * the SAME page share one trapped page / clone (the KPM appends overrides), which
 * is exactly what LSPlant needs (it inline-hooks ~20 libart funcs one at a time,
 * many sharing code pages).
 *
 * Prerequisite (privileged, done out-of-band once per boot by shctl + superkey):
 *     shctl <KEY> load shpte.kpm
 *     shctl <KEY> control shpte probe
 *     shctl <KEY> control shpte bridge
 * After that this library needs NO superkey -- it drives the KPM as the injected
 * agent (e.g. Vector's native layer) through personality(BRIDGE_MAGIC, ...).
 *
 * Boundary (Layer-1): the whole-page clone assumes the hooked function body fits
 * inside its page. Functions whose body spans a page boundary need multi-page
 * clones (tracked as future hardening); page-isolated targets are fine today.
 *
 * Build: link lib/dbi.c. Not for kernel use (plain userspace + libc + libdbi).
 */
#ifndef LIBKPMHOOK_H
#define LIBKPMHOOK_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Bypass the process gate (persist.kpmhook.target). For standalone/test callers
 * (e.g. tools/kpmhooktool) that run in their own dedicated process and have no Dobby
 * fallback -- NOT used by Vector, which relies on the property gate for safety. Call
 * before kpm_hook_init() / the first kpm_inline_hooker().
 */
void kpm_hook_force_enable(void);

/*
 * Rev1-(1): enable the ghost main-path. When on, every NEW region clone is hosted in
 * VMA-less kernel memory (KPM `pghookg`) instead of an anonymous RX mmap, so the
 * recompiled hook code is unreachable by /proc/maps + mincore enumeration (it stays
 * directly readable only if its VA is already known). Off by default -- the proven
 * userspace-clone path is unchanged until a caller opts in. Call before the first
 * kpm_inline_hooker(); affects regions created after the call. Requires the on-device
 * shpte KPM to be >= v0.6.2 (it understands `pghookg`); on an older KPM the pghookg
 * reply is not "ok", the hook returns NULL, and the caller falls back to Dobby.
 */
void kpm_hook_set_ghost(int on);

/*
 * Enable the kernel fs-hide for THIS process: register our tgid so the KPM spoofs its statfs
 * f_type (overlayfs -> erofs) and drops overlay/magisk lines from its /proc/self/mountinfo +
 * /proc/self/mounts -- defeats the "hidden overlayfs" mount detection. Reader-gated to our tgid
 * (root's own views stay truthful). Call once from postAppSpecialize. No-op on a pre-0.6.6 KPM.
 */
void kpm_hook_fshide_enable(void);

/*
 * Tell the KPM process gate the real package/process name. Vector calls this from
 * postAppSpecialize (where the app's nice_name is known) BEFORE LSPlant installs its
 * inline hooks -- at hook time /proc/self/cmdline is still "zygote64", so the backend
 * cannot identify the app on its own. Only the build's injection target then engages
 * the KPM (everything else stays on Dobby). Standalone test callers may skip this (the
 * gate falls back to /proc/self/cmdline). Call before kpm_hook_init() / the first hooker.
 */
void kpm_hook_set_process_name(const char *name);

/*
 * Probe the bridge and cache getpid(). Returns 0 if this process is gated-in AND the
 * bridge is live; <0 otherwise (gated out, or bridge not armed) -- in which case no
 * hook is attempted. Optional: kpm_inline_hooker() lazily runs this on first use.
 */
int kpm_hook_init(void);

/* Release every whole-page clone mapping. Call after all unhooks are done. */
void kpm_hook_shutdown(void);

/* LSPlant InitInfo.inline_hooker: returns the backup (call-original) pointer, or
 * NULL on failure. `target` is the function to hook, `hooker` the replacement. */
void *kpm_inline_hooker(void *target, void *hooker);

/* LSPlant InitInfo.inline_unhooker: `func` is the original target previously
 * passed to kpm_inline_hooker. Returns 1 on success, 0 on failure. */
int kpm_inline_unhooker(void *func);

/* LSPlant InitInfo.traceless_inline_hooker (Java methods only): SSOL-trap the cold
 * quick-compiled body `target` so a call routes to `hooker` and a call-original runs
 * the original via SSOL. Returns the unmapped backup VA, or NULL -> in-place fallback.
 * Distinct from kpm_inline_hooker: that clones hot libart-FUNCTION pages; SSOL on hot
 * .text would be a fault storm. See kpmhook.c for the split rationale. */
void *kpm_ssol_hooker(void *target, void *hooker);

/* Tear down one SSOL traceless hook installed by kpm_ssol_hooker. Returns 1/0. */
int kpm_ssol_unhooker(void *func);

/* ---- Phase B.2: R^X shadow-page backend for Java methods -------------------------------
 * Routes the method's quick-compiled entry CODE at its own address to `trampoline` by having
 * the KPM put a SHADOW copy of the page behind the same VA in an execute-only view, with a
 * 16-byte `movz/movk/br` patch over the first 4 instructions. Readers keep seeing the
 * original bytes (CRC-clean), the target's ArtMethod is never written, and -- unlike SSOL
 * (crash) and the region clone ("StackMap not found") -- the original code still runs at its
 * own PC, so ART's unwinder and StackMap lookups are untouched.
 *
 * `qc` is the quick-compiled entry, `trampoline` the replacement LSPlant generated. Returns
 * the per-method call-original STUB to install as the backup ArtMethod's entry, or NULL with
 * the exact reason in logcat (bridge off, page already patched, an unrelocatable instruction,
 * a literal load of the patched page, a trampoline above 48 bits, or a KPM reject) -- on NULL
 * the caller must fall back to its in-place path.
 *
 * B.4: the returned stub is in VMA-LESS memory (a KPM ghost page, published by `wxstub`) --
 * it does NOT appear in /proc/self/maps and needs no hiding. It is composed in an ordinary
 * non-executable RW buffer, so nothing this backend allocates is an anomalous executable
 * region. The trampoline pool page LSPlant minted is hidden by a targeted kpm_hide_region. */
void *kpm_wx_java_hooker(void *qc, void *trampoline);

/* Disarm one WX hook by its quick-compiled entry (the ArtMethod entry is never modified by
 * this backend, so `target->GetEntryPoint()` still yields it). Returns 1 if a shadow page was
 * released, 0 if this qc was never WX-hooked. */
int kpm_wx_java_unhooker(void *qc);

/* Raw arming primitive (Phase B.2 A): write a 16-byte patch into the SHADOW copy of `addr`'s
 * page in THIS process. Returns 0 on success. The bytes must not perform any memory access --
 * see the red lines in kpmhook.c. */
int kpm_wx_patch(uint64_t addr, const uint8_t patch[16]);

/* ---- SHARED-STUB ROUTER: the ONE patch per process that covers methods with no unique body ---
 *
 * The gap it closes: a Java method with no independent compiled body has an `entry_point_` of one
 * of ART's SHARED interpreter stubs (`nterp_entry_point`, `quick_to_interpreter_bridge`,
 * `quick_resolution_trampoline`). Patching such a stub per method is impossible -- every method
 * using it shares it -- and rewriting the method's ArtMethod entry is the detectable in-place
 * fallback. The fix is to patch the stub ONCE and dispatch inside it on `x0`.
 *
 * What this does: R^X-patch the first 16 bytes of ONE shared entry with `movz/movk/br <router>`,
 * and run a router that reads `x0` (the ArtMethod*, ART's quick ABI) and looks it up in an
 * N-ENTRY table. On a MISS it replays the four instructions the patch covered and continues at
 * `entry + 16`, touching nothing else (see the red lines in kpmhook.c for exactly which registers
 * the router is allowed to touch). On a HIT it does NOT resume the shared stub: starting from the
 * caller's quick-ABI register state it TAIL-CALLS the replacement through
 * `replacement->entry_point_from_quick_compiled_code_` -- the entry point ART itself installed for
 * that method -- so the stub is never handed an ArtMethod it was not entered for. That is the
 * difference between this router and a bare "x0 = replacement and carry on": `nterp_entry_point`
 * reads the method's flags and dex/code-item data out of `x0` under a contract the CALLER fixed at
 * its own compile time, so a swapped-in method ART would have entered another way (JNI trampoline,
 * interpreter bridge, JIT code) is misinterpreted by it (device-measured: `nterp_op_unused_e4`
 * SIGTRAP for a native ArtMethod, silent wrong results on a large app). The entry address is NEVER
 * hardcoded -- the caller resolves it from ART's symbols (Vector: `ElfSymbolCache`, the same
 * resolver LSPlant gets as `art_symbol_resolver`), and this API fails closed when it is null.
 *
 * WHAT THE CALLER MUST GUARANTEE (B.7.2's red lines; the enforcement lives in the caller):
 *   1. `backup` is a DIFFERENT ArtMethod from `target`, whose bytecode comes from `target`
 *      (`backup->CopyFrom(target)`). A call-original must NEVER call `target` -- `target`'s calls
 *      re-enter this same shared entry, match the table and recurse forever. Because `backup` is a
 *      distinct object, a call through it arrives with x0 = backup, which is a MISS here, so the
 *      original runs through the untouched interpreter path. That is the whole recursion argument.
 *   2. Only `nterp_entry_point` is armed. `nterp_with_clinit_entry_point` shares its page (0x40
 *      away, device-measured) and the R^X backend allows one patch per page, so a method whose qc
 *      is the with-clinit entry is refused by the caller and takes the in-place path.
 *   3. `target` is NEVER written: no SetEntryPoint, no SetNonCompilable, no BackupTo. The only
 *      ArtMethod this API needs is the one in the table.
 *   4. THE REPLACEMENT MUST NOT ITSELF BE A ROUTED TARGET. The hit path enters the replacement
 *      through its own entry point, which for an interpreted hook method IS this same shared
 *      entry; if the replacement were also a table target that second pass would be a hit and
 *      branch again, i.e. the table would contain a cycle and the router would loop without bound
 *      inside a global interpreter entry. `kpm_wx_router_add` refuses that (the shortest cycle is
 *      a chain of two, so refusing "the replacement is already a routed target" removes all of
 *      them), which is what makes the router's re-entry provably terminating.
 *   5. `quickcode_offset` -- the byte offset of `entry_point_from_quick_compiled_code_` inside an
 *      ArtMethod -- must come from ART's own layout (Vector: LSPlant's
 *      `ArtMethod::GetEntryPointOffset()`), never from a hardcoded constant, and is refused
 *      (fail-closed, logged) if it is not a plausible pointer-field offset.
 *
 * TABLE. N entries, capped at 64 (fail-closed: the caller falls back to in-place and logs why).
 * Publication is torn-free by construction: two immutable-once-published tables and one
 * `g_wxr_active` pointer; the writer only fills the INACTIVE table and flips the pointer with a
 * RELEASE store, and the router does one ACQUIRE load and reads the table that pointer names -- so
 * it observes either the old table or the new one and never a mixture. A generation counter would
 * have required the ROUTER to retry, and a retry loop in a global interpreter entry point is the
 * spin red line 5 forbids. The router itself holds no lock, issues no syscall and allocates
 * nothing.
 *
 * RUNTIME UPDATE BY PROPERTY (B.7.1 harness, kept for the mechanism test): a 1 Hz poll thread
 * installs `persist.kpmhook.routerpoc.am` / `.repl` as ONE EXTRA table entry -- both set = that
 * pair, both cleared = no harness entry, one set = refused and logged. It is kept SEPARATE from
 * the programmatic entries so a test publication can never clobber a live hook. Properties, not an
 * API call, because the app under test is a different APK from this module: every process can set
 * a property, nothing else crosses that boundary conveniently. A stale address from a previous
 * launch is a normal input, which is why wxr_plausible() filters it and every publication is
 * logged with the exact pair.
 *
 * Arms the router and installs {target_am, replacement_am} as the harness entry. Returns 0 on
 * success; <0 with the exact reason in logcat (bridge off, entry null/misaligned, an implausible
 * ArtMethod entry-point offset, a JIT page -- B.7.0's guard, kept -- an already-armed page, an
 * unrelocatable or same-page-literal covered instruction, a table half-filled, a router address
 * above 48 bits, a KPM reject) -- on failure NOTHING is armed and no state is left behind. Pass
 * 0/0 to arm with an EMPTY table, which is the pure MISS-path test.
 *
 * `target_am` may equal `replacement_am`: a hit then enters the method through ITS OWN entry
 * point, i.e. exactly what an unhooked call does, so behaviour is unchanged while `hits` still
 * proves the lookup and the redirect happened -- the safest way to exercise the hit branch before
 * a real replacement is available. (kpm_wx_router_add, the HOOK path, refuses that case: there it
 * would be a bug, not a test.) */
int kpm_wx_router_poc_arm(uint64_t entry, uint64_t target_am, uint64_t replacement_am,
                          uint32_t quickcode_offset);

/* B.7.2 HOOK PATH. Arm the router if it is not armed yet, then route one method onto it: a call
 * that reaches the shared `entry` with x0 == target_am is redirected to `replacement_am`, which
 * the router enters through `replacement_am`'s OWN entry point (`quickcode_offset` is where that
 * field lives in an ArtMethod). `target_am` is the method's ArtMethod*, `replacement_am` the
 * HOOK's ArtMethod* (whose own entry point runs the hook -- for LSPlant, the generated hook
 * method), and `entry` the shared stub resolved from ART's symbols by the caller (the eligibility
 * decision is the caller's: this function can only check that the entry agrees with the one
 * already armed).
 *
 * Every refusal is fail-closed and logged with its reason, and the caller falls back to its
 * in-place path: bridge off, a null/implausible entry, a null ArtMethod, target == replacement,
 * the replacement being itself a routed target (see red line 4 above), a different entry or
 * offset than the one already armed (one W^X patch per page, one arm per process), the table
 * being FULL (64), or any arm refusal. Adding an entry that is already present is an update, not
 * a duplicate. Returns 0 on success. */
int kpm_wx_router_add(uint64_t entry, uint64_t target_am, uint64_t replacement_am,
                      uint32_t quickcode_offset);

/* Stop routing `target_am` (the table entry is dropped; its behaviour reverts, because it no
 * longer matches). Returns 1 if the method WAS routed, 0 if it was not -- which is not an error:
 * the caller uses it to decide whether the router owned this method.
 *
 * The ARM IS LEFT IN PLACE, deliberately: the patch belongs to the shared entry, not to one
 * method, so releasing it would unhook every other routed method at once, and re-arming is
 * impossible (the shadow bytes are immutable). The residual cost is the router's per-call
 * dispatch, i.e. exactly the cost every non-routed interpreted call already pays. */
int kpm_wx_router_remove(uint64_t target_am);

/* Disarm: put the original PTE back for the armed shared entry (the R^X patch is released, so
 * the router becomes unreachable) and empty the table, programmatic entries included. Returns 1
 * if a patch was released, 0 if the router was not armed OR the KPM refused the release -- in
 * which case the patch is LEFT LIVE and the state is unchanged (fail closed: reporting success
 * while the router still runs would be a lie). The router's ghost page stays published either way
 * (a published ghost VA is burnt in the KPM by design -- see wx_stub_publish_locked). */
int kpm_wx_router_poc_disarm(void);

/* The table's shape, shared with the implementation so the stats struct below cannot drift out of
 * step with it. KPM_WXR_MAX_ENTRIES is the fail-closed cap on the number of METHODS one process
 * can route; the extra slot is the B.7.1 property harness's pair. */
#define KPM_WXR_MAX_ENTRIES 64
#define KPM_WXR_SLOT_COUNT (KPM_WXR_MAX_ENTRIES + 1)

/* Counter/state snapshot. Counters are plain lock-free read-modify-writes on 64-bit cells (the
 * router must never block or spin, red line 5), so under concurrent interpreted calls an
 * increment can be lost -- they are diagnostics, not accounting. */
struct kpm_wx_router_stats {
    uint64_t armed;       /* 1 = the shared entry currently carries the router patch */
    uint64_t entry;       /* the armed shared entry (nterp_entry_point) */
    uint64_t router;      /* the ghost router page VA (VMA-less) */
    uint64_t mode;        /* WX_MODE_FLIP (0) or WX_MODE_RX (1) */
    uint64_t self_reads;  /* 1 = the body reads its own page, which is why mode is RX */
    uint64_t target;      /* FIRST live entry's target (0 = empty table: pure miss path) */
    uint64_t replacement; /* FIRST live entry's replacement */
    uint64_t entries;     /* live table size: programmatic entries + the harness pair (0 or 1) */
    uint64_t routed;      /* programmatic entries (== entries minus the harness pair) */
    uint64_t added;       /* kpm_wx_router_add calls that installed a NEW entry (coverage) */
    uint64_t updated;     /* kpm_wx_router_add calls that updated an existing entry */
    uint64_t removed;     /* kpm_wx_router_remove calls that removed an entry */
    uint64_t refused_full;/* adds REFUSED because the 64-entry cap was reached (fail-closed) */
    uint64_t hits;        /* the call was redirected: the router entered `replacement` through
                           * the replacement's OWN entry point (never a resumed shared stub) */
    uint64_t misses;      /* nothing redirected: the shared stub ran as if unpatched */
    uint64_t publishes;   /* table updates after the initial arm (0 = still the arm-time table) */
    uint64_t polling;     /* 1 = the B.7.1 runtime harness thread is running */
    uint64_t x0_last;     /* the most recent x0 the router was entered with (diagnostic) */
    uint64_t slot_hits[KPM_WXR_SLOT_COUNT]; /* per-TABLE-POSITION hit counts (see the dump) */
};
int kpm_wx_router_poc_stats(struct kpm_wx_router_stats *out);

/* One logcat line with the same snapshot (the backend's usual observability channel). */
void kpm_wx_router_poc_dump(void);

/* Hide every UNNAMED EXECUTABLE region of this process from /proc/self/{maps,smaps} via the KPM's
 * mm-gated maps-hide -- LSPlant's trampoline pool (rwxp anon, minted by every DoHook), the KPM's
 * own region clones (r-xp anon), and ART's ~1.29MB in-memory-dex code region (which exists only
 * because the framework dex Vector loads is in memory, so it is our footprint too). Named anon
 * regions ([anon:jit-code-cache] etc.) are NOT touched. Gated process only; returns the number of
 * REGIONS hidden.
 *
 * B.4 -- ONE hide-set entry PER REGION. The KPM's filter matches an entry against a VMA's vm_start,
 * so registering a region's start page hides the whole region (the branch above it in maps_hide_vma
 * range-tests exactly that way). The old per-page loop spent 315 entries on the 1.29MB region alone
 * and filled MAX_HIDE=64 by itself, which is why the actual pools stayed visible; a typical run now
 * costs a handful of entries, so the arm path and the +5s backstop can both afford to call it.
 *
 * MUST be called with libkpmhook's internal lock released -- it calls kpm_hide_region(), which
 * takes that lock. Safe to call from the target's own hook path: no VA-scoped operation is issued. */
int kpm_hide_all_anon_exec(void);

#ifdef __cplusplus
}
#endif

#endif /* LIBKPMHOOK_H */
