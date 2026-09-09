# `native/src/kpm/` — vendored-code sync ledger

This directory holds Vector's **KPM traceless hook backend**, vendored from
[`stealth-core`](https://github.com/1013503897/stealth-core) `lib/`. Because the two repos are
independent gits, the copies **drift**. This file makes the drift *visible and syncable*: every
Vector-side delta is listed, and every upstream file's provenance is pinned.

> Provenance pin (update on each sync):
> - **stealth-core** base commit: `2a148bca2e4ef00ba1cdf5eb58122ec87c51b406` (upstream date 2026-09-01).
> - ⚠️ **The vendored `dbi.c` / `aarch64_decode.h` were taken from stealth-core's WORKING TREE**, which
>   at sync time carried the *uncommitted* finalization (the #6 128-bit SIMD literal fix,
>   `aarch64_decode.h`, `docs/bridge-protocol.md`, `lib/ssol.c`) sitting ATOP `2a148bc` — those files
>   are NOT yet in any commit. **Re-pin this SHA to the finalization commit once it lands**
>   (`git -C <stealth-core> rev-parse HEAD`) so the provenance is reproducible.
> - Date of this ledger's last sync: _<fill in on commit>_ (left as a placeholder — do not invent).

## Files and their relationship to upstream

| Vector file | Upstream `stealth-core/lib/` | Relationship |
|---|---|---|
| `dbi.h` | `dbi.h` | **verbatim** (identical modulo EOL) |
| `dbi.c` | `dbi.c` | **verbatim** (identical modulo EOL) — resynced this round (see below) |
| `aarch64_decode.h` | `aarch64_decode.h` | **verbatim** — newly vendored this round |
| `kpmhook.h` | `kpmhook.h` | superset (adds `kpm_ssol_*`, tri-state `kpm_inline_unhooker` doc) |
| `kpmhook.c` | `kpmhook.c` | **documented superset** — shared clone path in lock-step; deltas below |

Keep `dbi.c` / `dbi.h` / `aarch64_decode.h` **byte-identical** to upstream (verify with
`diff <(tr -d '\r' <a) <(tr -d '\r' <b)`); do not add Vector-only markers to them — the provenance
lives here so the verbatim property survives.

## Vector deltas in `kpmhook.c` (vs stealth-core `lib/kpmhook.c`)

1. **Process gating.** `KPM_STR` macro; `INJECTED_PACKAGE_UID` → `KPM_TARGET_UID`; `INJECTED_PACKAGE_NAME`
   compile gate; `g_proc_name` + `kpm_hook_set_process_name()` (the app name is unknown at hook time —
   `/proc/self/cmdline` is still `zygote64`), and `proc_is_target()` prefers that name over cmdline.
   Upstream gates purely on `/proc/self/cmdline` / props.
2. **SSOL client glue** (Vector-only): `kpm_ssol_hooker` / `kpm_ssol_unhooker`, `struct sov/srgn`,
   `find_srgn_locked` / `make_srgn_locked`, the `SSOL_*` table caps + VA bases, and the SSOL teardown
   loop inside `kpm_hook_shutdown`. This drives the KPM `ssolhook` / `ssolunhook` bridge commands.
   ⚠️ This is the **userspace bridge client**, a *different layer* from upstream `lib/ssol.c` (which is
   the offline SSOL *simulator* that runs kernel-side). There is **no upstream client file** to split
   this back into — so it deliberately stays inlined in `kpmhook.c`, sharing `g_lock` /
   `ensure_init_locked` / `bridge_cmd` / `reply_ok` with the clone path (splitting would force changing
   those from `static` to `extern`, a behavior-affecting change to the shared init/mutex).
3. **`kpm_hide_region()`** (Vector-only): maps-hide client (`hidergn`).
4. **`version` handshake client — ADVISORY-ONLY** (Vector-only): `CLIENT_BRIDGE_PROTO`, `bridge_kv`,
   `advise_bridge_version_locked`, called once from `ensure_init_locked`. See
   `stealth-core/docs/bridge-protocol.md`. It **only logs** (INFO for a pre-`version` KPM, ERROR for
   proto/capacity ABI drift) and **never** disables the KPM backend, sets `g_init_failed`, or changes
   a hook/fallback decision. This is a deliberate safety choice: falling back to Dobby is **fatal** on
   hardened anti-tamper targets (self-check → SIGKILL), so a new Vector running against an in-service KPM that
   predates the `version` command must keep working unchanged. ⚠️ compile-verified only — device-test
   the log line, but there is **no behavior to regress** (the hook path is identical with/without it).
5. **Tri-state `kpm_inline_unhooker`** (Vector-only): returns `-1` (not ours) / `0` (ours, teardown
   failed) / `1` (ok), consumed by `native_api.h::UnhookInline`. Upstream returns a plain `0/1`.
6. **Census scratch cap** `CENSUS_CLONE_CAP` (16384): upstream still sizes `g_clonebuf` at
   `CLONE_CAP` (6144), which under-sizes the 6× 128-bit-SIMD-literal worst case and silently RANGEd.
   *(This same under-size exists upstream — see "applicable upstream" below.)*

## This round: upstream fixes reviewed for applicability

| Upstream change (this stealth-core round) | Applies to Vector client? | Action |
|---|---|---|
| **#6 128-bit SIMD LDR-literal** materialization in `dbi.c` `insn_size` / `emit_one` | **Yes** — Vector's region clones run the same recompiler; a truncated 8-byte copy corrupts a `LDR Qt` clone | **Synced** (verbatim `dbi.c`). ⚠️ runtime behavior change → device-test |
| **`aarch64_decode.h`** decoder consolidation (was 3 drifting copies) | **Yes** — `dbi.c` now includes it | **Synced** (file added; `dbi.c` includes it) |
| `readable_extent` literal-pool bounding (`dbi_recompile_range` `lit_lo/lit_hi`) | Already present in Vector `kpmhook.c` (`readable_extent`, bounded reads) | **Already in sync** — no change |
| `do_ssolarm` leak helper (kernel `shpte.c`) | Userspace analog = "release freshly-made-but-unused region": clone path was the **bug #1** fixed this round; SSOL path already releases | **Fixed (clone path) / already present (SSOL)** |
| region `is_xtrap` gating; `hide_del` | **No** — kernel-side (`kpm/shpte.c`), not the userspace client | N/A (kernel) |
| SSOL simulator taps in `lib/ssol.c` | **No** — kernel-side simulator; Vector's SSOL is a bridge client only | N/A (kernel) |

Additional Vector-side fixes this round (not upstream syncs): **#1** region leak on bridge reject
(`kpm_inline_hooker` reject branch now releases a freshly-made region — the **same bug exists upstream
`lib/kpmhook.c` and was fixed there too this round**), plus the doc/robustness items (#P2/#P5/#P6/#P7/#10).

## How to sync an upstream fix

1. `git -C <stealth-core> log --oneline lib/` since the pinned SHA; read the diffs.
2. For **verbatim** files (`dbi.*`, `aarch64_decode.h`): copy the upstream file over, then
   `diff <(tr -d '\r' <vector) <(tr -d '\r' <upstream))` must be empty.
3. For **`kpmhook.c`**: apply the fix to the shared clone/region logic by hand, keeping the deltas
   above intact. Record any *new* delta in this table.
4. Bump the provenance pin (SHA + date) at the top.

## Second vendored/fork chain — LSPlant (`external/lsplant`)

Parallel to stealth-core, Vector carries a **second** vendored fork: the `external/lsplant` submodule
points at `1013503897/LSPlant.git`, checked out on branch **`vector-l2a`** (HEAD
`572f0d0cbbafea5378ca11ba8dab3376c6ae1de7` at time of writing). That branch carries the KPM Java-path
additions — `InitInfo.traceless_inline_hooker` (`traceless_inline_hooker` in `lsplant.hpp` /
`lsplant.cc`) — which is the LSPlant side that calls Vector's `kpm_ssol_hooker`. Remotes on the
submodule: `origin` (https, upstream fork) and `mine` (ssh, push). `.gitmodules` does **not** pin the
branch, so a fresh `submodule update` lands on the recorded commit; to move it, check out `vector-l2a`
and **rebase onto upstream LSPlant**, then update the submodule pointer. Treat `vector-l2a` as the
authoritative integration branch for the LSPlant↔KPM Java path.

## EOL

Both repos store these sources **LF** in-index. Vector's root `.gitattributes` (`* text=auto eol=lf`)
keeps the working tree LF too. stealth-core has no `.gitattributes`, so a Windows checkout may show its
`lib/dbi.c` working tree as CRLF — harmless for cross-repo `diff` if you strip CR (`tr -d '\r'`), and a
scoped `.gitattributes` was added on the stealth-core side to normalize it (run `git add --renormalize .`
there to apply to already-tracked files).
