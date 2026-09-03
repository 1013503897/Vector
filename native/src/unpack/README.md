# native/src/unpack — stealth unpacker (INERT scaffold)

Skeleton for the traceless DEX / extraction-shell unpacker. Design spec:
`../../../../stealth-poc/docs/unpacker-design.md` (sibling repo). Builds on the same
primitives as M-C: `ElfSymbolCache` (symbol resolution), `kpm_inline_hooker`
(kpm/kpmhook.h, traceless hook), and the post-init worker pattern of
`zygisk/src/main/cpp/module.cpp` `RunTracelessConvert` (module.cpp:307).

## Status: ACTIVE (default OFF at runtime)

`native/CMakeLists.txt` now defines `VECTOR_UNPACK_ENABLED`, and `module.cpp` calls
`vector::native::unpack::StartIfEnabled(...)` post-init, so the unpacker IS compiled and wired.
Every `.cpp` body is still wrapped in `#ifdef VECTOR_UNPACK_ENABLED` (flip the define off to
excise it to empty translation units). At **runtime** it is a no-op unless
`persist.kpmhook.unpack=1` AND the process is the `persist.kpmhook.target` app — see
"Runtime props" below.

## File map

| File | Role | Design §  |
|---|---|---|
| `unpacker.h/.cpp` | public entry `StartIfEnabled()`, prop-gated config, post-init worker orchestration | §3, §6 |
| `choke_hook.h/.cpp` | choke-point selection + install (kpm_inline_hooker / inline) + capture callback | §2 |
| `method_enumerator.h/.cpp` | `ClassLinker::VisitClasses` enumeration + Tier-B force-compile / Tier-C invoke driver | §3 |
| `codeitem_sink.h/.cpp` | capture record buffer + whole-dex dump + flush to disk | §5 |
| `art_internal.h/.cpp` | the single home for resolved ART symbols + ABI offsets (cf. the `+24` in ForceCompileMethod) | §2, §4 |

## Phase plan (from the design spec)

- **P0** — plain inline hook on `ArtMethod::Invoke` + capture CodeItem to disk (Tier-A, stealth=0). No DBI, no enumeration. (`choke_hook` + `codeitem_sink` + `art_internal::get_code_item`.)
- **P1** — `VisitClasses` enumeration + Tier-B force-compile driver (reuse the `ForceCompileMethod` symbol pattern). (`method_enumerator`.)
- **P2** — offline DEX reassembler (host-side, lives in `tools/dexfixer/`, NOT here).
- **P3** — choke point → `kpm_inline_hooker` (stealth=1) + one-time DBI correctness check on that one function + maps hide. (the only DBI cost; see design §4.)

## Wiring (done)

Activated as designed:
1. `native/CMakeLists.txt` defines `VECTOR_UNPACK_ENABLED` on the native target.
2. `module.cpp` calls `vector::native::unpack::StartIfEnabled(...)` post-init.
3. Runtime gating — see "Runtime props" above (`persist.kpmhook.unpack*`).
4. The tier-based choke point defaults to `ArtMethod::GetCodeItem`; do NOT default the choke to
   `Execute` (huge/multi-page → hardest DBI case; design §4). The primary path is now
   `dexfind`(+`trigger`)/`interp`, not the tier choke.

## Runtime props (`persist.kpmhook.*`)

All gated behind `persist.kpmhook.unpack=1` + `persist.kpmhook.target=<pkg>` (the app's nice
name). Set with `resetprop` (APatch: `/data/adb/ap/bin/resetprop`). Output lands in
`<app_data>/unpack` (or the app's EXTERNAL dir with `extout=1`).

| prop (`persist.kpmhook.unpack…`) | default | meaning |
|---|---|---|
| `` (bare `.unpack`) | 0 | master enable |
| `.stealth` | 0 | choke hook via KPM traceless (1) vs Dobby (0) |
| `.traceless` | 0 | dexfind `FindClass` hook via KPM clone (1) vs Dobby (0) — RASP-safe |
| `.dexfind` | 0 | per-class dex discovery via ART `VisitClasses` (reaches header-mangled dexes) |
| `.trigger` | 0 | per-method `GetCodeItem` force-restore → `captures.txt` (needs `dexfind`) |
| `.interp` | 0 | interpreter-point capture (hook `art::interpreter::Execute`, FART-style) |
| `.interp_ms` | 30000 | interp capture window |
| `.activeload` | 0 | `Class.forName` every class (per-class DefineClass-restore shells, e.g. dpt) |
| `.extout` | 0 | write dumps to the app's EXTERNAL dir (pullable past strict SELinux MLS) |
| `.predelay_ms` | 6000 | dexfind: wait before the `FindClass` hook so the app loads its classes |
| **`.worker_delay_ms`** | **0** | **NEW — sleep before the worker's first ART touch (AttachCurrentThread / `art::Get()`). See "self-libart-patching shells" below.** |
| `.rounds` / `.interval_ms` | 40 / 400 | whole-dex burst scan (used only when `dexfind`/`interp`/`activeload` all off) |

**KPM engagement is now gated** (`StartIfEnabled`): the process is identified to the shpte KPM
(`set_process_name` + `ghost` + `fshide`) **only** when a KPM path is actually used
(`stealth=1 || traceless=1 || gcashfix || openat`). A pure-Dobby run (`stealth=0 traceless=0`)
leaves the process off the KPM's radar entirely — otherwise the KPM PTE-manages the target's
libart pages and collides with packers that patch libart themselves.

### Recipe — whole-dex encryption shell (Bangcle/SecNeo, 百度加固, …)

```
resetprop persist.kpmhook.unpack 1
resetprop persist.kpmhook.target <pkg>
resetprop persist.kpmhook.unpack.dexfind 1        # + traceless=1 if the app RASP-scans libart
```
`dexfind` alone dumps the decrypted whole dexes (method bodies intact); no `trigger` needed.

### Recipe — method-extraction shell that self-patches libart (51job `s.h.e.l.l`)

Such a shell maps a **private libart copy** at startup and inline-hooks it. That routine faults
`SEGV_ACCERR` (killing the app <1s in) if the worker touches ART while it runs, **and** the app's
dexes exceed a single VMA. Use pure Dobby + a settle delay:

```
resetprop persist.kpmhook.unpack 1
resetprop persist.kpmhook.target com.job.android
resetprop persist.kpmhook.unpack.stealth 0            # pure Dobby -> KPM not engaged
resetprop persist.kpmhook.unpack.traceless 0
resetprop persist.kpmhook.unpack.dexfind 1
resetprop persist.kpmhook.unpack.trigger 1            # per-method CodeItem capture
resetprop persist.kpmhook.unpack.worker_delay_ms 12000  # let the shell finish patching libart first
resetprop persist.kpmhook.unpack.extout 1
```
Launch the app, drive the UI (to invoke the methods you want restored) during/after the delay, then
pull `captures.txt` + `region_*_fixed.dex`. `DumpRegionsForPointers` reads multi-region dexes by
`file_size`, so the big structure dexes reconstruct whole. Offline: map each capture region to a
structure dex by method count (`(region, method_idx)` is self-consistent) and disassemble the
captured CodeItems against that dex's constant pool. (This recovered 51job's request-sign from
364k+ captures.)

## Hard limits (design §8)

VMP / dex2c / bytecode-virtualization shells have NO standard CodeItem → out of scope,
stealth does not help. Tier-C carries FART-class crash risk.
