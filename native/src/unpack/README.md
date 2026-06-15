# native/src/unpack — stealth unpacker (INERT scaffold)

Skeleton for the traceless DEX / extraction-shell unpacker. Design spec:
`../../../../stealth-poc/docs/unpacker-design.md` (sibling repo). Builds on the same
primitives as M-C: `ElfSymbolCache` (symbol resolution), `kpm_inline_hooker`
(kpm/kpmhook.h, traceless hook), and the post-init worker pattern of
`zygisk/src/main/cpp/module.cpp` `RunTracelessConvert` (module.cpp:307).

## ⚠️ Status: INERT — does NOT build into anything yet

`native/CMakeLists.txt` does `file(GLOB_RECURSE NATIVE_SOURCES "src/*.cpp")`, so these
`.cpp` files ARE swept into the build. To keep Vector's (actively-changing) build green
and this scaffold zero-impact, **every `.cpp` body is wrapped in
`#ifdef VECTOR_UNPACK_ENABLED`** (never defined). Result: each is an empty translation
unit → compiles to nothing → no symbols, no behavior, cannot break the build.

Nothing here is called from `module.cpp`. The unpacker is completely dormant until
deliberately wired (see "Wiring" below). This matches "scaffold only, don't compile/test,
Vector next door is still being changed".

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

## Wiring (do NOT do yet — Vector build in flux)

When ready to activate:
1. Add `-DVECTOR_UNPACK_ENABLED` to the native target's compile options (or `#define` it).
2. In `module.cpp`, after `RunTracelessConvert();` (the post-init worker, module.cpp:755),
   call `vector::native::unpack::StartIfEnabled(g_vm, env_);`.
3. Gate at runtime with `persist.kpmhook.unpack=1`, `unpack.tier=A|B|C`,
   `unpack.stealth=0|1`, `unpack.choke=invoke|bridge|execute` (see `unpacker.cpp`).
4. The choke point defaults to `ArtMethod::Invoke` (small fn → cheap DBI clone). Do NOT
   default to `Execute` (huge/multi-page → hardest DBI case; design §4).

## Hard limits (design §8)

VMP / dex2c / bytecode-virtualization shells have NO standard CodeItem → out of scope,
stealth does not help. Tier-C carries FART-class crash risk.
