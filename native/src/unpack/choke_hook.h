#pragma once

// choke_hook — installs the hook at the CodeItem-restore choke point and captures each
// restored CodeItem. Design §2.
//
// Choke-point selection is the key DBI decision: a SMALL single libart function keeps the
// stealth (kpm_inline_hooker) trap in the L1 regime (DBI-on-libart, oat_census-validated),
// NOT the dense DBI-on-JIT path that currently SIGILLs (kpm-ultimate-goal 2026-06-13).
//   kArtMethodInvoke  : ArtMethod::Invoke (recommended default; small).
//   kInterpreterBridge: artInterpreterToInterpreterBridge (small/medium).
//   kExecute          : art::interpreter::Execute (huge/multi-page -> HARDEST DBI; avoid).

namespace vector::native::unpack {

class CodeItemSink;

enum class ChokePoint { kArtMethodInvoke, kInterpreterBridge, kExecute };

// Install the choke hook.
//   stealth=true  -> kpm_inline_hooker (traceless; libart .text untouched, clone hidden).
//   stealth=false -> plain inline hook (Dobby) for shells without an anti-dump self-check.
// `sink` receives every captured CodeItem. Returns false on resolve/install failure
// (caller fail-safes to no-op, mirroring the M-C fallback discipline).
bool InstallChokeHook(ChokePoint cp, bool stealth, CodeItemSink *sink);

// Remove the choke hook (kpm_inline_unhooker / Dobby unhook). Call before teardown.
bool RemoveChokeHook();

}  // namespace vector::native::unpack
