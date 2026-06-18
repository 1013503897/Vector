#pragma once

// interp_capture — direction-1 increment-2c. Captures the REAL method bytecode of a side-cache /
// DefineClass-restore extraction shell (dpt-shell) at the FART capture point: the interpreter.
//
// WHY GetCodeItem (increment-2b) can't: dpt hooks ClassLinker::DefineClass and restores each
// method's real CodeItem into a parallel structure visible ONLY on the execution path;
// ArtMethod::GetCodeItem keeps returning the nop'd in-place stub. The real bytecode only becomes
// reachable at the instant a method actually interprets — where ART hands the interpreter a
// CodeItemDataAccessor pointing at the real insns. So we hook art::interpreter::Execute (the
// unified switch-interpreter entry) and, per method, synthesize a standard CodeItem from the live
// accessor (registers/ins/outs size + insns) and record it. Mechanism-agnostic: it works no matter
// where or how the shell stashes the restored code.
//
// COVERAGE is whatever the app actually interprets during the window. Passive (operator drives the
// app) proves the capture point; full coverage (active class-load + active invoke) is a follow-on.

#include <cstddef>

namespace vector::native::unpack {

class CodeItemSink;

// Hook art::interpreter::Execute, capture every distinct method interpreted over `window_ms`, then
// unhook and flush the captures into `sink` (captures.txt, the same format increment-2b emits ->
// tools/dexfixer/splice.py). Runs on the worker thread (blocks for the window); the hook fires on
// the app's own runnable threads. No-op (returns 0) unless ok_for_interp_capture(). Returns the
// number of distinct methods captured.
size_t CaptureInterpreted(CodeItemSink *sink, int window_ms);

}  // namespace vector::native::unpack
