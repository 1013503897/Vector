#pragma once

// class_dex_finder — direction-1 increment-1. Discovers every loaded app dex by enumerating
// classes (ClassLinker::VisitClasses) and reading each class's dex::ClassDef pointer
// (mirror::Class::GetClassDef), then dumps the WHOLE containing /proc/self/maps region
// (header-agnostic) via the sink. This recovers dexes the whole-dex maps scan misses because
// the packer (NetEase Yidun) mangles the in-memory dex header so IsDexHeader rejects it.
//
// Both ART symbols (VisitClasses + GetClassDef) resolve on this device's libart even though
// GetDexFile / Begin / Size are inlined. The one missing piece — the ClassLinker* `this` for
// VisitClasses — is captured by transiently hooking ClassLinker::FindClass (its arg0); that hook
// also gives a RUNNABLE thread (FindClass is REQUIRES_SHARED(mutator_lock_)) so the enumeration
// runs in a valid ART thread state, which the detached unpacker worker does NOT have on its own.

#include <cstddef>

namespace vector::native::unpack {

class CodeItemSink;

// Call from the unpacker worker. Installs a one-shot ClassLinker::FindClass hook, lets it fire
// (the app loads classes continuously), enumerates all classes -> ClassDef pointers on the
// runnable app thread, then dumps each distinct containing region into `sink` and unhooks.
// `wait_ms` bounds the wait for the first class load. Returns the number of regions dumped;
// 0 (no-op) if the ART surface is unresolved or the hook never fired.
//
// increment-2: when `trigger` is true AND the ArtMethod ABI is calibrated (CalibrateForMethodEnum
// ran), the visitor also collects every class's ArtMethod* (stable LinearAlloc pointers); BEFORE
// dumping, the worker calls ArtMethod::GetCodeItem on each — which forces an extraction shell to
// restore each method's CodeItem in place. The dump then captures the now-complete dex. Harmless
// on whole-dex shells (CodeItems already present).
// increment-2d: when `active_load` is true, AFTER enumeration and BEFORE the region dump, every
// class of the app's loaded dex(es) is Class.forName'd (active_load.h) so a per-class extraction
// shell (dpt) restores all CodeItems in place — recovering classes the app never reached. The dump
// then captures the restored code.
size_t FindAndDumpClassDexes(CodeItemSink *sink, void *jni_env, int wait_ms, bool trigger,
                             bool active_load, bool traceless, int pre_ms);

}  // namespace vector::native::unpack
