// codeitem_sink.cpp — see codeitem_sink.h. INERT until VECTOR_UNPACK_ENABLED.

#ifdef VECTOR_UNPACK_ENABLED

#include "unpack/codeitem_sink.h"

#include <common/logging.h>

namespace vector::native::unpack {

bool CodeItemSink::Init(const char *out_dir) {
    // TODO(P0): mkdir -p out_dir (app uid), open the index + per-dex blob files.
    LOGI("[unpack] sink init dir={}", out_dir ? out_dir : "(null)");
    return out_dir != nullptr;
}

uint32_t CodeItemSink::RegisterDex(const void *begin, size_t size) {
    // TODO(P0): dedup by `begin`; on first sight dump [begin, begin+size) to
    // <dir>/dex_<id>.dex (the whole, possibly-nop'd image) and return a new id.
    LOGI("[unpack] register dex begin={} size={}", begin, size);
    return static_cast<uint32_t>(dex_count_++);
}

void CodeItemSink::Capture(const CaptureRecord &rec) {
    // TODO(P0): dedup by (dex_id, method_idx); append {dex_id, method_idx, off, len} to
    // the index + copy `len` bytes from rec.code_item into the per-dex blob. off is
    // computed by the reassembler from the dex base, or recorded here if cheap.
    (void)rec;
    ++capture_count_;
}

void CodeItemSink::Flush() {
    // TODO(P0): fsync the index + blobs. Pull to host; tools/dexfixer reassembles.
    LOGI("[unpack] sink flush: dex={} captures={}", dex_count_, capture_count_);
}

}  // namespace vector::native::unpack

#endif  // VECTOR_UNPACK_ENABLED
