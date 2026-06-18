#pragma once

// dex_layout — pure dex-format helpers (no ART dependency). Two jobs:
//   1. Validate / locate a dex image in memory (IsDexHeader + the file_size field), so the
//      whole-dex dump can recover [begin, begin+file_size) from any inner pointer.
//   2. Parse a CodeItem's byte length (P0-design per-method capture).
// Everything here is host-testable against the dex spec; keep it ART-free.

#include <cstddef>
#include <cstdint>

namespace vector::native::unpack::dex {

constexpr uint32_t kHeaderSize = 0x70;        // dex header_size_ is always 0x70
constexpr uint32_t kEndianTag = 0x12345678;   // little-endian constant
constexpr size_t kMagicLen = 4;               // "dex\n" prefix (version digits vary)

// The leading fields of a dex header we actually read (see dex spec / dex_file.h).
struct Header {
    uint8_t magic[8];        // +0x00 "dex\n0XY\0"
    uint32_t checksum;       // +0x08 adler32
    uint8_t signature[20];   // +0x0c sha1
    uint32_t file_size;      // +0x20 total dex size in bytes
    uint32_t header_size;    // +0x24 == 0x70
    uint32_t endian_tag;     // +0x28 == 0x12345678
    // ... map_off / *_size / *_off follow; not needed here.
};
static_assert(sizeof(Header) >= 0x2c, "Header must cover endian_tag");

// True if `p` (>= 8 readable bytes) points at a plausible dex header. Conservative: checks
// the magic prefix, the fixed header_size, the endian tag, and a sane file_size. Caller
// guarantees the read of sizeof(Header) bytes at p is mapped.
inline bool IsDexHeader(const uint8_t *p) {
    if (!p) return false;
    if (p[0] != 'd' || p[1] != 'e' || p[2] != 'x' || p[3] != '\n') return false;
    const auto *h = reinterpret_cast<const Header *>(p);
    if (h->header_size != kHeaderSize) return false;
    if (h->endian_tag != kEndianTag) return false;
    // file_size must at least cover the header and be within a sane bound (256 MB).
    if (h->file_size < kHeaderSize || h->file_size > (256u << 20)) return false;
    return true;
}

inline uint32_t DexFileSize(const uint8_t *dex_base) {
    return reinterpret_cast<const Header *>(dex_base)->file_size;
}
inline uint32_t DexChecksum(const uint8_t *dex_base) {
    return reinterpret_cast<const Header *>(dex_base)->checksum;
}

// ---- CodeItem length (P0-design per-method capture; unused by P0-simple whole-dex) ----
//
// Standard (pre-CompactDex) CodeItem layout, all little-endian:
//   u2 registers_size; u2 ins_size; u2 outs_size; u2 tries_size;
//   u4 debug_info_off;  u4 insns_size;  u2 insns[insns_size];
//   [u2 padding if tries_size != 0 && insns_size odd]
//   try_item tries[tries_size]            (8 bytes each)
//   encoded_catch_handler_list handlers   (uleb128-encoded, variable)
// Returns the total byte length, or 0 if it cannot be computed safely.
size_t CodeItemLength(const uint8_t *code_item);

// ---- class-descriptor enumeration (increment-2d active class-loading) ----
//
// Locate a dex image by its INVARIANT fields (header_size==0x70 @ +0x24, endian_tag @ +0x28),
// NOT the magic — so it finds a packer's in-memory dex even when the shell mangled the magic /
// checksum (dpt / Yidun). Scans 4-byte-aligned from `from` up to `region_end`; returns the dex
// base whose [base, base+file_size) fits within `region_end`, or nullptr if none. For the next
// dex in a multi-dex region, pass `from = base + DexFileSize(base)`.
const uint8_t *LocateDexByInvariants(const uint8_t *from, const uint8_t *region_end);

// Enumerate every class descriptor ("Lcom/foo/Bar;") in the dex at `dex_base`, calling
// cb(descriptor, ctx) once per class_def. The descriptor is a NUL-terminated C-string pointing
// into the live dex (valid only during the call). `region_end` bounds every read; section offsets
// come straight from the header (intact even when magic is mangled). Bounds-checked + length-capped
// so it never faults within the region. Returns the count enumerated (0 if the header looks wrong).
using DescriptorCb = void (*)(const char *descriptor, void *ctx);
size_t EnumerateClassDescriptors(const uint8_t *dex_base, const uint8_t *region_end,
                                 DescriptorCb cb, void *ctx);

}  // namespace vector::native::unpack::dex
