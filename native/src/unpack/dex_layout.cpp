// dex_layout.cpp — CodeItem length parser (see dex_layout.h). INERT until VECTOR_UNPACK_ENABLED.
//
// Pure dex-format; no ART. Parses the standard CodeItem trailer (try_items + the
// uleb128-encoded catch-handler list) to recover the exact byte length, so the per-method
// capture (P0-design) copies precisely [code_item, code_item + len).

#ifdef VECTOR_UNPACK_ENABLED

#include "unpack/dex_layout.h"

namespace vector::native::unpack::dex {

namespace {

// Read an unsigned LEB128, advancing *p. No bounds arg: caller bounds via the dex image.
uint32_t ReadUleb128(const uint8_t **p) {
    const uint8_t *ptr = *p;
    uint32_t result = *ptr & 0x7f;
    if (*ptr++ & 0x80) {
        result |= (uint32_t)(*ptr & 0x7f) << 7;
        if (*ptr++ & 0x80) {
            result |= (uint32_t)(*ptr & 0x7f) << 14;
            if (*ptr++ & 0x80) {
                result |= (uint32_t)(*ptr & 0x7f) << 21;
                if (*ptr++ & 0x80) {
                    result |= (uint32_t)(*ptr & 0x7f) << 28;
                    ptr++;
                }
            }
        }
    }
    *p = ptr;
    return result;
}

// Read a signed LEB128 (used by encoded_catch_handler.size sign).
int32_t ReadSleb128(const uint8_t **p) {
    const uint8_t *ptr = *p;
    int32_t result = *ptr & 0x7f;
    int shift = 7;
    if (*ptr++ & 0x80) {
        for (; shift < 32; shift += 7) {
            uint8_t b = *ptr++;
            result |= (int32_t)(b & 0x7f) << shift;
            if (!(b & 0x80)) {
                if (shift + 7 < 32 && (b & 0x40)) result |= -(1 << (shift + 7));
                break;
            }
        }
    }
    *p = ptr;
    return result;
}

}  // namespace

size_t CodeItemLength(const uint8_t *ci) {
    if (!ci) return 0;
    // Fixed 16-byte standard CodeItem header.
    uint16_t tries_size = *reinterpret_cast<const uint16_t *>(ci + 6);
    uint32_t insns_size = *reinterpret_cast<const uint32_t *>(ci + 12);
    // Sanity caps: a real standard CodeItem never has these magnitudes. They bound the parse so a
    // NON-standard input (a CompactDex CodeItem, whose +6/+12 fields mean something else, or random
    // memory) returns 0 fast instead of running away in the handler loop below.
    if (insns_size > (1u << 20)) return 0;        // > 1M code units
    if (tries_size > 8192) return 0;

    const uint8_t *p = ci + 16;            // start of insns[]
    p += (size_t)insns_size * 2;           // u2 insns[insns_size]
    if (tries_size == 0) {
        return (size_t)(p - ci);           // no tries/handlers
    }
    // Optional u2 padding to 4-byte-align the try_item array.
    if (insns_size & 1) p += 2;
    // try_item[tries_size], 8 bytes each (u4 start_addr; u2 insn_count; u2 handler_off).
    p += (size_t)tries_size * 8;

    // encoded_catch_handler_list: uleb128 size, then `size` encoded_catch_handler entries.
    uint32_t handler_count = ReadUleb128(&p);
    if (handler_count > 65536) return 0;          // cap (garbage input)
    for (uint32_t i = 0; i < handler_count; i++) {
        int32_t size = ReadSleb128(&p);           // signed: <0 means a catch-all follows
        uint32_t pairs = (size < 0) ? (uint32_t)(-size) : (uint32_t)size;
        if (pairs > 65536) return 0;              // cap
        for (uint32_t j = 0; j < pairs; j++) {
            ReadUleb128(&p);                      // type_idx
            ReadUleb128(&p);                      // address
        }
        if (size <= 0) ReadUleb128(&p);           // catch_all_addr
    }
    return (size_t)(p - ci);
}

// ---- class-descriptor enumeration (increment-2d) -----------------------------------------

namespace {
inline uint32_t Rd32(const uint8_t *p) { return *reinterpret_cast<const uint32_t *>(p); }
}  // namespace

const uint8_t *LocateDexByInvariants(const uint8_t *from, const uint8_t *region_end) {
    if (!from || region_end <= from) return nullptr;
    // The invariant pair sits at dex_base+0x24 (header_size) / +0x28 (endian). Scan for it, then
    // back up 0x24 to the dex base. 4-byte-aligned (the header is u4-aligned in every dex).
    const uint8_t *start = reinterpret_cast<const uint8_t *>(
        (reinterpret_cast<uintptr_t>(from) + 3) & ~uintptr_t(3));
    for (const uint8_t *x = start; x + 8 <= region_end; x += 4) {
        if (Rd32(x) != kHeaderSize) continue;
        if (Rd32(x + 4) != kEndianTag) continue;
        const uint8_t *base = x - 0x24;
        if (base < from) continue;
        if (base + 0x70 > region_end) continue;          // must be able to read the full header
        uint32_t fsz = Rd32(base + 0x20);                // file_size
        if (fsz < kHeaderSize || fsz > (256u << 20)) continue;
        if (base + fsz > region_end) continue;
        return base;
    }
    return nullptr;
}

size_t EnumerateClassDescriptors(const uint8_t *dex_base, const uint8_t *region_end,
                                 DescriptorCb cb, void *ctx) {
    if (!dex_base || !cb || region_end <= dex_base + 0x70) return 0;
    auto in = [&](const uint8_t *p, size_t n) { return p >= dex_base && p + n <= region_end; };

    uint32_t string_ids_size = Rd32(dex_base + 0x38);
    uint32_t string_ids_off = Rd32(dex_base + 0x3c);
    uint32_t type_ids_size = Rd32(dex_base + 0x40);
    uint32_t type_ids_off = Rd32(dex_base + 0x44);
    uint32_t class_defs_size = Rd32(dex_base + 0x60);
    uint32_t class_defs_off = Rd32(dex_base + 0x64);
    // Sanity: section tables must lie within the region.
    if (!string_ids_size || !type_ids_size || !class_defs_size) return 0;
    if (class_defs_size > (1u << 22) || type_ids_size > (1u << 22) || string_ids_size > (1u << 23))
        return 0;
    const uint8_t *sids = dex_base + string_ids_off;
    const uint8_t *tids = dex_base + type_ids_off;
    const uint8_t *cdefs = dex_base + class_defs_off;
    if (!in(sids, (size_t)string_ids_size * 4)) return 0;
    if (!in(tids, (size_t)type_ids_size * 4)) return 0;
    if (!in(cdefs, (size_t)class_defs_size * 0x20)) return 0;

    size_t n = 0;
    for (uint32_t ci = 0; ci < class_defs_size; ci++) {
        uint32_t class_idx = Rd32(cdefs + (size_t)ci * 0x20);       // class_def.class_idx
        if (class_idx >= type_ids_size) continue;
        uint32_t str_idx = Rd32(tids + (size_t)class_idx * 4);      // type_id -> descriptor str idx
        if (str_idx >= string_ids_size) continue;
        uint32_t str_off = Rd32(sids + (size_t)str_idx * 4);        // string_id -> string_data_off
        const uint8_t *p = dex_base + str_off;
        if (!in(p, 1)) continue;
        // Skip the uleb128 utf16_size (<=5 bytes), then the MUTF8 bytes follow (NUL-terminated).
        const uint8_t *q = p;
        for (int k = 0; k < 5 && in(q, 1); k++) {
            uint8_t b = *q++;
            if (!(b & 0x80)) break;
        }
        // Bound the descriptor: must be NUL-terminated within 512 bytes and the region.
        const char *desc = reinterpret_cast<const char *>(q);
        const uint8_t *limit = q + 512 < region_end ? q + 512 : region_end;
        const uint8_t *e = q;
        while (e < limit && *e) e++;
        if (e >= limit || *e != 0) continue;           // not terminated in bound -> skip
        if (desc[0] != 'L') continue;                  // only class types (skip arrays/primitives)
        cb(desc, ctx);
        n++;
    }
    return n;
}

}  // namespace vector::native::unpack::dex

#endif  // VECTOR_UNPACK_ENABLED
