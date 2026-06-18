#!/usr/bin/env python3
"""splice — graft restored CodeItems (Vector increment-2b capture) back into the structure-only
dex(es) recovered by dexfixer, to defeat SIDE-CACHE method-extraction shells (e.g. dpt-shell).

Such shells keep each method's CodeItem slot in the dex but blank/encrypt the insns in place,
restoring the real CodeItem to a side structure at runtime. Vector's dexfind+trigger captures the
restored CodeItem per method into <unpack-dir>/captures.txt:

    <region_start_hex> <dex_method_index> <codeitem_hex>

`region_start_hex` matches the dexfixer output `region_<start>_<size>_fixed.dex`. For each fixed dex
we map every dex_method_index -> its in-dex code_off (by walking class_data), then overwrite the
blanked CodeItem in place when the captured one is the same length (dpt encrypts in place, so it is),
else append it and repoint. Finally checksum+signature are recomputed.

Usage:
    python splice.py <dir-with-captures.txt-and-region_*_fixed.dex> [out_dir]
"""
import os
import sys
import struct
import zlib
import hashlib


def uleb(b, o):
    r = s = 0
    while True:
        x = b[o]; o += 1; r |= (x & 0x7f) << s; s += 7
        if not (x & 0x80):
            break
    return r, o


def sleb(b, o):
    r = s = 0
    while True:
        x = b[o]; o += 1; r |= (x & 0x7f) << s; s += 7
        if not (x & 0x80):
            if x & 0x40:
                r |= -(1 << s)
            break
    return r, o


def codeitem_len(buf, off):
    """Byte length of a standard CodeItem at buf[off]."""
    tries = struct.unpack_from('<H', buf, off + 6)[0]
    insns_size = struct.unpack_from('<I', buf, off + 12)[0]
    p = off + 16 + insns_size * 2
    if tries == 0:
        return p - off
    if insns_size & 1:
        p += 2
    p += tries * 8
    sz, p = uleb(buf, p)
    for _ in range(sz):
        s, p = sleb(buf, p)
        for _ in range(abs(s)):
            _, p = uleb(buf, p)
            _, p = uleb(buf, p)
        if s <= 0:
            _, p = uleb(buf, p)
    return p - off


def method_codeoffs(dex):
    """Walk every class_data. Returns:
       coffs       {dex_method_index: code_off}
       midx_class  {dex_method_index: class_def_index}   (to locate the owning class_data to rebuild)
       class_cdo   {class_def_index: class_data_off}"""
    u4 = lambda o: struct.unpack_from('<I', dex, o)[0]
    cdef_sz, cdef_off = u4(0x60), u4(0x64)
    coffs, midx_class, class_cdo = {}, {}, {}
    for ci in range(cdef_sz):
        cdo = u4(cdef_off + ci * 0x20 + 24)
        if cdo == 0:
            continue
        class_cdo[ci] = cdo
        o = cdo
        sf, o = uleb(dex, o); inf, o = uleb(dex, o); dm, o = uleb(dex, o); vm, o = uleb(dex, o)
        for _ in range(sf):
            _, o = uleb(dex, o); _, o = uleb(dex, o)
        for _ in range(inf):
            _, o = uleb(dex, o); _, o = uleb(dex, o)
        for grp in (dm, vm):
            midx = 0
            for k in range(grp):
                diff, o = uleb(dex, o); midx = diff if k == 0 else midx + diff
                _, o = uleb(dex, o)             # access_flags
                coff, o = uleb(dex, o)          # code_off
                midx_class[midx] = ci
                if coff:
                    coffs[midx] = coff
    return coffs, midx_class, class_cdo


def enc_uleb(v):
    out = bytearray()
    while True:
        b = v & 0x7f
        v >>= 7
        if v:
            out.append(b | 0x80)
        else:
            out.append(b)
            return out


def class_data_off(dex, class_idx):
    """ClassDef.class_data_off (u4) field OFFSET inside the dex for a given class_def index."""
    cdef_off = struct.unpack_from('<I', dex, 0x64)[0]
    return cdef_off + class_idx * 0x20 + 24


def rebuild_class_data(dex, cdo, new_offs):
    """Re-emit the class_data_item at offset `cdo`, replacing code_off for any method whose
    dex_method_index is in `new_offs` ({midx: new_code_off}). Returns the new class_data bytes.
    Fields are copied verbatim (only method code_offs change)."""
    o = cdo
    sf, o = uleb(dex, o); inf, o = uleb(dex, o); dm, o = uleb(dex, o); vm, o = uleb(dex, o)
    out = bytearray()
    out += enc_uleb(sf); out += enc_uleb(inf); out += enc_uleb(dm); out += enc_uleb(vm)
    for _ in range(sf + inf):                     # encoded_field[]: idx_diff, access_flags
        a, o = uleb(dex, o); b, o = uleb(dex, o)
        out += enc_uleb(a); out += enc_uleb(b)
    for grp in (dm, vm):                          # encoded_method[]: idx_diff, access, code_off
        midx = 0
        for k in range(grp):
            diff, o = uleb(dex, o); midx = diff if k == 0 else midx + diff
            acc, o = uleb(dex, o)
            coff, o = uleb(dex, o)
            if midx in new_offs:
                coff = new_offs[midx]
            out += enc_uleb(diff); out += enc_uleb(acc); out += enc_uleb(coff)
    return out


def fixsig(dex):
    # file_size (u4 @ 0x20) must match the (possibly grown) image, else strict loaders reject it.
    struct.pack_into('<I', dex, 0x20, len(dex))
    dex[12:32] = hashlib.sha1(bytes(dex[32:])).digest()
    struct.pack_into('<I', dex, 8, zlib.adler32(bytes(dex[12:])) & 0xffffffff)


def load_captures(path):
    by_region = {}
    with open(path) as f:
        for line in f:
            parts = line.split()
            if len(parts) != 3:
                continue
            region, midx, hexs = parts
            by_region.setdefault(region.lower(), []).append((int(midx), bytes.fromhex(hexs)))
    return by_region


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(2)
    d = sys.argv[1]
    out_dir = sys.argv[2] if len(sys.argv) > 2 else os.path.join(d, 'spliced')
    os.makedirs(out_dir, exist_ok=True)

    cap_path = os.path.join(d, 'captures.txt')
    if not os.path.isfile(cap_path):
        print(f"no captures.txt in {d}")
        sys.exit(1)
    by_region = load_captures(cap_path)
    print(f"captures.txt: {sum(len(v) for v in by_region.values())} methods across "
          f"{len(by_region)} region(s)")

    # match each region_start -> the dexfixer-reconstructed dex
    fixed = [f for f in os.listdir(d) if f.startswith('region_') and f.endswith('_fixed.dex')]
    for region, caps in by_region.items():
        match = None
        for f in fixed:
            # region_<start>_<size>_fixed.dex
            start = f.split('_')[1].lower()
            if start == region:
                match = f
                break
        if not match:
            print(f"  region {region}: no matching *_fixed.dex (skipped, {len(caps)} caps)")
            continue
        dex = bytearray(open(os.path.join(d, match), 'rb').read())
        coffs, midx_class, class_cdo = method_codeoffs(dex)
        patched = same = grew = missing = 0
        # Methods whose captured CodeItem differs in size from the in-dex stub can't be overwritten
        # in place; collect them per owning class for append+repoint below.
        repoint = {}     # class_idx -> {midx: new_code_off}
        append = bytearray()
        base = (len(dex) + 3) & ~3   # appended items start 4-aligned after the current image

        def emit(code):
            nonlocal append
            pad = (-len(append)) & 3
            append += b'\x00' * pad
            off = base + len(append)
            append += code
            return off

        for midx, code in caps:
            co = coffs.get(midx)
            if co is None:
                missing += 1
                continue
            try:
                cur = codeitem_len(dex, co)
            except Exception:
                cur = -1
            if cur == len(code):
                dex[co:co + len(code)] = code         # in-place overwrite (same size)
                same += 1; patched += 1
            else:
                ci = midx_class.get(midx)
                if ci is None or ci not in class_cdo:
                    missing += 1
                    continue
                repoint.setdefault(ci, {})[midx] = emit(code)   # append, remember new code_off
                grew += 1; patched += 1

        # Rebuild each affected class's class_data with the new code_offs, append it, and repoint
        # the (fixed-width u4) ClassDef.class_data_off — no in-place uleb resize needed.
        if repoint:
            dex += b'\x00' * ((-len(dex)) & 3)
            dex += append                              # bring appended code items into the image
            for ci, new_offs in repoint.items():
                new_cd = rebuild_class_data(dex, class_cdo[ci], new_offs)
                dex += b'\x00' * ((-len(dex)) & 3)
                cd_off = len(dex)
                dex += new_cd
                struct.pack_into('<I', dex, class_data_off(dex, ci), cd_off)

        fixsig(dex)
        out = os.path.join(out_dir, match.replace('_fixed.dex', '_spliced.dex'))
        open(out, 'wb').write(dex)
        print(f"  {match}: {len(caps)} caps -> patched={patched} (in-place={same} "
              f"append+repoint={grew}) idx-missing={missing} -> {os.path.basename(out)}")
    print(f"done -> {out_dir}")


if __name__ == '__main__':
    main()
