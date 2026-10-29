#!/usr/bin/env python3
"""Собирает Windows-ресурс с иконкой (icon_windows_amd64.syso) из PNG-файлов."""
import struct, sys

def build(pngs, out):
    # pngs: list of (size, bytes)
    n = len(pngs)
    # layout of the resource tree
    # root(2 entries) -> typeIcon dir(n) -> n lang dirs(1) ; typeGroup dir(1) -> lang dir(1)
    def dir_size(k): return 16 + 8 * k
    off = 0
    root = off; off += dir_size(2)
    icon_dir = off; off += dir_size(n)
    icon_lang = []
    for _ in range(n):
        icon_lang.append(off); off += dir_size(1)
    grp_dir = off; off += dir_size(1)
    grp_lang = off; off += dir_size(1)
    entries = []  # data entries
    icon_ent = []
    for _ in range(n):
        icon_ent.append(off); off += 16
    grp_ent = off; off += 16
    data_start = off
    blobs = []
    pos = data_start
    icon_pos = []
    for _, b in pngs:
        icon_pos.append(pos); blobs.append(b); pos += (len(b) + 3) // 4 * 4
    grp = struct.pack('<HHH', 0, 1, n)
    for i, (sz, b) in enumerate(pngs):
        w = 0 if sz >= 256 else sz
        grp += struct.pack('<BBBBHHIH', w, w, 0, 0, 1, 32, len(b), i + 1)
    grp_pos = pos; blobs.append(grp); pos += (len(grp) + 3) // 4 * 4
    total = pos
    buf = bytearray(total)
    relocs = []

    def put_dir(at, entries_):  # entries_: list of (id, target_offset, is_dir)
        struct.pack_into('<IIHHHH', buf, at, 0, 0, 0, 0, 0, len(entries_))
        for j, (eid, tgt, isdir) in enumerate(entries_):
            struct.pack_into('<II', buf, at + 16 + 8 * j, eid, tgt | (0x80000000 if isdir else 0))

    put_dir(root, [(3, icon_dir, True), (14, grp_dir, True)])
    put_dir(icon_dir, [(i + 1, icon_lang[i], True) for i in range(n)])
    for i in range(n):
        put_dir(icon_lang[i], [(0x0409, icon_ent[i], False)])
        struct.pack_into('<IIII', buf, icon_ent[i], icon_pos[i], len(pngs[i][1]), 0, 0)
        relocs.append(icon_ent[i])
    put_dir(grp_dir, [(1, grp_lang, True)])
    put_dir(grp_lang, [(0x0409, grp_ent, False)])
    struct.pack_into('<IIII', buf, grp_ent, grp_pos, len(grp), 0, 0)
    relocs.append(grp_ent)
    p = data_start
    for b in blobs:
        buf[p:p + len(b)] = b
        p += (len(b) + 3) // 4 * 4

    # COFF object
    nrel = len(relocs)
    sec_raw = 20 + 40
    reloc_off = sec_raw + total
    symtab = reloc_off + 10 * nrel
    coff = struct.pack('<HHIIIHH', 0x8664, 1, 0, symtab, 1, 0, 0)
    coff += struct.pack('<8sIIIIIIHHI', b'.rsrc', 0, 0, total, sec_raw, reloc_off, 0, nrel, 0, 0x40000040)
    coff += bytes(buf)
    for r in relocs:
        coff += struct.pack('<IIH', r, 0, 3)  # ADDR32NB against symbol 0
    coff += struct.pack('<8sIhHBB', b'.rsrc', 0, 1, 0, 3, 0)  # section symbol
    coff += struct.pack('<I', 4)  # empty string table
    open(out, 'wb').write(coff)

if __name__ == '__main__':
    out = sys.argv[1]
    files = sys.argv[2:]
    items = []
    for f in files:
        d = open(f, 'rb').read()
        w = struct.unpack('>I', d[16:20])[0]
        items.append((w, d))
    build(items, out)
