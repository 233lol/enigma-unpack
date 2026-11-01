#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""Add a TLS directory to the rebuilt exe.

The original program uses static TLS (msvcrt style):
    mov eax, fs:[0x2C]
    mov ecx, [_tls_index]      ; 0x44DFB8
    mov ecx, [eax + ecx*4]
    ... [ecx + 4] ...
Our rebuilt PE lost the original TLS data directory, so the loader never
allocates a TLS block for the module -> [ecx+4] dereferences NULL.

We insert an IMAGE_TLS_DIRECTORY32 into the .idata slack, set
AddressOfIndex = 0x44DFB8 and SizeOfZeroFill = 0x20, and register directory 9.
"""
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
EXE = os.path.abspath(sys.argv[1] if len(sys.argv) > 1
                      else os.path.join(HERE, '..', 'out', 'unenigma.exe'))
BASE = 0x400000
TLS_INDEX_VA = 0x44DFB8
TLS_DIR_VA = 0x454800          # inside .idata raw slack (RVA 0x54800)
ZERO_FILL = 0x20

d = bytearray(open(EXE, 'rb').read())
e = struct.unpack_from('<I', d, 0x3c)[0]
nsec = struct.unpack_from('<H', d, e + 6)[0]
optsize = struct.unpack_from('<H', d, e + 20)[0]
opt = e + 24
sizeimg = struct.unpack_from('<I', d, opt + 56)[0]

secs = []
for k in range(nsec):
    s = opt + optsize + k * 40
    nm = d[s:s + 8].rstrip(b'\0').decode('latin-1')
    vs, va, rs, ro = struct.unpack_from('<IIII', d, s + 8)
    secs.append((nm, s, va, vs, rs, ro))


def rva_off(rva):
    for nm, s, va, vs, rs, ro in secs:
        if va <= rva < va + max(vs, rs):
            return ro + (rva - va), s, va, vs, rs, ro
    raise ValueError(hex(rva))


rva = TLS_DIR_VA - BASE
off, s_hdr, s_va, s_vs, s_rs, s_ro = rva_off(rva)
end_rva = rva + 24
# TLS directory: Start, End, Index, Callbacks, SizeOfZeroFill, Characteristics
tls = struct.pack('<IIIIII', 0, 0, TLS_INDEX_VA, 0, ZERO_FILL, 0)
d[off:off + 24] = tls

# data directory 9 (TLS)
struct.pack_into('<II', d, opt + 96 + 9 * 8, rva, 24)

# make sure the section / image cover it
need_vs = end_rva - s_va
if need_vs > s_vs:
    struct.pack_into('<I', d, s_hdr + 8, need_vs)
if off + 24 > s_ro + s_rs:
    print('WARN: TLS dir beyond raw size')
if end_rva > sizeimg:
    struct.pack_into('<I', d, opt + 56, (end_rva + 0xFFF) & ~0xFFF)

open(EXE, 'wb').write(d)
print(f'{EXE}')
print(f'  TLS directory @ VA {TLS_DIR_VA:#x} (rva {rva:#x}), index @ {TLS_INDEX_VA:#x}, '
      f'zero-fill {ZERO_FILL:#x}')
print(f'  directory[9] = rva {rva:#x} size 24')


