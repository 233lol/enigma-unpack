#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""Entry stub: restore .data protection, prime the CRT heap, then jump to the
real CRT startup (0x4209E9 - the function that calls WinMain).

The original image's entry (0x4204BF) is a DLL-style startup that returns
immediately; the real exe startup that reaches WinMain is 0x4209E9.
"""
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
EXE = os.path.abspath(sys.argv[1] if len(sys.argv) > 1
                      else os.path.join(HERE, '..', 'out', 'unenigma.exe'))
BASE = 0x400000
ENTRY = 0x204BF
CRT_MAIN = 0x4209E9
DATA_VA, DATA_SIZE = 0x44C000, 0x3000
HEAP_GLOBAL = 0x44E96C

d = bytearray(open(EXE, 'rb').read())
e = struct.unpack_from('<I', d, 0x3c)[0]
nsec = struct.unpack_from('<H', d, e + 6)[0]
optsize = struct.unpack_from('<H', d, e + 20)[0]
opt = e + 24
secalign = struct.unpack_from('<I', d, opt + 32)[0]
filealign = struct.unpack_from('<I', d, opt + 36)[0]

secs = []
by_name = {}
for k in range(nsec):
    s = opt + optsize + k * 40
    name = d[s:s + 8].rstrip(b'\0').decode('latin-1')
    va = struct.unpack_from('<I', d, s + 12)[0]
    vs = struct.unpack_from('<I', d, s + 8)[0]
    rs = struct.unpack_from('<I', d, s + 16)[0]
    ro = struct.unpack_from('<I', d, s + 20)[0]
    secs.append((name, s, va, vs, rs, ro))
    if name:
        by_name[name] = (s, va, vs, rs, ro)

s_hdr, s_va, s_vs, s_rs, s_ro = by_name['.idata']
cave_va = BASE + s_va + ((s_vs + 0xF) & ~0xF)
cave_off = s_ro + (cave_va - BASE - s_va)
code = bytearray()
patches = []


def emit(b):
    code.extend(b)


def pos():
    return len(code)


def addr(p):
    return cave_va + p


def patch32(p, v):
    patches.append((p, v))


# ---- resolve kernel32 + APIs ----
emit(b'\x68'); p = pos(); emit(b'\0\0\0\0'); patch32(p, None)
emit(b'\xff\x15' + struct.pack('<I', 0x43C1A0))       # GetModuleHandleA
emit(b'\x8b\xd8')                                     # mov ebx,eax


def resolve(name):
    emit(b'\x68'); p = pos(); emit(b'\0\0\0\0'); patch32(p, None)
    emit(b'\x53')
    emit(b'\xff\x15' + struct.pack('<I', 0x43C19C))    # GetProcAddress
    emit(b'\xa3'); p2 = pos(); emit(b'\0\0\0\0'); patch32(p2, None)


resolve(b'VirtualProtect\0')
resolve(b'GetProcessHeap\0')
resolve(b'Sleep\0')

# beat the asynchronous .data reprotection: sleep, then protect twice
emit(b'\x68' + struct.pack('<I', 120))                 # Sleep(120)
emit(b'\xff\x15'); p = pos(); emit(b'\0\0\0\0'); patch32(p, None)
for _ in range(2):
    emit(b'\x68'); p = pos(); emit(b'\0\0\0\0'); patch32(p, None)   # &old
    emit(b'\x6a\x04')
    emit(b'\x68' + struct.pack('<I', DATA_SIZE))
    emit(b'\x68' + struct.pack('<I', DATA_VA))
    emit(b'\xff\x15'); p = pos(); emit(b'\0\0\0\0'); patch32(p, None)

# *0x44E96C = GetProcessHeap()
emit(b'\xff\x15'); p = pos(); emit(b'\0\0\0\0'); patch32(p, None)
emit(b'\xa3' + struct.pack('<I', HEAP_GLOBAL))

# run the app's security-cookie init, then the CRT main (0x4209E9).
rel = 0x420F40 - (addr(pos()) + 5)
emit(b'\xe8' + struct.pack('<i', rel))          # __security_init_cookie
rel = CRT_MAIN - (addr(pos()) + 5)
emit(b'\xe9' + struct.pack('<i', rel))

str_pos = {}
for key, s in (('k32', b'kernel32.dll\0'), ('vp', b'VirtualProtect\0'),
               ('gph', b'GetProcessHeap\0'), ('sl', b'Sleep\0')):
    str_pos[key] = pos()
    emit(s)
glob_pos = pos()
g_vp = glob_pos
g_gph = glob_pos + 4
g_sl = glob_pos + 8
g_old = glob_pos + 12
emit(b'\0' * 16)
while len(code) % 4:
    code.append(0)

targets = [addr(str_pos['k32']), addr(str_pos['vp']), addr(g_vp),
           addr(str_pos['gph']), addr(g_gph),
           addr(str_pos['sl']), addr(g_sl),
           addr(g_sl),
           addr(g_old), addr(g_vp),
           addr(g_old), addr(g_vp),
           addr(g_gph)]
assert len(patches) == len(targets), (len(patches), len(targets))
for (p, _), tgt in zip(patches, targets):
    struct.pack_into('<I', code, p, tgt)

end_va = cave_va + len(code)
print('cave VA %#x size %#x' % (cave_va, len(code)))
if cave_off + len(code) > len(d):
    d.extend(b'\0' * (cave_off + len(code) - len(d)))
d[cave_off:cave_off + len(code)] = code

need_vs = end_va - BASE - s_va
if need_vs > s_vs:
    struct.pack_into('<I', d, s_hdr + 8, need_vs)
if cave_off + len(code) > s_ro + s_rs:
    new_rs = (cave_off + len(code) - s_ro + filealign - 1) // filealign * filealign
    struct.pack_into('<I', d, s_hdr + 16, new_rs)
sizeimg = struct.unpack_from('<I', d, opt + 56)[0]
need_img = (end_va - BASE + secalign - 1) // secalign * secalign
if need_img > sizeimg:
    struct.pack_into('<I', d, opt + 56, need_img)

# Point the PE entry at the cave.  Do NOT overwrite the instruction at the old
# entry (0x4204BF): the CRT calls that function internally.
struct.pack_into('<I', d, opt + 16, cave_va - BASE)
print('AddressOfEntryPoint -> %#x (cave)' % (cave_va - BASE))
print('cave -> %#x' % CRT_MAIN)

open(EXE, 'wb').write(d)
print('written', EXE, len(d))
