import os
import struct
import sys

SRC = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else 'out/unenigma.exe')
DST = os.path.abspath(sys.argv[2] if len(sys.argv) > 2 else 'out/unenigma_logcf.exe')
BASE = 0x400000
CALL_RVA = 0x3574C
IAT = 0x43C0CC
CAVE_RVA = 0x54A00
BUF_RVA = 0x54C00
BUF_SIZE = 0x200

d = bytearray(open(SRC, 'rb').read())
e = struct.unpack_from('<I', d, 0x3c)[0]
nsec = struct.unpack_from('<H', d, e + 6)[0]
optsize = struct.unpack_from('<H', d, e + 20)[0]
opt = e + 24
sec_tab = opt + optsize
secs = []
for i in range(nsec):
    s = sec_tab + i * 40
    name = bytes(d[s:s + 8]).rstrip(b'\0').decode('latin-1')
    vs, va, rs, ro = struct.unpack_from('<IIII', d, s + 8)
    secs.append((name, s, va, vs, rs, ro))


def rva_off(rva):
    for name, s, va, vs, rs, ro in secs:
        if va <= rva < va + max(vs, rs):
            return ro + (rva - va), name, s, va, vs, rs, ro
    raise ValueError(hex(rva))


buf_off, buf_sec, s, va, vs, rs, ro = rva_off(BUF_RVA)
need_raw = (BUF_RVA - va) + BUF_SIZE
if need_raw > rs:
    new_rs = (need_raw + 0x1FF) & ~0x1FF
    struct.pack_into('<I', d, s + 16, new_rs)
    if ro + new_rs > len(d):
        d.extend(b'\0' * (ro + new_rs - len(d)))
if need_raw > vs:
    struct.pack_into('<I', d, s + 8, need_raw)

p32 = lambda x: struct.pack('<I', x & 0xFFFFFFFF)
cave = bytearray()
cave += b'\x60'                                   # pushad
cave += b'\x8b\x74\x24\x24'                       # mov esi,[esp+0x24]
cave += b'\xbf' + p32(BASE + BUF_RVA)             # mov edi,buf
cave += b'\xb9' + p32(BUF_SIZE)                   # mov ecx,size
cave += b'\xf3\xa4'                               # rep movsb
cave += b'\x61'                                   # popad
cave += b'\xff\x25' + p32(IAT)                    # jmp [real]
cave_off, _, _, _, _, _, _ = rva_off(CAVE_RVA)
d[cave_off:cave_off + len(cave)] = cave
d[buf_off:buf_off + BUF_SIZE] = b'\0' * BUF_SIZE
call_off, _, _, _, _, _, _ = rva_off(CALL_RVA)
rel = (BASE + CAVE_RVA) - (BASE + CALL_RVA + 5)
d[call_off:call_off + 6] = b'\xe8' + struct.pack('<i', rel) + b'\x90'
open(DST, 'wb').write(d)
print('written', DST, 'cave', hex(BASE + CAVE_RVA), 'buf', hex(BASE + BUF_RVA))
