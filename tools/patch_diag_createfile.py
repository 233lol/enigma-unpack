#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""诊断补丁：记录 CreateFileW / FindFirstFileA / FindFirstFileExA 的失败路径。

生成 out\unenigma_diag.exe 后，用 tools\auto_seq.py 配合 DIAG_POLL=1 运行：
失败路径会写进 0x454E00 的缓冲区，标志字节在 0x454DFF。
"""
import os
import struct
import sys

SRC = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else os.path.join('out', 'unenigma.exe'))
DST = os.path.abspath(sys.argv[2] if len(sys.argv) > 2 else os.path.join('out', 'unenigma_diag.exe'))
BASE = 0x400000
CALL_RVA = 0x3574C          # call dword ptr [0x43C0CC] in the file wrapper
IAT_CREATEFILE = 0x43C0CC
CAVE_RVA = 0x54A00
POST_RVA = CAVE_RVA + 0x80
FLAG_RVA = 0x54DFF
BUF_RVA = 0x54E00
BUF_SIZE = 0x200
RET_VA = BASE + CALL_RVA + 6

# (name, pre_rva, post_rva, real_ptr_rva, ret_ptr_rva, iat_slot, fail_zero)
HOOKS = [
    ('FindFirstFileA', 0x54C00, 0x54C80, 0x54DC0, 0x54DC4, 0x43C138, False),
    ('FindFirstFileExA', 0x54D00, 0x54D80, 0x54DC8, 0x54DCC, 0x43C0B8, False),
    ('CreateDirectoryW', 0x54B00, 0x54B80, 0x54DD0, 0x54DD4, 0x43C0C0, True),
]


def u16(d, o):
    return struct.unpack_from('<H', d, o)[0]


def u32(d, o):
    return struct.unpack_from('<I', d, o)[0]


def w32(d, o, v):
    struct.pack_into('<I', d, o, v)


d = bytearray(open(SRC, 'rb').read())
e = u32(d, 0x3c)
nsec = u16(d, e + 6)
optsize = u16(d, e + 20)
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
            return ro + (rva - va), name
    raise ValueError('rva %#x not mapped' % rva)


# extend the section holding the caves / buffer
buf_off, buf_sec = rva_off(BUF_RVA)
for name, s, va, vs, rs, ro in secs:
    if name == buf_sec:
        need_raw = (BUF_RVA - va) + BUF_SIZE
        if need_raw > rs:
            new_rs = (need_raw + 0x1FF) & ~0x1FF
            w32(d, s + 16, new_rs)
            if ro + new_rs > len(d):
                d.extend(b'\0' * (ro + new_rs - len(d)))
        if need_raw > vs:
            w32(d, s + 8, need_raw)
        break


def build_hook(pre_rva, post_rva, real_rva, ret_rva, fail_zero=False):
    """Build a pre/post cave pair for an API with lpFileName as arg 1."""
    pre = bytearray()
    post = bytearray()
    labels = {}
    fix = []
    labels_p = {}
    fix_p = []

    def emit(b):
        pre.extend(b)

    def label(n):
        labels[n] = len(pre)

    def jcc(op, target):
        emit(bytes([op, 0]))
        fix.append((len(pre) - 1, target))

    def emitp(b):
        post.extend(b)

    def labelp(n):
        labels_p[n] = len(post)

    def jccp(op, target):
        emitp(bytes([op, 0]))
        fix_p.append((len(post) - 1, target))

    emit(b'\x60')                                      # pushad
    emit(b'\x8b\x74\x24\x24')                          # mov esi,[esp+0x24]
    emit(b'\x85\xf6')                                  # test esi,esi
    jcc(0x74, 'popad')
    emit(b'\xbf' + struct.pack('<I', BASE + BUF_RVA))
    emit(b'\xb9' + struct.pack('<I', BUF_SIZE - 1))
    label('loop')
    emit(b'\x8a\x06\x88\x07\x84\xc0')
    jcc(0x74, 'popad')
    emit(b'\x46\x47\x49')
    jcc(0x75, 'loop')
    emit(b'\xc6\x07\x00')
    label('popad')
    emit(b'\x61')                                      # popad
    emit(b'\x8b\x04\x24')                              # mov eax,[esp]
    emit(b'\xa3' + struct.pack('<I', BASE + ret_rva))  # mov [ret],eax
    emit(b'\xc6\x05' + struct.pack('<I', BASE + FLAG_RVA) + b'\x00')
    emit(b'\xc7\x04\x24' + struct.pack('<I', BASE + post_rva))
    emit(b'\xff\x25' + struct.pack('<I', BASE + real_rva))
    for pos, target in fix:
        pre[pos] = (labels[target] - (pos + 1)) & 0xFF

    if fail_zero:
        emitp(b'\x85\xc0')                             # test eax,eax
        jccp(0x75, 'ret')                              # jne ret (success)
    else:
        emitp(b'\x83\xf8\xff')                         # cmp eax,-1
        jccp(0x75, 'ret')
    emitp(b'\xc6\x05' + struct.pack('<I', BASE + FLAG_RVA) + b'\x01')
    emitp(b'\xb9' + struct.pack('<I', 0x08000000))     # delay for poller
    labelp('delay')
    emitp(b'\x49\x75\xfd')
    labelp('ret')
    emitp(b'\xff\x25' + struct.pack('<I', BASE + ret_rva))
    for pos, target in fix_p:
        post[pos] = (labels_p[target] - (pos + 1)) & 0xFF
    return bytes(pre), bytes(post)


# --- CreateFileW call-site hook (fixed return address) -------------------
pre = bytearray()
post = bytearray()
labels = {}
fix = []
labels_p = {}
fix_p = {}


def emit(b):
    pre.extend(b)


def label(n):
    labels[n] = len(pre)


def jcc(op, target):
    emit(bytes([op, 0]))
    fix.append((len(pre) - 1, target))


def emitp(b):
    post.extend(b)


def labelp(n):
    labels_p[n] = len(post)


def jccp(op, target):
    emitp(bytes([op, 0]))
    fix_p[(len(post) - 1)] = target


emit(b'\x60')
emit(b'\x8b\x74\x24\x24')
emit(b'\x85\xf6')
jcc(0x74, 'popad')
emit(b'\xbf' + struct.pack('<I', BASE + BUF_RVA))
emit(b'\xb9' + struct.pack('<I', BUF_SIZE - 1))
label('loop')
emit(b'\x8a\x06\x88\x07\x84\xc0')
jcc(0x74, 'popad')
emit(b'\x46\x47\x49')
jcc(0x75, 'loop')
emit(b'\xc6\x07\x00')
label('popad')
emit(b'\x61')
emit(b'\xc6\x05' + struct.pack('<I', BASE + FLAG_RVA) + b'\x00')
emit(b'\xc7\x04\x24' + struct.pack('<I', BASE + POST_RVA))
emit(b'\xff\x25' + struct.pack('<I', IAT_CREATEFILE))
for pos, target in fix:
    pre[pos] = (labels[target] - (pos + 1)) & 0xFF

emitp(b'\x83\xf8\xff')
jccp(0x75, 'ret')
emitp(b'\xc6\x05' + struct.pack('<I', BASE + FLAG_RVA) + b'\x01')
emitp(b'\xb9' + struct.pack('<I', 0x08000000))
labelp('delay')
emitp(b'\x49\x75\xfd')
labelp('ret')
rel = RET_VA - (BASE + POST_RVA + len(post) + 5)
emitp(b'\xe9' + struct.pack('<i', rel))
for pos, target in fix_p.items():
    post[pos] = (labels_p[target] - (pos + 1)) & 0xFF

# write CreateFileW caves and patch the call site
cave_off, _ = rva_off(CAVE_RVA)
post_off, _ = rva_off(POST_RVA)
d[cave_off:cave_off + len(pre)] = pre
d[post_off:post_off + len(post)] = post
call_off, _ = rva_off(CALL_RVA)
rel = (BASE + CAVE_RVA) - (BASE + CALL_RVA + 5)
d[call_off:call_off + 6] = b'\xe8' + struct.pack('<i', rel) + b'\x90'

# write the other hooks
for name, pre_rva, post_rva, real_rva, ret_rva, slot, fail_zero in HOOKS:
    p, q = build_hook(pre_rva, post_rva, real_rva, ret_rva, fail_zero)
    po, _ = rva_off(pre_rva)
    qo, _ = rva_off(post_rva)
    d[po:po + len(p)] = p
    d[qo:qo + len(q)] = q
    print('%s hook: cave %#x post %#x real %#x ret %#x slot %#x fail_zero=%s'
          % (name, BASE + pre_rva, BASE + post_rva, BASE + real_rva,
             BASE + ret_rva, slot, fail_zero))

# zero flag + buffer
d[rva_off(FLAG_RVA)[0]] = 0
d[buf_off:buf_off + BUF_SIZE] = b'\0' * BUF_SIZE

open(DST, 'wb').write(d)
print('written', DST)
print('CreateFileW: call %#x -> cave %#x, post %#x, buffer %#x'
      % (BASE + CALL_RVA, BASE + CAVE_RVA, BASE + POST_RVA, BASE + BUF_RVA))
