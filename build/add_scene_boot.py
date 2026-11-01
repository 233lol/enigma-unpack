#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""Make the rebuilt exe supply the scene files the game expects in %TEMP%.

Why: the game's `Scene:Init` opens `<GetTempPathA()>\scene1.hsp` (an absolute
path).  In the original, Enigma's virtual file system materializes those files
there from inside the packed exe.  An unpacked build has no such VFS, so the
open fails with WinError 2 -> HspError 12 (FILE_IO) right when the prologue
starts, even though the same scenes are present in data.dpm.

This step appends a `.scn` section containing a small startup stub plus the
two validated scene files.  It repoints AddressOfEntryPoint at the stub; the
stub writes `<temp>\scene1.hsp` and `<temp>\scene2.hsp`, then jumps to the old
entry point.  The image is not relocated (DllCharacteristics has no
DYNAMIC_BASE), so absolute addressing is safe.

usage: python add_scene_boot.py <exe> <scene1.hsp> [scene2.hsp]
"""
import os
import struct
import sys

BASE = 0x400000
# IAT slots already resolved by the loader before the entry point runs.
SLOT_GETTEMPPATH = 0x43C150
SLOT_MULTIBYTETOWIDECHAR = 0x43C198
SLOT_CREATEFILEW = 0x43C0CC
SLOT_WRITEFILE = 0x43C0F0
SLOT_CLOSEHANDLE = 0x43C154

TEMP_SIZE = 0x104
WBUF_CHARS = 0x104


class Asm:
    def __init__(self):
        self.b = bytearray()
        self.labels = {}
        self.fixups = []                 # (kind, pos, name)

    def emit(self, data):
        self.b += data

    def label(self, name):
        self.labels[name] = len(self.b)

    def abs_addr(self, name):
        self.fixups.append(('abs', len(self.b), name))
        self.emit(b'\0\0\0\0')

    def rel32(self, opcode, label):
        self.emit(opcode)
        self.fixups.append(('rel', len(self.b), label))
        self.emit(b'\0\0\0\0')

    def jmp(self, label):
        self.rel32(b'\xe9', label)

    def jz(self, label):
        self.rel32(b'\x0f\x84', label)

    def push(self, v):
        if -0x80 <= v <= 0x7f:
            self.emit(b'\x6a' + struct.pack('<b', v))
        else:
            self.emit(b'\x68' + struct.pack('<I', v & 0xFFFFFFFF))

    def push_addr(self, name):
        self.emit(b'\x68')
        self.abs_addr(name)

    def call_iat(self, va):
        self.emit(b'\xff\x15' + struct.pack('<I', va))

    def add_esp(self, n):
        self.emit(b'\x83\xc4' + struct.pack('<b', n))

    def mov_esi(self, name):
        self.emit(b'\xbe')
        self.abs_addr(name)

    def mov_ecx(self, v):
        self.emit(b'\xb9' + struct.pack('<I', v))


def build_stub(scenes):
    a = Asm()
    a.emit(b'\x9c')                              # pushfd
    a.emit(b'\x60')                              # pushad
    a.emit(b'\xfc')                              # cld

    a.push_addr('temp')                          # lpBuffer
    a.push(TEMP_SIZE)                            # nBufferLength
    a.call_iat(SLOT_GETTEMPPATH)
    a.emit(b'\x85\xc0')                          # test eax,eax
    a.jz('done')

    # MultiByteToWideChar(CP_ACP, 0, temp, -1, wbuf, 260)
    a.push(WBUF_CHARS)
    a.push_addr('wbuf')
    a.push(-1)
    a.push_addr('temp')
    a.push(0)
    a.push(0)
    a.call_iat(SLOT_MULTIBYTETOWIDECHAR)
    a.emit(b'\x85\xc0')
    a.jz('done')
    # MultiByteToWideChar returns chars including the terminating NUL; keep the
    # prefix length (without NUL) so each filename can overwrite the previous.
    a.emit(b'\x48')                              # dec eax
    a.emit(b'\xa3')
    a.abs_addr('plen')                           # mov [plen],eax

    for idx, (wname, blob, size) in enumerate(scenes, 1):
        nxt = 'next%d' % idx
        a.emit(b'\x8b\x0d')
        a.abs_addr('plen')                       # mov ecx,[plen]
        a.emit(b'\xbf')
        a.abs_addr('wbuf')                       # mov edi,wbuf
        a.emit(b'\x8d\x3c\x4f')                  # lea edi,[edi+ecx*2]
        a.mov_esi('wname%d' % idx)
        a.mov_ecx(len(wname) // 2)               # chars incl. terminator
        a.emit(b'\xf3\xa5')                      # rep movsw

        a.push(0)                                # hTemplate
        a.push(0x80)                             # FILE_ATTRIBUTE_NORMAL
        a.push(2)                                # CREATE_ALWAYS
        a.push(0)                                # lpSecurityAttributes
        a.push(0)                                # dwShareMode
        a.push(0x40000000)                       # GENERIC_WRITE
        a.push_addr('wbuf')
        a.call_iat(SLOT_CREATEFILEW)
        a.emit(b'\x83\xf8\xff')                  # cmp eax,-1
        a.jz(nxt)
        a.emit(b'\x8b\xd8')                      # mov ebx,eax

        a.push(0)
        a.push_addr('written')
        a.push(size)
        a.push_addr('blob%d' % idx)
        a.emit(b'\x53')                          # push ebx
        a.call_iat(SLOT_WRITEFILE)
        a.emit(b'\x53')                          # push ebx
        a.call_iat(SLOT_CLOSEHANDLE)
        a.label(nxt)

    a.label('done')
    a.emit(b'\x61')                              # popad
    a.emit(b'\x9d')                              # popfd
    a.jmp('old_entry')
    return a


def main():
    if len(sys.argv) < 3:
        sys.exit(__doc__.strip().splitlines()[-1])
    exe = os.path.abspath(sys.argv[1])
    srcs = [os.path.abspath(p) for p in sys.argv[2:] if os.path.isfile(p)]
    if not srcs:
        sys.exit('no scene files')

    d = bytearray(open(exe, 'rb').read())
    e = struct.unpack_from('<I', d, 0x3C)[0]
    nsec = struct.unpack_from('<H', d, e + 6)[0]
    optsize = struct.unpack_from('<H', d, e + 20)[0]
    opt = e + 24
    secalign = struct.unpack_from('<I', d, opt + 32)[0]
    filealign = struct.unpack_from('<I', d, opt + 36)[0]
    sizeimg = struct.unpack_from('<I', d, opt + 56)[0]
    entry = struct.unpack_from('<I', d, opt + 16)[0]

    scenes = []
    for p in srcs[:2]:
        name = os.path.basename(p)
        blob = open(p, 'rb').read()
        scenes.append((name.encode('utf-16le') + b'\0\0', blob, len(blob)))
    while len(scenes) < 2:
        scenes.append(scenes[0])

    a = build_stub(scenes)
    code_len = (len(a.b) + 3) & ~3
    a.b += b'\0' * (code_len - len(a.b))

    off = code_len
    data = {}

    def place(name, size, align=4):
        nonlocal off
        off = (off + align - 1) & ~(align - 1)
        data[name] = off
        off += size
        return data[name]

    place('temp', TEMP_SIZE, 4)
    place('wbuf', WBUF_CHARS * 2, 4)
    place('written', 4, 4)
    place('plen', 4, 4)
    for i, (wname, blob, size) in enumerate(scenes, 1):
        place('wname%d' % i, len(wname), 2)
        place('blob%d' % i, len(blob), 4)
    vsize = (off + 0xFFF) & ~0xFFF

    new_rva = (sizeimg + secalign - 1) // secalign * secalign
    sec_va = BASE + new_rva
    old_entry_va = BASE + entry

    for kind, pos, name in a.fixups:
        if kind == 'abs':
            struct.pack_into('<I', a.b, pos, sec_va + data[name])
        elif kind == 'rel':
            if name == 'old_entry':
                target = old_entry_va
            else:
                target = sec_va + a.labels[name]
            rel = target - (sec_va + pos + 4)
            struct.pack_into('<i', a.b, pos, rel)

    # section image: code + data
    img = bytearray(vsize)
    img[:len(a.b)] = a.b
    for i, (wname, blob, size) in enumerate(scenes, 1):
        img[data['wname%d' % i]:data['wname%d' % i] + len(wname)] = wname
        img[data['blob%d' % i]:data['blob%d' % i] + len(blob)] = blob

    raw_off = (len(d) + filealign - 1) // filealign * filealign
    if len(d) < raw_off:
        d += b'\0' * (raw_off - len(d))
    raw_size = (vsize + filealign - 1) // filealign * filealign
    d += img
    d += b'\0' * (raw_size - len(img))

    sec_off = opt + optsize + nsec * 40
    d[sec_off:sec_off + 8] = b'.scn\0\0\0\0'
    struct.pack_into('<I', d, sec_off + 8, vsize)
    struct.pack_into('<I', d, sec_off + 12, new_rva)
    struct.pack_into('<I', d, sec_off + 16, raw_size)
    struct.pack_into('<I', d, sec_off + 20, raw_off)
    struct.pack_into('<I', d, sec_off + 36, 0xE0000040)      # RWX

    struct.pack_into('<H', d, e + 6, nsec + 1)
    struct.pack_into('<I', d, opt + 56, (new_rva + vsize + secalign - 1)
                     // secalign * secalign)
    struct.pack_into('<I', d, opt + 16, new_rva)

    open(exe, 'wb').write(d)
    print('%s' % exe)
    print('  .scn @ rva %#x (%d bytes), entry %#x -> stub, then %#x'
          % (new_rva, vsize, entry, old_entry_va))
    for i, (wname, blob, size) in enumerate(scenes, 1):
        print('  scene%d: %s (%d bytes) -> %%TEMP%%\\%s'
              % (i, wname.decode('utf-16le').rstrip('\0'), size,
                 wname.decode('utf-16le').rstrip('\0')))
    return 0


if __name__ == '__main__':
    sys.exit(main())
