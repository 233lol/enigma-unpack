#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Restore WinMain in the rebuilt enigma exe.

Enigma virtualized exactly one function in the original HSP3 runtime image:
WinMain at VA 0x41AFF0 (it was replaced by `call <Enigma VM>` + bytecode).
Everything else in the image is the untouched original code.

HSP3's own source (src/hsp3/win32gui/main.cpp) has:

    int APIENTRY WinMain(HINSTANCE hInstance, HINSTANCE, LPSTR, int)
    {
        int res = hsp3win_init(hInstance, NULL);
        if (res == 0) res = hsp3win_exec();
        return res;
    }

In this binary (identified by cross references / optmes access):
    hsp3win_init = 0x414C70
    hsp3win_exec = 0x414A70

This script writes an equivalent native WinMain at 0x41AFF0.
"""
import os
import struct
import sys

BASE = 0x400000
WINMAIN_RVA = 0x1AFF0
HSP3WIN_INIT = 0x414C70
HSP3WIN_EXEC = 0x414A70


def build_stub(start_va):
    code = bytearray()
    code += b'\x55'                       # push ebp
    code += b'\x8b\xec'                   # mov ebp, esp
    code += b'\x6a\x00'                   # push 0            (startfile = NULL)
    code += b'\xff\x75\x08'               # push [ebp+8]      (hInstance)
    here = start_va + len(code) + 5
    code += b'\xe8' + struct.pack('<i', HSP3WIN_INIT - here)
    code += b'\x83\xc4\x08'               # add esp, 8
    code += b'\x85\xc0'                   # test eax, eax
    here = start_va + len(code) + 2
    code += b'\x75' + struct.pack('<b', (start_va + len(code) + 2 + 5) - here)
    here = start_va + len(code) + 5
    code += b'\xe8' + struct.pack('<i', HSP3WIN_EXEC - here)
    code += b'\x5d'                       # pop ebp
    code += b'\xc2\x10\x00'               # ret 0x10
    return bytes(code)


def rva_to_off(data, rva):
    e = struct.unpack_from('<I', data, 0x3C)[0]
    n = struct.unpack_from('<H', data, e + 6)[0]
    optsize = struct.unpack_from('<H', data, e + 20)[0]
    opt = e + 24
    sec = opt + optsize
    for i in range(n):
        s = sec + i * 40
        vs, va, rs, ro = struct.unpack_from('<IIII', data, s + 8)
        if va <= rva < va + max(vs, rs):
            return ro + (rva - va)
    raise ValueError(f'RVA {rva:#x} not in any section')


def main():
    exe = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else
                          os.path.join(HERE, '..', 'out', 'unenigma.exe'))
    d = bytearray(open(exe, 'rb').read())
    off = rva_to_off(d, WINMAIN_RVA)
    stub = build_stub(BASE + WINMAIN_RVA)
    old = bytes(d[off:off + len(stub)])
    d[off:off + len(stub)] = stub
    open(exe, 'wb').write(d)
    print(f'{exe}')
    print(f'  WinMain {BASE + WINMAIN_RVA:#x} (file {off:#x})')
    print(f'  old: {old.hex()}')
    print(f'  new: {stub.hex()}  ({len(stub)} bytes)')
    print(f'  init {HSP3WIN_INIT:#x}  exec {HSP3WIN_EXEC:#x}')


if __name__ == '__main__':
    main()
