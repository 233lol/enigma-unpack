#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""Build the single-file unpacked program.

Appends a prebuilt DPM to the rebuilt exe and patches the HSPHED pack fields so
the runtime loads it from its own image ("packed exe" mode) instead of looking
for an external data.dpm.

usage: python build_singlefile.py <in.exe> <out.exe> <data.dpm>
"""
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
IN = os.path.abspath(sys.argv[1] if len(sys.argv) > 1
                     else os.path.join(HERE, '..', 'out', 'unenigma.exe'))
OUT = os.path.abspath(sys.argv[2] if len(sys.argv) > 2
                      else os.path.join(HERE, '..', 'out', 'unenigma_single.exe'))
DPM = os.path.abspath(sys.argv[3] if len(sys.argv) > 3
                      else os.path.join(HERE, '..', 'out', 'data.dpm'))
HSPHED_FILE_OFF = 0x4B48C            # optmes[] in .data (RVA 0x4C08C)

dpm = open(DPM, 'rb').read()
if dpm[:4] != b'DPMX':
    sys.exit('%s is not a DPM' % DPM)

exe = bytearray(open(IN, 'rb').read())
dpm_ofs = (len(exe) + 0xFFF) & ~0xFFF
checksum = sum(dpm) & 0xFFFF
print(f'dpm @ {dpm_ofs:#x} size {len(dpm):#x} checksum {checksum:#06x} '
      f'mode "{dpm_ofs - 0x10000}"')

# ---- patch HSPHED pack fields (see Hsp3::Reset / hsp3win_init) ------------
hed = bytearray(36)
txt = str(dpm_ofs - 0x10000).encode('ascii')
hed[9:9 + len(txt)] = txt
hed[17] = 0
hed[19] = ord('x'); struct.pack_into('<h', hed, 20, 800)
hed[22] = ord('y'); struct.pack_into('<h', hed, 23, 600)
hed[25] = ord('d'); struct.pack_into('<h', hed, 26, 0)
hed[28] = ord('s'); struct.pack_into('<H', hed, 29, checksum)
hed[31] = ord('k'); struct.pack_into('<I', hed, 32, 0)
exe[HSPHED_FILE_OFF:HSPHED_FILE_OFF + 36] = hed

if len(exe) < dpm_ofs:
    exe += b'\0' * (dpm_ofs - len(exe))
exe += dpm
open(OUT, 'wb').write(exe)
print(f'written {OUT}  {len(exe):,} bytes')
