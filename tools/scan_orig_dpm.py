import os
import struct
import sys
import time

sys.path[:0] = ['extract', '.']
import paths
import winmem
import enigma_launch

exe = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else 'test/crackme.exe')
name = os.path.basename(exe)
paths.use_local_temp()
winmem.kill(name)
time.sleep(0.6)
rc = enigma_launch.run(exe, 'player', enigma_launch.DEFAULT_WAIT)
print('launcher rc', rc)
pid = winmem.find_pid(name)
if not pid:
    print('no pid')
    sys.exit(1)
mem = winmem.Mem(pid)
outdir = os.path.join('tmp', 'orig_dpm')
os.makedirs(outdir, exist_ok=True)
found = 0
for base, size, data in mem.iter_readable():
    for magic in (b'DPMX',):
        i = 0
        while True:
            i = data.find(magic, i)
            if i < 0:
                break
            va = base + i
            hdr = mem.read(va, 16)
            if hdr and len(hdr) == 16:
                optr, dent, namsize = struct.unpack_from('<III', hdr, 4)
                if 16 <= optr < 0x20000 and 0 < dent < 200:
                    total = optr
                    entries = []
                    ok = True
                    for k in range(dent):
                        e = mem.read(va + 16 + k * 32, 32)
                        if not e or len(e) < 32:
                            ok = False
                            break
                        nm = e[:16].split(b'\0')[0]
                        flags, key, off, sz = struct.unpack_from('<IIII', e, 16)
                        entries.append((nm, off, sz))
                        total = max(total, optr + off + sz)
                    if ok and total < 0x2000000:
                        blob = mem.read(va, total)
                        if blob and blob[:4] == b'DPMX':
                            print('DPMX at %#x dent=%d total=%d' % (va, dent, total))
                            for nm, off, sz in entries[:20]:
                                print('   ', nm, off, sz)
                            open(os.path.join(outdir, 'dpm_%x.bin' % va), 'wb').write(blob)
                            found += 1
            i += 1
print('found', found)
if os.environ.get('KEEP') != '1':
    winmem.kill(name)
