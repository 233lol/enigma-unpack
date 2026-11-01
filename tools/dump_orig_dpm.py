import os
import shutil
import struct
import sys
import time

sys.path[:0] = ['extract', '.']
import paths
import winmem
import enigma_launch

gdir = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else 'test')
disk = os.path.join(gdir, 'data.dpm')
bak = disk + '.diagbak'
if os.path.isfile(disk):
    shutil.move(disk, bak)
    print('moved disk data.dpm aside')
try:
    exe = os.path.join(gdir, 'crackme.exe')
    paths.use_local_temp()
    winmem.kill('crackme.exe')
    time.sleep(0.6)
    rc = enigma_launch.run(exe, 'player', enigma_launch.DEFAULT_WAIT)
    print('launcher rc', rc)
    pid = winmem.find_pid('crackme.exe')
    if not pid:
        print('no pid')
        sys.exit(1)
    m = winmem.Mem(pid)
    r = winmem.Remote(m)
    for path in ('data.dpm', os.path.join(gdir, 'data.dpm')):
        arg = r.alloc(0x400)
        try:
            r.write(arg, path.encode('mbcs') + b'\x00')
            size = r.call(0x401280, [arg])
            print('path', path, 'size', size)
            if size and size != 0xFFFFFFFF and size < 0x2000000:
                buf = r.call(0x4018F0, [arg])
                print(' buf', hex(buf) if buf else None)
                if buf and buf < 0x80000000:
                    d = m.read(buf, min(size, 64))
                    print(' head', d[:16] if d else None)
                    if d and d[:4] == b'DPMX':
                        full = m.read(buf, size)
                        out = os.path.join('tmp', 'orig_dpm_virtual.bin')
                        open(out, 'wb').write(full)
                        print('saved', out, len(full))
                        break
        finally:
            r.free(arg)
    r.close()
    m.close()
finally:
    winmem.kill('crackme.exe')
    if os.path.isfile(bak):
        if os.path.isfile(disk):
            os.remove(disk)
        shutil.move(bak, disk)
        print('restored disk data.dpm')
