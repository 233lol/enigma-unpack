import os
import sys
import time

sys.path[:0] = ['extract', '.']
import paths
import winmem
import enigma_launch

gdir = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else 'test')
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
names = [
    'start.ax', 'start.hsp', 'main.ax', 'main.hsp', 'system.ax', 'system.hsp',
    'scene1.hsp', 'scene2.hsp', 'data.dpm', 'data.s2', 'cdata.s2', 'cdatan.s2',
    'cdatan1.s2', 'cdatan2.s2', 'npc.s2', 'userNpc', 'userNpc.s2', 'item.s2',
    'init.s2', 'init.ax', 'boot.ax', 'boot.s2', 'start.s2', 'main.s2',
    'system.s2', 'scene.s2', 'scenes.s2', 'script.s2', 'script.ax',
    'hsp3.s2',
]
for name in names:
    arg = r.alloc(0x400)
    try:
        r.write(arg, name.encode('mbcs') + b'\x00')
        size = r.call(0x401280, [arg])
        if size not in (None, 0xFFFFFFFF):
            print('%-20s %d' % (name, size))
    finally:
        r.free(arg)
r.close()
m.close()
winmem.kill('crackme.exe')
