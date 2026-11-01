import sys

sys.path.insert(0, 'extract')
import winmem

exe_name = sys.argv[1]
out = sys.argv[2]
pid = winmem.find_pid(exe_name)
if not pid:
    print('process not found:', exe_name)
    sys.exit(1)
m = winmem.Mem(pid)
img = m.read(0x400000, 0x53000)
m.close()
if not img:
    print('read failed')
    sys.exit(1)
open(out, 'wb').write(img)
print('wrote', out, len(img), 'pid', pid)
