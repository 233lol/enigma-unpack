import sys

sys.path[:0] = ['extract', '.']
import winmem
import extract_script

exe_name = sys.argv[1]
out = sys.argv[2]
pid = winmem.find_pid(exe_name)
if not pid:
    print('no pid')
    sys.exit(1)
m = winmem.Mem(pid)
va, allsize = extract_script.scan_hsp3(m, print)
if va:
    blob = m.read(va, allsize)
    open(out, 'wb').write(blob)
    print('wrote', out, len(blob), 'va', hex(va))
m.close()
