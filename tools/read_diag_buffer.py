import sys

sys.path.insert(0, 'extract')
import winmem

exe_name = sys.argv[1] if len(sys.argv) > 1 else 'unenigma_diag.exe'
pid = winmem.find_pid(exe_name)
if not pid:
    print('process not found:', exe_name)
    sys.exit(1)
m = winmem.Mem(pid)
flag = m.read(0x454DFF, 1)
buf = m.read(0x454E00, 0x200)
m.close()
if not buf:
    print('read failed')
    sys.exit(1)
print('pid', pid, 'flag', flag[0] if flag else None)
buf = buf.split(b'\0')[0]
print('pid', pid)
print('ANSI :', repr(buf))
for enc in ('mbcs', 'gbk', 'utf-8'):
    try:
        print('%-6s: %r' % (enc, buf.decode(enc)))
    except Exception as exc:
        print('%-6s: (decode failed) %s' % (enc, exc))
# wide string view (if the buffer was UTF-16, the first NUL will truncate above)
m = winmem.Mem(pid)
raw = m.read(0x454E00, 0x200)
m.close()
try:
    print('UTF-16:', repr(raw[:raw.find(b'\0\0') + 2].decode('utf-16le', 'replace')))
except Exception as exc:
    print('UTF-16: (failed)', exc)
