import os
import struct
import subprocess
import sys
import time
import ctypes

sys.path[:0] = ['extract', '.']
import paths
import winmem
from enigma_launch import enum_windows, is_game_window

gdir = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else 'test')
exe_name = sys.argv[2] if len(sys.argv) > 2 else 'unenigma_single.exe'
delay = float(sys.argv[3]) if len(sys.argv) > 3 else 1.0
exe = os.path.join(gdir, exe_name)
u = ctypes.windll.user32

subprocess.run(['taskkill', '/F', '/IM', exe_name], capture_output=True)
time.sleep(0.6)
env = os.environ.copy()
for k in ('TEMP', 'TMP', 'TMPDIR'):
    env[k] = paths.TMP
p = subprocess.Popen([exe], cwd=gdir, env=env)
t0 = time.time()
h = None
while time.time() - t0 < 25:
    for w in enum_windows():
        if is_game_window(w):
            h = w['hwnd']
            break
    if h:
        break
    if p.poll() is not None:
        print('exited early', p.poll())
        sys.exit(1)
    time.sleep(0.1)
if not h:
    print('no window')
    sys.exit(1)

pid = winmem.find_pid(exe_name)
mem = winmem.Mem(pid)
k32 = ctypes.WinDLL('kernel32', use_last_error=True)
k32.VirtualAllocEx.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t,
                               ctypes.c_ulong, ctypes.c_ulong]
k32.VirtualAllocEx.restype = ctypes.c_void_p
base = k32.VirtualAllocEx(mem.h, None, 0x1000, 0x3000, 0x40)
print('shim base', hex(base))
p32 = lambda x: struct.pack('<I', x & 0xFFFFFFFF)
FAKE = base + 0x400
FFA = base + 0x000
FFEA = base + 0x040
FNFA = base + 0x080
FC = base + 0x0C0
# FindFirstFileA(path, data) -> fake handle; ret 8
mem.write(FFA, b'\xb8' + p32(FAKE) + b'\xc2\x08\x00')
# FindFirstFileExA(path, level, data, flags, filter, ...) -> fake; ret 24
mem.write(FFEA, b'\xb8' + p32(FAKE) + b'\xc2\x18\x00')
# FindNextFileA(handle, data) -> 0; ret 8
mem.write(FNFA, b'\x31\xc0\xc2\x08\x00')
# FindClose(handle) -> 1; ret 4
mem.write(FC, b'\xb8\x01\x00\x00\x00\xc2\x04\x00')
mem.write(FAKE, struct.pack('<I', 0xDEADBEEF))
mem.write(0x43C138, p32(FFA))
mem.write(0x43C0B8, p32(FFEA))
mem.write(0x43C134, p32(FNFA))
mem.write(0x43C144, p32(FC))
print('empty-dir shims installed')

u.ShowWindow(h, 9)
u.SetWindowPos(h, -1, 0, 0, 1024, 900, 0x0040)
u.SetForegroundWindow(h)
time.sleep(0.8)
u.SetCursorPos(400, 300)
time.sleep(0.2)
u.mouse_event(0x0002, 0, 0, 0, 0)
time.sleep(0.05)
u.mouse_event(0x0004, 0, 0, 0, 0)
time.sleep(0.6)


def focus():
    u.SetWindowPos(h, -1, 0, 0, 1024, 900, 0x0040)
    u.SetForegroundWindow(h)
    time.sleep(0.15)


def key(vk, wait=None):
    focus()
    u.keybd_event(vk, 0, 0, 0)
    time.sleep(0.12)
    u.keybd_event(vk, 0, 2, 0)
    time.sleep(delay if wait is None else wait)


def char(ch):
    key(ord(ch.upper()))


for _ in range(9):
    char('b')
char('a')
char('b')
char('a')
char('b')
key(0x0D)
char('a')
key(0x1B)
char('a')
for ch in 'test':
    char(ch)
key(0x0D, 6.0)

print('done; alive=', p.poll() is None, 'code=', p.poll(), 'pid=', p.pid)
err = os.path.join(gdir, 'error.txt')
if os.path.isfile(err):
    print('--- error.txt ---')
    print(open(err, 'rb').read().decode('gbk', 'replace'))
if os.environ.get('KEEP') != '1':
    try:
        p.kill()
    except Exception:
        pass
    subprocess.run(['taskkill', '/F', '/IM', exe_name], capture_output=True)
mem.close()
