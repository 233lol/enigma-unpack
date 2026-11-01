import os
import struct
import subprocess
import sys
import threading
import time
import ctypes

sys.path[:0] = ['extract', '.']
import paths
import winmem
from enigma_launch import enum_windows, is_game_window

gdir = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else 'test')
exe_name = sys.argv[2] if len(sys.argv) > 2 else 'unenigma_single.exe'
delay = float(sys.argv[3]) if len(sys.argv) > 3 else 1.2
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
p32 = lambda x: struct.pack('<I', x & 0xFFFFFFFF)
REAL = base + 0x100
SHIM = base + 0x000
BUF = base + 0x200
real_mkdir = struct.unpack('<I', mem.read(0x43C0C0, 4))[0]
mem.write(REAL, p32(real_mkdir))
code = bytearray()
code += b'\x60'                          # pushad
code += b'\x8b\x74\x24\x24'              # mov esi,[esp+0x24]
code += b'\xbf' + p32(BUF)               # mov edi,buf
code += b'\xb9\x80\x00\x00\x00'          # mov ecx,0x80
code += b'\xf3\xa4'                      # rep movsb
code += b'\x61'                          # popad
code += b'\xff\x25' + p32(REAL)          # jmp [real]
mem.write(SHIM, bytes(code))
mem.write(0x43C0C0, p32(SHIM))
print('CreateDirectoryW logger installed, real=%#x' % real_mkdir)

captured = []
stop = threading.Event()


def poll():
    last = None
    while not stop.is_set() and p.poll() is None:
        try:
            b = mem.read(BUF, 0x80)
            if b and b != last:
                last = b
                captured.append(b)
        except Exception:
            break
        time.sleep(0.01)


th = threading.Thread(target=poll, daemon=True)
th.start()

# focus
fg = u.GetForegroundWindow()
fg_tid = u.GetWindowThreadProcessId(fg, None)
cur_tid = ctypes.windll.kernel32.GetCurrentThreadId()
u.AttachThreadInput(cur_tid, fg_tid, True)
u.ShowWindow(h, 9)
u.SetWindowPos(h, -1, 0, 0, 1024, 900, 0x0040)
u.SetForegroundWindow(h)
u.SetFocus(h)
u.AttachThreadInput(cur_tid, fg_tid, False)
time.sleep(1.0)
u.SetCursorPos(400, 300)
time.sleep(0.2)
u.mouse_event(0x0002, 0, 0, 0, 0)
time.sleep(0.05)
u.mouse_event(0x0004, 0, 0, 0, 0)
time.sleep(0.6)


def focus():
    fg = u.GetForegroundWindow()
    fg_tid = u.GetWindowThreadProcessId(fg, None)
    cur_tid = ctypes.windll.kernel32.GetCurrentThreadId()
    u.AttachThreadInput(cur_tid, fg_tid, True)
    u.SetWindowPos(h, -1, 0, 0, 1024, 900, 0x0040)
    u.SetForegroundWindow(h)
    u.SetFocus(h)
    u.AttachThreadInput(cur_tid, fg_tid, False)
    time.sleep(0.12)


def key(vk, wait=None):
    focus()
    u.keybd_event(vk, 0, 0, 0)
    time.sleep(0.1)
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

stop.set()
th.join(timeout=1.0)
print('done; alive=', p.poll() is None, 'code=', p.poll())
print('--- CreateDirectoryW paths ---')
for b in captured:
    a = b.split(b'\0')[0]
    w = b.decode('utf-16le', 'ignore').split('\0')[0]
    print('ANSI', repr(a), '| WIDE', repr(w))
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
