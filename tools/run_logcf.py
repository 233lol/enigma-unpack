import os
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
exe_name = sys.argv[2] if len(sys.argv) > 2 else 'unenigma_logcf.exe'
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
captured = []
stop = threading.Event()


def poll():
    last = None
    while not stop.is_set() and p.poll() is None:
        try:
            b = mem.read(0x454C00, 0x100)
            if b and b != last:
                last = b
                captured.append(b)
        except Exception:
            break
        time.sleep(0.01)


th = threading.Thread(target=poll, daemon=True)
th.start()


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


focus()
time.sleep(0.8)
u.SetCursorPos(400, 300)
time.sleep(0.2)
u.mouse_event(0x0002, 0, 0, 0, 0)
time.sleep(0.05)
u.mouse_event(0x0004, 0, 0, 0, 0)
time.sleep(0.6)


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
print('--- CreateFileW paths (last 80) ---')
for b in captured[-80:]:
    w = b.decode('utf-16le', 'ignore').split('\0')[0]
    a = b.split(b'\0')[0]
    print(repr(w), '|', repr(a))
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
