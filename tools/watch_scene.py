"""Watch <repo>\\tmp for scene1.hsp creation while entering the prologue."""
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

kind = sys.argv[1] if len(sys.argv) > 1 else 'rebuilt'
exe_name = sys.argv[2] if len(sys.argv) > 2 else (
    'crackme.exe' if kind == 'orig' else 'unenigma_single.exe')
delay = float(sys.argv[3]) if len(sys.argv) > 3 else 0.9
gdir = os.path.abspath('test')
exe = os.path.join(gdir, exe_name)
u = ctypes.windll.user32
paths.use_local_temp()

winmem.kill(exe_name)
time.sleep(0.5)
proc = None
if kind == 'orig':
    import enigma_launch
    enigma_launch.run(exe, 'player', enigma_launch.DEFAULT_WAIT)
else:
    env = os.environ.copy()
    for k in ('TEMP', 'TMP', 'TMPDIR'):
        env[k] = paths.TMP
    proc = subprocess.Popen([exe], cwd=gdir, env=env)

t0 = time.time()
h = None
while time.time() - t0 < 30:
    for w in enum_windows():
        if is_game_window(w):
            h = w['hwnd']
            break
    if h:
        break
    time.sleep(0.1)
if not h:
    print('no window')
    sys.exit(1)

events = []
stop = threading.Event()
target = os.path.join(paths.TMP, 'scene1.hsp')
last = None


def watch():
    global last
    while not stop.is_set():
        try:
            st = os.stat(target)
            cur = (st.st_size, round(st.st_mtime, 3))
        except OSError:
            cur = None
        if cur != last:
            events.append((round(time.time() - t0, 2), cur))
            last = cur
        time.sleep(0.004)


th = threading.Thread(target=watch, daemon=True)
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
    time.sleep(0.1)


def key(vk, wait=None):
    focus()
    u.keybd_event(vk, 0, 0, 0)
    time.sleep(0.1)
    u.keybd_event(vk, 0, 2, 0)
    time.sleep(delay if wait is None else wait)


def char(ch):
    key(ord(ch.upper()))


u.ShowWindow(h, 9)
u.SetWindowPos(h, -1, 0, 0, 1024, 900, 0x0040)
u.SetForegroundWindow(h)
time.sleep(1.2)
u.SetCursorPos(400, 300)
time.sleep(0.2)
u.mouse_event(0x0002, 0, 0, 0, 0)
time.sleep(0.05)
u.mouse_event(0x0004, 0, 0, 0, 0)
time.sleep(0.8)

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
for ch in 'zzq':
    char(ch)
key(0x0D, 6.0)
time.sleep(0.5)
stop.set()
th.join(timeout=1)

print('scene1.hsp events:')
for t, ev in events:
    print('  %.2f %s' % (t, ev))
print('alive=', winmem.find_pid(exe_name) is not None)
err = os.path.join(gdir, 'error.txt')
print('error.txt', os.path.getsize(err) if os.path.isfile(err) else None)
if proc is not None:
    try:
        proc.kill()
    except Exception:
        pass
winmem.kill(exe_name)
