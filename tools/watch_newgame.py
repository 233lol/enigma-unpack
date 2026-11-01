import os
import sys
import threading
import time
import ctypes

sys.path[:0] = ['extract', '.']
import paths
import winmem
import enigma_launch
from enigma_launch import enum_windows, is_game_window

gdir = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else 'test')
exe_name = sys.argv[2] if len(sys.argv) > 2 else 'crackme.exe'
delay = float(sys.argv[3]) if len(sys.argv) > 3 else 0.9
exe = os.path.join(gdir, exe_name)
name = sys.argv[4] if len(sys.argv) > 4 else 'test'
u = ctypes.windll.user32

paths.use_local_temp()
winmem.kill(exe_name)
time.sleep(0.6)
if exe_name == 'crackme.exe':
    rc = enigma_launch.run(exe, 'player', enigma_launch.DEFAULT_WAIT)
    print('launcher rc', rc)
    p = None
else:
    env = os.environ.copy()
    for k in ('TEMP', 'TMP', 'TMPDIR'):
        env[k] = paths.TMP
    p = __import__('subprocess').Popen([exe], cwd=gdir, env=env)

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

# filesystem watcher
events = []
stop = threading.Event()
save = os.path.join(gdir, 'save')
seen = set()
t_start = time.time()


def snap():
    try:
        return set(os.listdir(save))
    except OSError:
        return set()


seen = snap()


def watch():
    global seen
    while not stop.is_set():
        cur = snap()
        for n in cur - seen:
            events.append((round(time.time() - t_start, 2), n))
        seen = cur
        time.sleep(0.02)


th = threading.Thread(target=watch, daemon=True)
th.start()

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
for ch in name:
    char(ch)
key(0x0D, 8.0)

time.sleep(1.0)
stop.set()
th.join(timeout=1)
print('--- save dir changes ---')
for t, n in events:
    print(t, n)
print('alive=', winmem.find_pid(exe_name) is not None)
print('--- save listing ---')
for n in sorted(snap()):
    print('  ', n)
err = os.path.join(gdir, 'error.txt')
if os.path.isfile(err):
    print('--- error.txt ---')
    print(open(err, 'rb').read().decode('gbk', 'replace')[:800])
if os.environ.get('KEEP') == '1':
    print('keeping game running')
else:
    if p is not None:
        p.kill()
    winmem.kill(exe_name)
