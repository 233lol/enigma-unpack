import os
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
u.ShowWindow(h, 9)
u.SetWindowPos(h, -1, 0, 0, 1024, 900, 0x0040)
u.SetForegroundWindow(h)
time.sleep(1.0)
u.SetCursorPos(400, 300)
time.sleep(0.2)
u.mouse_event(0x0002, 0, 0, 0, 0)
time.sleep(0.05)
u.mouse_event(0x0004, 0, 0, 0, 0)
time.sleep(0.6)


def key(vk, wait=1.2):
    u.SetWindowPos(h, -1, 0, 0, 1024, 900, 0x0040)
    u.SetForegroundWindow(h)
    time.sleep(0.15)
    u.keybd_event(vk, 0, 0, 0)
    time.sleep(0.12)
    u.keybd_event(vk, 0, 2, 0)
    time.sleep(wait)


# title -> Restore an adventurer (a)
key(0x41, 2.0)
# save list -> select first entry
key(0x41, 2.0)
# confirm / load
key(0x20, 5.0)
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
