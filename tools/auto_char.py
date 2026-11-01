import os
import subprocess
import sys
import time
import ctypes

sys.path[:0] = ['extract', '.']
import paths
from enigma_launch import enum_windows, is_game_window

gdir = os.path.abspath(sys.argv[1])
name = sys.argv[2] if len(sys.argv) > 2 else 'unenigma_single.exe'
exe = os.path.join(gdir, name)
u = ctypes.windll.user32

# kill existing
subprocess.run(['taskkill', '/F', '/IM', name], capture_output=True)
time.sleep(0.5)
env = os.environ.copy()
for k in ('TEMP', 'TMP', 'TMPDIR'):
    env[k] = paths.TMP
p = subprocess.Popen([exe], cwd=gdir, env=env)
t0 = time.time()
h = None
while time.time() - t0 < 20:
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
time.sleep(0.5)
u.SetCursorPos(400, 300)
time.sleep(0.2)
u.mouse_event(0x0002, 0, 0, 0, 0)
time.sleep(0.05)
u.mouse_event(0x0004, 0, 0, 0, 0)
time.sleep(0.5)


def focus():
    u.SetWindowPos(h, -1, 0, 0, 1024, 900, 0x0040)
    u.SetForegroundWindow(h)
    time.sleep(0.1)


def key(vk, wait=0.5):
    focus()
    u.keybd_event(vk, 0, 0, 0)
    time.sleep(0.12)
    u.keybd_event(vk, 0, 2, 0)
    time.sleep(wait)


def text(s):
    focus()
    for ch in s:
        vk = ord(ch.upper())
        u.keybd_event(vk, 0, 0, 0)
        time.sleep(0.05)
        u.keybd_event(vk, 0, 2, 0)
        time.sleep(0.05)


VK_DOWN, VK_UP, VK_SPACE, VK_ENTER, VK_ESC = 0x28, 0x26, 0x20, 0x0D, 0x1B
VK_X, VK_C, VK_N, VK_SHIFT = 0x58, 0x43, 0x4E, 0x10

# title -> new game
key(VK_DOWN); key(VK_SPACE, 1.5)
# alias -> background
key(VK_X, 0.3); key(VK_C, 1.5)
# background -> race
key(VK_SPACE, 1.5)
# race -> change race name? -> No
key(VK_SPACE, 0.8); key(VK_DOWN); key(VK_SPACE, 1.2)
# gender
key(VK_SPACE, 1.2)
# class
key(VK_SPACE, 0.8); key(VK_DOWN); key(VK_SPACE, 1.2)
# talent: pick with letter n
key(VK_N, 1.5)
# ability values -> traits
key(VK_SPACE, 1.5)
# traits: switch to selectable list, select 3
key(VK_SPACE, 0.5)
key(VK_DOWN); key(VK_SPACE, 0.5)
key(VK_DOWN); key(VK_SPACE, 0.5)
key(VK_DOWN); key(VK_SPACE, 1.0)
# portrait
key(VK_SPACE, 1.2)
# mode
key(VK_SPACE, 1.5)
# final summary -> confirmation
key(VK_ESC, 1.0)
key(VK_SPACE, 1.0)
# name input
text('test')
key(VK_ENTER, 6.0)

# screenshot
# (caller can screenshot)
print('done; alive=', p.poll() is None, 'pid=', p.pid)
err = os.path.join(gdir, 'error.txt')
if os.path.isfile(err):
    print('--- error.txt ---')
    print(open(err, 'rb').read().decode('gbk', 'replace'))
if os.environ.get('KEEP') == '1':
    print('KEEP=1: leaving game running')
else:
    try:
        p.kill()
    except Exception:
        pass
    subprocess.run(['taskkill', '/F', '/IM', name], capture_output=True)
