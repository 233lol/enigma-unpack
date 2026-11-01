import os
import sys
import time
import ctypes

sys.path[:0] = ['extract', '.']
import paths
import winmem
import enigma_launch
from enigma_launch import enum_windows, is_game_window

gdir = os.path.abspath(sys.argv[1])
exe_name = sys.argv[2] if len(sys.argv) > 2 else 'crackme.exe'
delay = float(sys.argv[3]) if len(sys.argv) > 3 else 1.0
exe = os.path.join(gdir, exe_name)
u = ctypes.windll.user32

paths.use_local_temp()
winmem.kill(exe_name)
time.sleep(0.6)
rc = enigma_launch.run(exe, 'player', enigma_launch.DEFAULT_WAIT)
print('launcher rc', rc)
time.sleep(1.0)
h = None
for w in enum_windows():
    if is_game_window(w):
        h = w['hwnd']
        break
if not h:
    print('no game window')
    sys.exit(1)
u.ShowWindow(h, 9)
u.SetWindowPos(h, -1, 0, 0, 1024, 900, 0x0040)
u.SetForegroundWindow(h)
time.sleep(1.5)
u.SetCursorPos(400, 300)
time.sleep(0.2)
u.mouse_event(0x0002, 0, 0, 0, 0)
time.sleep(0.05)
u.mouse_event(0x0004, 0, 0, 0, 0)
time.sleep(1.0)


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
if os.environ.get('STOP_BEFORE_ENTER') == '1':
    print('stopped before final enter; game left running')
else:
    key(0x0D, 6.0)

print('alive=', winmem.find_pid(exe_name) is not None)
err = os.path.join(gdir, 'error.txt')
if os.path.isfile(err):
    print('--- error.txt ---')
    print(open(err, 'rb').read().decode('gbk', 'replace'))
if os.environ.get('KEEP') == '1' or os.environ.get('STOP_BEFORE_ENTER') == '1':
    print('keeping game running')
else:
    winmem.kill(exe_name)
