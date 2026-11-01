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

gdir = os.path.abspath(sys.argv[1])
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

failures = []
stop_poll = threading.Event()
if os.environ.get('DIAG_POLL') == '1':
    pid = winmem.find_pid(exe_name)
    poll_mem = winmem.Mem(pid)
    # hook FindFirstFileA / FindFirstFileExA: save real addresses, point IAT
    # slots at the caves
    for slot, cave, real_rva in ((0x43C138, 0x454C00, 0x454DC0),
                                 (0x43C0B8, 0x454D00, 0x454DC8),
                                 (0x43C0C0, 0x454B00, 0x454DD0)):
        real_find = struct.unpack('<I', poll_mem.read(slot, 4))[0]
        poll_mem.write(real_rva, struct.pack('<I', real_find))
        poll_mem.write(slot, struct.pack('<I', cave))
        print('hooked %#x -> real %#x, cave %#x' % (slot, real_find, cave))

    def poll():
        while not stop_poll.is_set() and p.poll() is None:
            try:
                flag = poll_mem.read(0x454DFF, 1)
                if flag and flag[0]:
                    b = poll_mem.read(0x454E00, 0x200)
                    if b:
                        b = b.split(b'\0')[0]
                        if not failures or failures[-1] != b:
                            failures.append(b)
            except Exception:
                break
            time.sleep(0.02)

    th = threading.Thread(target=poll, daemon=True)
    th.start()
    print('polling diagnostic buffer')

if os.environ.get('PATCH_EXIT') == '1':
    pid = winmem.find_pid(exe_name)
    mem = winmem.Mem(pid)
    mem.write(0x454B80, b'\xeb\xfe')
    for slot in (0x43C0FC, 0x43C1D0, 0x43C1D4):
        mem.write(slot, struct.pack('<I', 0x454B80))
    mem.close()
    print('patched ExitProcess/TerminateProcess to hang')


def focus():
    fg = u.GetForegroundWindow()
    fg_tid = u.GetWindowThreadProcessId(fg, None)
    cur_tid = ctypes.windll.kernel32.GetCurrentThreadId()
    u.AttachThreadInput(cur_tid, fg_tid, True)
    u.SetWindowPos(h, -1, 0, 0, 1024, 900, 0x0040)
    u.SetForegroundWindow(h)
    u.SetFocus(h)
    u.AttachThreadInput(cur_tid, fg_tid, False)
    time.sleep(0.15)


def key(vk, wait=None):
    focus()
    u.keybd_event(vk, 0, 0, 0)
    time.sleep(0.12)
    u.keybd_event(vk, 0, 2, 0)
    time.sleep(delay if wait is None else wait)


def char(ch):
    key(ord(ch.upper()))


# Exact sequence from user:
# b x9, a, b, a, b, enter, a, Esc, a, name, enter
for _ in range(9):
    char('b')
char('a')
char('b')
char('a')
char('b')
key(0x0D)          # enter
char('a')
key(0x1B)          # Esc
char('a')
for ch in 'test':
    char(ch)
if os.environ.get('STOP_BEFORE_ENTER') == '1':
    print('stopped before final enter; game left running')
else:
    key(0x0D, 6.0)

stop_poll.set()
try:
    th.join(timeout=1.0)
except Exception:
    pass
if failures:
    print('--- failed CreateFileW paths ---')
    for b in failures[-10:]:
        try:
            print(repr(b), '=>', b.decode('mbcs', 'replace'))
        except Exception:
            print(repr(b))
else:
    print('no failed CreateFileW captured')

print('done; alive=', p.poll() is None, 'pid=', p.pid)
err = os.path.join(gdir, 'error.txt')
if os.path.isfile(err):
    print('--- error.txt ---')
    print(open(err, 'rb').read().decode('gbk', 'replace'))
if os.environ.get('KEEP') == '1' or os.environ.get('STOP_BEFORE_ENTER') == '1':
    print('keeping game running')
else:
    try:
        p.kill()
    except Exception:
        pass
    subprocess.run(['taskkill', '/F', '/IM', exe_name], capture_output=True)
