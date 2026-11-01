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
real_fnfa = struct.unpack('<I', mem.read(0x43C134, 4))[0]
REAL = base + 0x100
SHIM = base + 0x000
mem.write(REAL, p32(real_fnfa))
# FindNextFileA shim: skip the directory entry "sav_test"
code = bytearray()
fix = []
labels = {}


def emit(b):
    code.extend(b)


def label(n):
    labels[n] = len(code)


def jcc(op, target):
    code.append(op)
    fix.append((len(code), target))
    code.append(0)


emit(b'\x55\x8b\xec')                     # push ebp; mov ebp,esp
emit(b'\x56\x57')                         # push esi; push edi
label('loop')
emit(b'\xff\x75\x08')                     # push [ebp+8] (data)
emit(b'\xff\x75\x04')                     # push [ebp+4] (handle)
emit(b'\xff\x15' + p32(REAL))             # call [real]
emit(b'\x85\xc0')                         # test eax,eax
jcc(0x74, 'done')                         # jz done
emit(b'\x8b\x75\x08')                     # mov esi,[ebp+8]
emit(b'\x81\x7e\x2c' + b'sav_')           # cmp dword [esi+0x2c],'sav_'
jcc(0x75, 'done')                         # jne done
emit(b'\x81\x7e\x30' + b'test')           # cmp dword [esi+0x30],'test'
jcc(0x75, 'done')                         # jne done
emit(b'\x80\x7e\x34\x00')                 # cmp byte [esi+0x34],0
jcc(0x75, 'done')                         # jne done
emit(b'\xeb')                             # jmp loop
fix.append((len(code), 'loop'))
code.append(0)
label('done')
emit(b'\x5f\x5e')                         # pop edi; pop esi
emit(b'\x5d')                             # pop ebp
emit(b'\xc2\x08\x00')                     # ret 8
for pos, target in fix:
    code[pos] = (labels[target] - (pos + 1)) & 0xFF
mem.write(SHIM, bytes(code))
mem.write(0x43C134, p32(SHIM))
print('FindNextFileA shim installed, real=%#x' % real_fnfa)

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
