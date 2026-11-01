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
if not base:
    print('VirtualAllocEx failed')
    sys.exit(1)
print('shim base', hex(base))

p32 = lambda x: struct.pack('<I', x & 0xFFFFFFFF)
OFF_FFA, OFF_FFA_POST = 0x000, 0x040
OFF_FFEA, OFF_FFEA_POST = 0x080, 0x0C0
OFF_FNFA, OFF_FC = 0x100, 0x140
OFF_REAL_FFA, OFF_REAL_FFEA, OFF_REAL_FNFA, OFF_REAL_FC = 0x400, 0x404, 0x408, 0x40C
OFF_SAVED_FFA, OFF_SAVED_FFEA, OFF_FAKE = 0x410, 0x414, 0x418


def A():
    return bytearray(), {}, []


def label(st, n):
    st[1][n] = len(st[0])


def emit(st, b):
    st[0].extend(b)


def rel8(st, op, target):
    st[0].append(op)
    st[2].append((len(st[0]), target))
    st[0].append(0)


def finish(st):
    b, labels, fix = st
    for pos, target in fix:
        b[pos] = (labels[target] - (pos + 1)) & 0xFF
    return bytes(b)


# FindFirstFileA shim
st = A()
emit(st, b'\x8b\x04\x24')                          # mov eax,[esp]
emit(st, b'\xa3' + p32(base + OFF_SAVED_FFA))      # mov [saved],eax
emit(st, b'\xc7\x04\x24' + p32(base + OFF_FFA_POST))
emit(st, b'\xff\x25' + p32(base + OFF_REAL_FFA))
ffa = finish(st)

st = A()
emit(st, b'\x8b\xd0')                              # mov edx,eax
emit(st, b'\xa1' + p32(base + OFF_SAVED_FFA))      # mov eax,[saved]
emit(st, b'\x89\x04\x24')                          # mov [esp],eax
emit(st, b'\x8b\xc2')                              # mov eax,edx
emit(st, b'\x83\xf8\xff')                          # cmp eax,-1
rel8(st, 0x75, 'done')                             # jne done
emit(st, b'\xb8' + p32(base + OFF_FAKE))           # mov eax,fake
label(st, 'done')
emit(st, b'\xc3')
ffa_post = finish(st)

# FindFirstFileExA shim
st = A()
emit(st, b'\x8b\x04\x24')
emit(st, b'\xa3' + p32(base + OFF_SAVED_FFEA))
emit(st, b'\xc7\x04\x24' + p32(base + OFF_FFEA_POST))
emit(st, b'\xff\x25' + p32(base + OFF_REAL_FFEA))
ffea = finish(st)

st = A()
emit(st, b'\x8b\xd0')
emit(st, b'\xa1' + p32(base + OFF_SAVED_FFEA))
emit(st, b'\x89\x04\x24')
emit(st, b'\x8b\xc2')
emit(st, b'\x83\xf8\xff')
rel8(st, 0x75, 'done2')
emit(st, b'\xb8' + p32(base + OFF_FAKE))
label(st, 'done2')
emit(st, b'\xc3')
ffea_post = finish(st)

# FindNextFileA shim
st = A()
emit(st, b'\x81\x7c\x24\x04' + p32(base + OFF_FAKE))  # cmp [esp+4],fake
rel8(st, 0x75, 'real')                                # jne real
emit(st, b'\x31\xc0')                                 # xor eax,eax
emit(st, b'\xc2\x08\x00')                             # ret 8
label(st, 'real')
emit(st, b'\xff\x25' + p32(base + OFF_REAL_FNFA))
fnfa = finish(st)

# FindClose shim
st = A()
emit(st, b'\x81\x7c\x24\x04' + p32(base + OFF_FAKE))
rel8(st, 0x75, 'realc')
emit(st, b'\xb8\x01\x00\x00\x00')
emit(st, b'\xc2\x04\x00')
label(st, 'realc')
emit(st, b'\xff\x25' + p32(base + OFF_REAL_FC))
fc = finish(st)

# write code
mem.write(base + OFF_FFA, ffa)
mem.write(base + OFF_FFA_POST, ffa_post)
mem.write(base + OFF_FFEA, ffea)
mem.write(base + OFF_FFEA_POST, ffea_post)
mem.write(base + OFF_FNFA, fnfa)
mem.write(base + OFF_FC, fc)
# save real addresses
real_ffa = struct.unpack('<I', mem.read(0x43C138, 4))[0]
real_ffea = struct.unpack('<I', mem.read(0x43C0B8, 4))[0]
real_fnfa = struct.unpack('<I', mem.read(0x43C134, 4))[0]
real_fc = struct.unpack('<I', mem.read(0x43C144, 4))[0]
mem.write(base + OFF_REAL_FFA, p32(real_ffa))
mem.write(base + OFF_REAL_FFEA, p32(real_ffea))
mem.write(base + OFF_REAL_FNFA, p32(real_fnfa))
mem.write(base + OFF_REAL_FC, p32(real_fc))
mem.write(base + OFF_FAKE, p32(0xDEADBEEF))
# patch IAT slots
mem.write(0x43C138, p32(base + OFF_FFA))
mem.write(0x43C0B8, p32(base + OFF_FFEA))
mem.write(0x43C134, p32(base + OFF_FNFA))
mem.write(0x43C144, p32(base + OFF_FC))
print('shim installed; real ffa=%#x ffea=%#x fnfa=%#x fc=%#x'
      % (real_ffa, real_ffea, real_fnfa, real_fc))

# focus and send the user's exact sequence
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
