"""Trace file API calls + results in the running game by patching IAT slots.

Allocates executable shims inside the target, points the app's IAT slots at
them, and polls a ring buffer so entries survive the game's crash.

usage: python tools/trace_files.py rebuilt|orig [exe] [key-delay]
"""
import os
import struct
import subprocess
import sys
import threading
import time
import ctypes

sys.path[:0] = ['extract', '.', 'tools']
import paths                                                    # noqa: E402
import winmem                                                   # noqa: E402
import pehooks                                                  # noqa: E402
from enigma_launch import enum_windows, is_game_window                          # noqa: E402

kind = sys.argv[1] if len(sys.argv) > 1 else 'rebuilt'
exe_name = sys.argv[2] if len(sys.argv) > 2 else (
    'crackme.exe' if kind == 'orig' else 'unenigma_single.exe')
delay = float(sys.argv[3]) if len(sys.argv) > 3 else 0.9
gdir = os.path.abspath('test')
exe = os.path.join(gdir, exe_name)
u = ctypes.windll.user32
k32 = ctypes.WinDLL('kernel32', use_last_error=True)
k32.VirtualProtectEx.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
                                 ctypes.c_size_t, ctypes.c_ulong,
                                 ctypes.POINTER(ctypes.c_ulong)]
k32.VirtualProtectEx.restype = ctypes.c_int


def make_writable(mem, addr):
    old = ctypes.c_ulong(0)
    page = addr & ~0xFFF
    ok = k32.VirtualProtectEx(mem.h, ctypes.c_void_p(page), 0x1000, 0x04,
                              ctypes.byref(old))
    return bool(ok)

# in-process targets (same RVA in the unpacked app image)
SLOTS = {
    'CreateFileW': (0x43C0CC, 7, True),
    'CreateDirectoryW': (0x43C0C0, 2, True),
    'DeleteFileA': (0x43C13C, 1, False),
    'FindFirstFileA': (0x43C138, 2, False),
    'FindFirstFileExA': (0x43C0B8, 5, False),
    'SetCurrentDirectoryA': (0x43C108, 1, False),
    'GetFullPathNameA': (0x43C110, 4, False),
}
BASE = 0x400000
RING_N = 512
RING_ENT = 8
CODE = 0x0000
IDX = 0x0800
RING = 0x1000


def p32(v):
    return struct.pack('<I', v & 0xFFFFFFFF)


def make_shim(shim, real, ring, idx, tag, nargs):
    """Pre-call logger: store (tag, filename) then tail-jump to the real API.

    pushfd/pushad leave the stack/registers untouched; the real function sees
    the original arguments and returns straight to the caller.
    """
    b = bytearray()
    b += b'\x9c'                                   # pushfd
    b += b'\x60'                                   # pushad
    b += b'\x8d\x74\x24\x28'                       # lea esi,[esp+0x28]
    b += b'\x8b\x3d' + p32(idx)                    # mov edi,[idx]
    b += b'\x81\xe7' + p32(RING_N - 1)             # and edi,RING_N-1
    b += b'\x8d\x3c\xfd' + p32(ring)               # lea edi,[edi*8+ring]
    b += b'\xc7\x07' + p32(tag)                    # mov dword [edi],tag
    b += b'\x8b\x06'                               # mov eax,[esi]
    b += b'\x89\x47\x04'                           # mov [edi+4],eax
    b += b'\xff\x05' + p32(idx)                    # inc dword [idx]
    b += b'\x61'                                   # popad
    b += b'\x9d'                                   # popfd
    b += b'\x68' + p32(real)                       # push real
    b += b'\xc3'                                   # ret  -> tail jump
    return bytes(b)


def main():
    paths.use_local_temp()
    winmem.kill(exe_name)
    time.sleep(0.5)
    proc = None
    if kind == 'orig':
        import enigma_launch
        rc = enigma_launch.run(exe, 'player', enigma_launch.DEFAULT_WAIT)
        print('launcher rc', rc)
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
        if proc is not None and proc.poll() is not None:
            print('exited early', proc.poll())
            return 1
        time.sleep(0.1)
    if not h:
        print('no window')
        return 1

    pid = winmem.find_pid(exe_name)
    if not pid:
        print('no pid')
        return 1
    mem = winmem.Mem(pid)
    if mem.read(BASE, 2) != b'MZ':
        print('warning: no MZ at 0x400000; slots may be wrong')

    k32.VirtualAllocEx.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
                                   ctypes.c_size_t, ctypes.c_ulong,
                                   ctypes.c_ulong]
    k32.VirtualAllocEx.restype = ctypes.c_void_p
    cave = k32.VirtualAllocEx(mem.h, None, 0x4000, 0x3000, 0x40)
    if not cave:
        print('VirtualAllocEx failed', ctypes.get_last_error())
        return 1
    print('cave', hex(cave))
    ring = cave + RING
    idx = cave + IDX
    mem.write(idx, b'\0\0\0\0')

    installed = {}
    wide_tags = set()
    off = CODE
    tag = 1
    for name, (slot, nargs, wide) in SLOTS.items():
        real = struct.unpack('<I', mem.read(slot, 4))[0]
        if not (0x60000000 <= real < 0x80000000):
            print('skip %s: slot %#x -> %#x (not an API)' % (name, slot, real))
            continue
        shim = cave + off
        code = make_shim(shim, real, ring, idx, tag, nargs)
        mem.write(shim, code)
        mem.write(slot, p32(shim))
        installed[name] = tag
        if wide:
            wide_tags.add(tag)
        print('hooked %-20s slot %#x real %#x shim %#x tag %d' %
              (name, slot, real, shim, tag))
        off += 0x100
        tag += 1

    # hspda.dll (game data archive plugin) opens files through CreateFileA
    mods = pehooks.modules32(mem)
    print('modules32:', [(hex(b), n) for b, s, n in mods])
    for base, size, name in mods:
        if 'hspda' not in name.lower():
            continue
        slot = pehooks.pe_import_slot(mem, base, 'kernel32', 'CreateFileA')
        if not slot:
            print('hspda: CreateFileA slot not found')
            continue
        real = struct.unpack('<I', mem.read(slot, 4))[0]
        shim = cave + off
        code = make_shim(shim, real, ring, idx, tag, 7)
        mem.write(shim, code)
        make_writable(mem, slot)
        mem.write(slot, p32(shim))
        installed['CreateFileA'] = tag
        print('hooked %-20s slot %#x real %#x shim %#x tag %d (in %s)' %
              ('CreateFileA', slot, real, shim, tag, name))
        off += 0x100
        tag += 1

    if not installed:
        print('nothing hooked')
        return 2

    captured = []
    stop = threading.Event()

    def poll():
        next_i = 0
        while not stop.is_set():
            try:
                raw = mem.read(idx, 4)
                if not raw:
                    break
                cur = struct.unpack('<I', raw)[0]
                if cur == next_i:
                    time.sleep(0.004)
                    continue
                if cur < next_i:
                    next_i = 0
                n = min(cur - next_i, RING_N)
                for k in range(n):
                    e = next_i + k
                    rec = mem.read(ring + (e & (RING_N - 1)) * RING_ENT,
                                   RING_ENT)
                    if not rec or len(rec) < RING_ENT:
                        continue
                    tag, path = struct.unpack('<II', rec)
                    name = ''
                    if path:
                        b = mem.read(path, 520)
                        if b:
                            if tag in wide_tags:
                                units = []
                                for j in range(0, len(b) - 1, 2):
                                    u = b[j] | (b[j + 1] << 8)
                                    if u == 0:
                                        break
                                    units.append(chr(u))
                                name = ''.join(units)
                            else:
                                name = b.split(b'\0')[0].decode(
                                    'mbcs', 'replace')
                    captured.append((time.time() - t0, tag, name))
                next_i = cur
            except Exception:
                break
            time.sleep(0.004)

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

    time.sleep(0.4)
    stop.set()
    th.join(timeout=1.5)

    tag_names = {1: 'FILE', 2: 'MKDIR', 3: 'DEL'}
    owned = {t: n for n, t in installed.items()}

    print('--- captured %d file ops (showing last 120) ---' % len(captured))
    for t, tag, name in captured[-120:]:
        print('%7.2f %-16s %s' % (t, owned.get(tag, tag), name))
    print('--- non-graphic ops (all) ---')
    for t, tag, name in captured:
        low = name.lower()
        if '\\graphic\\' in low or '\\sound\\' in low or name == '':
            continue
        print('%7.2f %-16s %s' % (t, owned.get(tag, tag), name))

    if proc is not None:
        try:
            proc.kill()
        except Exception:
            pass
    winmem.kill(exe_name)
    mem.close()
    return 0


if __name__ == '__main__':
    sys.exit(main())
