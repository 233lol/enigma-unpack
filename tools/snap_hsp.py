"""Snapshot the HSP variable table while a new game is created.

usage: python tools/snap_hsp.py orig|rebuilt <out.json> [exe] [delay]

Sequences the exact new-game key order, stops right before the final Enter,
takes a baseline snapshot, then presses Enter and samples PVal metadata at
~20 Hz until the process dies or the timeout expires.  All snapshots where the
metadata changed are written to <out.json> (plus a final one).
"""
import json
import os
import struct
import subprocess
import sys
import time
import ctypes

sys.path[:0] = ['extract', '.', 'tools']
import paths                                                     # noqa: E402
import winmem                                                    # noqa: E402
from enigma_launch import enum_windows, is_game_window                           # noqa: E402
import hsp_probe                                                 # noqa: E402

kind = sys.argv[1] if len(sys.argv) > 1 else 'rebuilt'
out_path = os.path.abspath(sys.argv[2] if len(sys.argv) > 2
                           else 'tmp/hsp_%s.json' % kind)
delay = float(sys.argv[4]) if len(sys.argv) > 4 else 0.9
gdir = os.path.abspath('test')
if kind == 'orig':
    exe_name = sys.argv[3] if len(sys.argv) > 3 else 'crackme.exe'
else:
    exe_name = sys.argv[3] if len(sys.argv) > 3 else 'unenigma_single.exe'
exe = os.path.join(gdir, exe_name)
u = ctypes.windll.user32

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
        sys.exit(1)
    time.sleep(0.1)
if not h:
    print('no window')
    sys.exit(1)


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
print('before final enter; sampling baseline')

pid = winmem.find_pid(exe_name)
if not pid:
    print('no pid')
    sys.exit(1)
mem = winmem.Mem(pid)
sc = hsp_probe.find_script(mem)
if not sc:
    print('no script')
    sys.exit(1)
script_va, allsize, pt_cs, max_cs, max_val, pt_dinfo, max_dinfo = sc
ctxs = hsp_probe.find_ctx(mem, script_va, pt_cs, max_cs)
if not ctxs:
    print('no ctx')
    sys.exit(1)
ctx, mcs, mem_var = ctxs[0]
print('script %#x ctx %#x mem_var %#x max_val %d' %
      (script_va, ctx, mem_var, max_val))


def meta():
    d = mem.read(mem_var, max_val * hsp_probe.PVAL_SIZE)
    if not d or len(d) < max_val * hsp_probe.PVAL_SIZE:
        return None
    rows = []
    for i in range(max_val):
        o = i * hsp_probe.PVAL_SIZE
        flag, mode = struct.unpack_from('<hh', d, o)
        lens = struct.unpack_from('<5i', d, o + 4)
        size = struct.unpack_from('<i', d, o + 24)[0]
        rows.append([flag, mode, list(lens), size])
    return rows


def scalars():
    """Integer/double variables with len 1x1: their current values."""
    d = mem.read(mem_var, max_val * hsp_probe.PVAL_SIZE)
    if not d:
        return {}
    vals = {}
    for i in range(max_val):
        o = i * hsp_probe.PVAL_SIZE
        flag = struct.unpack_from('<h', d, o)[0]
        lens = struct.unpack_from('<5i', d, o + 4)
        pt = struct.unpack_from('<I', d, o + 28)[0]
        if flag in (3, 4) and lens[1] <= 1 and lens[2] == 0:
            b = mem.read(pt, 8)
            if b:
                if flag == 4:
                    vals[i] = struct.unpack_from('<i', b, 0)[0]
                else:
                    vals[i] = struct.unpack_from('<d', b, 0)[0]
    return vals


def take(tag, want_scal=False):
    m = meta()
    if m is None:
        return None
    return dict(t=round(time.time() - t0, 3), tag=tag, meta=m,
                scal=scalars() if want_scal else None)


base = take('before-enter', want_scal=True)
print('baseline taken; pressing final enter')

import threading

samples = [base]
last = json.dumps(base['meta'], sort_keys=True) if base else ''
stop = threading.Event()
alive_box = [True]


def sampler():
    global last
    while not stop.is_set():
        if proc is not None and proc.poll() is not None:
            alive_box[0] = False
            return
        if kind == 'orig' and winmem.find_pid(exe_name) is None:
            alive_box[0] = False
            return
        s = take('run')
        if s is None:
            alive_box[0] = False
            return
        cur = json.dumps(s['meta'], sort_keys=True)
        if cur != last:
            s['tag'] = 'changed'
            samples.append(s)
            last = cur
        time.sleep(0.02)


th = threading.Thread(target=sampler, daemon=True)
th.start()
key(0x0D)
deadline = time.time() + 20
while time.time() < deadline and alive_box[0]:
    time.sleep(0.05)
stop.set()
th.join(timeout=2)
alive = alive_box[0]

# keep only changed samples + last
if len(samples) > 2:
    tail = samples[-1]
    samples = [base] + [s for s in samples[1:-1] if s['tag'] == 'changed'][-40:] + [tail]

os.makedirs(os.path.dirname(out_path), exist_ok=True)
json.dump(dict(kind=kind, script=script_va, max_val=max_val, alive=alive,
               samples=samples), open(out_path, 'w'), indent=0)
print('wrote', out_path, 'samples', len(samples), 'alive', alive)
err = os.path.join(gdir, 'error.txt')
if os.path.isfile(err):
    print('error.txt exists:', os.path.getsize(err))

if proc is not None:
    try:
        proc.kill()
    except Exception:
        pass
winmem.kill(exe_name)
mem.close()
