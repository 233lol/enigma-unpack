#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""从运行中的 crackme.exe 抓取 OEP（CRT 运行前）的解密原始映像。

原理
----
Enigma 的加载器解密完原程序后，把控制权交给原程序入口。我们不挂调试器
（会被检测），而是：

  1. 运行 crackme.exe，等注册对话框出现；
  2. 打描述符补丁（绕注册，和启动器同一套）；
  3. 给**每个线程**设硬件执行断点 DR0 = OEP；
  4. 点「注册」→ 加载器解密并跳到 OEP → 命中 DR0 → 未处理异常 →
     Windows 错误报告 (WER) 写出**全量转储**；
  5. 从转储里把 0x400000..0x453000 的原程序映像拼出来并校验。

WER 的 LocalDumps 需要事先配置（见 extract\enable_dumps.py / 启用错误转储.bat）。
单次命中的时机不一定落在「原程序已解密、CRT 未运行」的那一刻，所以本脚本会
**多试几次**，直到取到的映像通过校验（含 HSPHED 模板、代码非空、CRT 标记为 0）。

用法:
    python extract\extract_oep.py [--exe <crackme.exe>] [--oep 0x4209E9] [--out work\app_img_oep.bin]
"""
import argparse
import os
import shutil
import struct
import subprocess
import sys
import time
import winreg

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

import paths                                                    # noqa: E402
import winmem                                                   # noqa: E402
from enigma_launch import (enum_windows, find_window, image_base,  # noqa: E402
                          markers_ok, post_click, type_text,
                          OFF_SAVE, OFF_MSG, PATCH, BTN_REGISTER, BTN_OK)

APP_BASE = 0x400000
APP_SIZE = 0x53000                 # 原程序映像（0x400000..0x453000）
OEP_CANDIDATES = (0x4209E9, 0x420F3C)
WER_KEY = r'Software\Microsoft\Windows\Windows Error Reporting\LocalDumps\%s'

# 校验用的固定地址（均在原程序映像内）
VA_HSPHED = 0x44C08C               # .data 里的 HSPHED 模板
VA_CRT1 = 0x44DF6C                 # CRT 初始化标记（OEP 时应为 0）
VA_CRT2 = 0x44DF75
VA_COOKIE = 0x44C364
HSPHED_MAGIC = b'HSPHED~~'


# ------------------------------------------------------------------ WER 配置
def wer_folder(exe_name, want_dir=None):
    want = os.path.abspath(want_dir or paths.CRASH)
    os.makedirs(want, exist_ok=True)
    # 尽量把两个位置都指向项目 tmp；没有管理员权限时 HKLM 会失败，忽略即可。
    for _label, hk in (('HKLM', winreg.HKEY_LOCAL_MACHINE),
                       ('HKCU', winreg.HKEY_CURRENT_USER)):
        try:
            with winreg.CreateKeyEx(hk, WER_KEY % exe_name, 0, winreg.KEY_SET_VALUE) as k:
                winreg.SetValueEx(k, 'DumpFolder', 0, winreg.REG_EXPAND_SZ, want)
                winreg.SetValueEx(k, 'DumpType', 0, winreg.REG_DWORD, 2)
                winreg.SetValueEx(k, 'DumpCount', 0, winreg.REG_DWORD, 10)
        except OSError:
            pass
    for label, hk in (('HKLM', winreg.HKEY_LOCAL_MACHINE), ('HKCU', winreg.HKEY_CURRENT_USER)):
        try:
            with winreg.OpenKey(hk, WER_KEY % exe_name) as k:
                folder = os.path.expandvars(winreg.QueryValueEx(k, 'DumpFolder')[0])
                if folder:
                    return folder, label
        except OSError:
            continue
    return want, '未配置'


def _redirect_dump_dir(folder):
    """把项目内的旧转储目录用 junction 指到 tmp\\crashdumps。

    有些机器上 HKLM 的 DumpFolder 是以前配置的（例如 ...\\work\\crashdumps），
    普通权限改不动 HKLM。这里不写项目外：如果它还在项目内，就建一个目录
    junction 指向 tmp\\crashdumps，让 WER 实际写进 tmp。
    """
    if not folder or not paths._inside(folder):
        return None
    folder = os.path.abspath(folder)
    if os.path.abspath(folder) == os.path.abspath(paths.CRASH):
        return folder
    os.makedirs(paths.CRASH, exist_ok=True)
    # 已经是指向 tmp\crashdumps 的 junction：直接用
    try:
        if os.path.isdir(folder) and os.path.samefile(folder, paths.CRASH):
            return folder
    except OSError:
        pass
    # 旧的真实目录：把里面的转储搬进 tmp，再删掉/换成 junction
    if os.path.lexists(folder):
        if os.path.isdir(folder) and not os.path.islink(folder):
            try:
                for name in os.listdir(folder):
                    src = os.path.join(folder, name)
                    dst = os.path.join(paths.CRASH, name)
                    if os.path.isfile(src) and not os.path.exists(dst):
                        shutil.move(src, dst)
                os.rmdir(folder)
            except OSError:
                return folder
        else:
            try:
                os.rmdir(folder)
            except OSError:
                try:
                    os.remove(folder)
                except OSError:
                    return None
    try:
        os.makedirs(os.path.dirname(folder), exist_ok=True)
        subprocess.run(['cmd', '/c', 'mklink', '/J', folder, paths.CRASH],
                       capture_output=True)
    except OSError:
        return None
    return folder if os.path.isdir(folder) else None


def dump_dirs(exe_name='crackme.exe'):
    # 只搜索项目内的目录，避免把转储写到项目外。
    dirs = [paths.CRASH, os.path.join(paths.WORK, 'crashdumps')]
    folder, _ = wer_folder(exe_name)
    folder = _redirect_dump_dir(folder)
    if folder and folder not in dirs:
        dirs.insert(0, folder)
    return dirs


def snapshot_dumps(dirs, exe_name='crackme.exe'):
    seen = set()
    prefix = exe_name.lower()
    for d in dirs:
        if not os.path.isdir(d):
            continue
        for f in os.listdir(d):
            if f.lower().startswith(prefix) and f.lower().endswith('.dmp'):
                seen.add(os.path.join(d, f))
    return seen


# ------------------------------------------------------------------ 转储解析
def parse_minidump(path):
    d = open(path, 'rb').read()
    sig, _ver, nstreams, diroff = struct.unpack_from('<IIII', d, 0)
    if sig != 0x504D444D:
        raise ValueError('不是 minidump: %s' % path)
    streams = {}
    for i in range(nstreams):
        t, size, rva = struct.unpack_from('<III', d, diroff + i * 12)
        streams[t] = (size, rva)
    u32 = lambda o: struct.unpack_from('<I', d, o)[0]
    u64 = lambda o: struct.unpack_from('<Q', d, o)[0]
    ranges = []
    if 9 in streams:
        _, rva = streams[9]
        n = u64(rva)
        off = u64(rva + 8)
        for i in range(n):
            m = rva + 16 + i * 16
            start, size = u64(m), u64(m + 8)
            ranges.append((start, size, off))
            off += size
    elif 5 in streams:
        _, rva = streams[5]
        n = u32(rva)
        for i in range(n):
            m = rva + 4 + i * 16
            ranges.append((u64(m), u32(m + 8), u32(m + 12)))
    else:
        raise ValueError('转储里没有内存列表')
    return d, ranges


def carve(d, ranges):
    img = bytearray(APP_SIZE)
    got = 0
    for start, rsize, off in ranges:
        lo, hi = max(start, APP_BASE), min(start + rsize, APP_BASE + APP_SIZE)
        if lo < hi:
            img[lo - APP_BASE:hi - APP_BASE] = d[off + (lo - start):off + (hi - start)]
            got += hi - lo
    return bytes(img), got


def validate(img):
    """判断是不是「原程序已解密、CRT 未运行」的干净映像。"""
    if len(img) != APP_SIZE or img[:2] != b'MZ':
        return False, '不是 MZ'
    if img[VA_HSPHED - APP_BASE:VA_HSPHED - APP_BASE + len(HSPHED_MAGIC)] != HSPHED_MAGIC:
        return False, '缺少 HSPHED 模板'
    if not any(img[0x1000:0x3C000]):
        return False, '代码段为空'
    if img[VA_CRT1 - APP_BASE:VA_CRT1 - APP_BASE + 4] != b'\0' * 4:
        return False, 'CRT 已初始化'
    if img[VA_CRT2 - APP_BASE] != 0:
        return False, 'CRT 已初始化'
    return True, 'ok'


def extract_image(dump_path):
    d, ranges = parse_minidump(dump_path)
    img, got = carve(d, ranges)
    if got < APP_SIZE * 0.98:
        return None, '转储覆盖不足 %#x/%#x' % (got, APP_SIZE)
    ok, why = validate(img)
    return (img if ok else None), why


# ------------------------------------------------------------------ 单次尝试
def drive_and_trap(exe, oep, dirs, timeout, log):
    """跑一次 crackme 并触发 DR0，返回新产生的转储路径（或 None）。"""
    name = os.path.basename(exe)
    before = snapshot_dumps(dirs, name)
    winmem.kill(name)
    time.sleep(0.6)
    t0 = time.time()
    proc = subprocess.Popen([exe], cwd=os.path.dirname(exe))
    pid = proc.pid
    mem = winmem.Mem(pid)

    while time.time() - t0 < 20:
        if find_window('TEnigmaProtectorLoaderRegistrationForm', pid=pid):
            break
        if proc.poll() is not None:
            log('  进程提前退出: %#x' % proc.poll())
            return None
        time.sleep(0.02)
    else:
        log('  等不到注册对话框')
        return None
    time.sleep(1.4)

    base = image_base(mem)
    mem.write(base + OFF_SAVE, PATCH)
    mem.write(base + OFF_MSG, PATCH)

    wins = [w for w in enum_windows() if w['pid'] == pid]
    edits = sorted((w for w in wins if 'LoaderEdit' in w['cls']), key=lambda w: w['top'])
    memo = next((w for w in wins if 'LoaderMemo' in w['cls']), None)
    if edits:
        type_text(edits[-1]['hwnd'], 'player')
    if memo:
        type_text(memo['hwnd'], 'AAAA-BBBB-CCCC-DDDD-EEEE-FFFF')
    time.sleep(0.3)

    log('  设 DR0 = %#x（%d 个线程），点「注册」…'
        % (oep, winmem.arm_dr0_space_for_oep(pid, oep)))
    btn = find_window('LoaderButton', BTN_REGISTER, pid)
    if btn:
        post_click(btn['hwnd'])

    clicked_ok = False
    dump = None
    last_code = None
    deadline = time.time() + timeout
    while time.time() < deadline:
        winmem.arm_dr0_space_for_oep(pid, oep)
        if not clicked_ok:
            b = find_window('LoaderButton', BTN_OK, pid)
            if b:
                time.sleep(0.3)
                post_click(b['hwnd'])
                clicked_ok = True
        now = snapshot_dumps(dirs, name) - before
        if now:
            dump = max(now, key=os.path.getmtime)
        code = proc.poll()
        if code is not None and last_code is None:
            last_code = code
            log('  %s 已退出，代码 %#x' % (name, code & 0xffffffff))
        if dump and code is not None:
            break
        if code is not None and not now:
            time.sleep(0.8)
            now = snapshot_dumps(dirs, name) - before
            if now:
                dump = max(now, key=os.path.getmtime)
            break
        time.sleep(0.02)

    if not dump:
        time.sleep(2.0)
        now = snapshot_dumps(dirs, name) - before
        dump = max(now, key=os.path.getmtime) if now else None
    winmem.kill(name)
    return dump


def run(exe, oep=None, out=None, attempts=3, timeout=40, log=print):
    paths.use_local_temp()
    paths.ensure_dirs()
    name = os.path.basename(exe)
    out = out or os.path.join(paths.WORK, 'app_img_oep.bin')
    folder, src = wer_folder(name)
    dirs = dump_dirs(name)
    log('WER LocalDumps 目录: %s (%s)' % (folder, src))
    if os.path.abspath(folder) != os.path.abspath(paths.CRASH):
        log('  注意：WER 当前不是写入项目 tmp；若下面抓不到转储，'
            '请以管理员运行「启用错误转储.bat」。')
    before_all = snapshot_dumps(dirs, name)

    oeps = [oep] if oep else list(OEP_CANDIDATES)
    for ocandidate in oeps:
        for k in range(1, attempts + 1):
            log('尝试 OEP=%#x（第 %d/%d 次）' % (ocandidate, k, attempts))
            dump = drive_and_trap(exe, ocandidate, dirs, timeout, log)
            if not dump:
                log('  没抓到转储')
                continue
            log('  解析 %s (%.1f MB)' % (os.path.basename(dump), os.path.getsize(dump) / 1e6))
            img, why = extract_image(dump)
            if img is None:
                log('  该转储不可用：%s，重试…' % why)
                continue
            open(out, 'wb').write(img)
            log('已写出 %s (%d 字节)，校验通过。' % (out, len(img)))
            _cleanup_dumps(dirs, before_all, name, log)
            return 0
    _cleanup_dumps(dirs, before_all, name, log)
    log('多次尝试都没拿到干净的 OEP 映像。')
    log('可先运行「启用错误转储.bat」（管理员），确认 WER LocalDumps 已配置后再试。')
    return 3


def _cleanup_dumps(dirs, before, exe_name='crackme.exe', log=print):
    """删除本次运行产生的转储（每个约 90MB）。"""
    freed = 0
    for p in snapshot_dumps(dirs, exe_name) - before:
        try:
            freed += os.path.getsize(p)
            os.remove(p)
        except OSError:
            pass
    if freed:
        log('已清理本次产生的转储（%.0f MB）' % (freed / 1e6))


def main(argv=None):
    ap = argparse.ArgumentParser(
        description='从 crackme.exe 抓取 OEP 原程序映像（WER 转储 + DR0）')
    ap.add_argument('--exe', help='crackme.exe 路径')
    ap.add_argument('-g', '--game-dir', help='游戏目录')
    ap.add_argument('--oep', help='OEP 地址（默认自动尝试 0x4209E9 / 0x420F3C）')
    ap.add_argument('--out', help='输出路径（默认 work\\app_img_oep.bin）')
    ap.add_argument('--attempts', type=int, default=3, help='每个 OEP 地址尝试次数')
    args = ap.parse_args(argv)

    src = paths.find_source_exe(args.exe)
    if not src:
        print('找不到原始 crackme.exe（默认 bk\\crackme.exe）。')
        return 2
    exe = paths.ensure_target_game(src)
    if not exe:
        print('无法准备 test\\crackme.exe。')
        return 2
    exe = paths.prepare_extract_exe() or exe
    try:
        return run(exe, int(args.oep, 0) if args.oep else None, args.out, args.attempts)
    finally:
        paths.cleanup_extract_exe()


if __name__ == '__main__':
    sys.exit(main())
