#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""从运行中的 enigma 进程里取出脚本主体 start.ax（明文 HSP3 对象）。

原理
----
`Hsp3::Reset` 在启动时把脚本库里的 `start.ax` 整个读进一块堆内存并解密。
所以游戏窗口出现后，进程里存在一个以 `'HSP3'` 开头、长度写在头部 +12 的
对象。我们扫描可读内存，按头部字段（allsize / pt_cs / max_cs 合理）挑出
真正的脚本对象并整块导出。

用法:
    python extract\extract_script.py [--exe <crackme.exe>] [--out tmp\work\start.ax]
"""
import argparse
import os
import struct
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

import paths                                                    # noqa: E402
import winmem                                                   # noqa: E402
import enigma_launch                                             # noqa: E402

MIN_SIZE = 0x10000
MAX_SIZE = 0x4000000


def scan_hsp3(mem, log=print):
    """返回 (va, allsize)；找不到返回 (None, None)。"""
    best = None
    for base, size, data in mem.iter_readable():
        i = 0
        while True:
            i = data.find(b'HSP3', i)
            if i < 0:
                break
            va = base + i
            hd = mem.read(va, 0x30)
            if hd and len(hd) >= 0x30:
                allsize = struct.unpack_from('<I', hd, 12)[0]
                pt_cs = struct.unpack_from('<I', hd, 16)[0]
                max_cs = struct.unpack_from('<I', hd, 20)[0]
                ok = (MIN_SIZE <= allsize <= MAX_SIZE and 0 < max_cs < allsize
                      and 0 < pt_cs < max_cs)
                if ok and (best is None or allsize > best[1]):
                    best = (va, allsize)
                    log('  发现 HSP3 对象 @ %#x  allsize=%#x (pt_cs=%#x max_cs=%#x)'
                        % (va, allsize, pt_cs, max_cs))
            i += 1
    return best if best else (None, None)


def run(exe, out=None, log=print, timeout=60):
    paths.use_local_temp()
    paths.ensure_dirs()
    name = os.path.basename(exe)
    out = out or os.path.join(paths.WORK, 'start.ax')
    winmem.kill(name)
    time.sleep(0.6)

    log('通过启动器启动游戏（运行时绕注册）…')
    rc = enigma_launch.run(exe, 'player', enigma_launch.DEFAULT_WAIT)
    if rc != 0:
        log('启动器返回 %d，仍尝试扫描…' % rc)
    pid = winmem.find_pid(name)
    if not pid:
        log('找不到运行中的 %s' % name)
        return 4
    mem = winmem.Mem(pid)
    log('扫描 %d 的脚本对象…' % pid)
    va, allsize = scan_hsp3(mem, log)
    if va is None:
        # 窗口刚出现时脚本可能还在解密，重试几次
        for _ in range(10):
            time.sleep(0.5)
            va, allsize = scan_hsp3(mem, lambda *a: None)
            if va:
                log('  重试后找到 @ %#x allsize=%#x' % (va, allsize))
                break
    if va is None:
        log('没找到 HSP3 脚本对象')
        winmem.kill(name)
        return 3

    blob = mem.read(va, allsize)
    if not blob or len(blob) != allsize or blob[:4] != b'HSP3':
        log('读取脚本对象失败（%s 字节）' % (len(blob) if blob else 0))
        winmem.kill(name)
        return 3
    winmem.kill(name)
    os.makedirs(os.path.dirname(out), exist_ok=True)
    open(out, 'wb').write(blob)
    log('已写出 %s (%d 字节)' % (out, len(blob)))
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description='从运行中的 enigma 进程导出 start.ax')
    ap.add_argument('--exe', help='crackme.exe 路径')
    ap.add_argument('-g', '--game-dir', help='游戏目录')
    ap.add_argument('--out', help='输出路径（默认 work\\start.ax）')
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
        return run(exe, args.out)
    finally:
        paths.cleanup_extract_exe()


if __name__ == '__main__':
    sys.exit(main())
