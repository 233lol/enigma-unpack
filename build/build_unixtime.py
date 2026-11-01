#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""构建 unixTime.dll（替代原壳虚拟化的同名 DLL）。

原 DLL 只有 calcTimeDiffe1 被游戏脚本调用（自动备份存档的时间戳命名），
这里用 as/dlltool/ld 从 unixtime.s 汇编出功能等价的 32 位 DLL，
只依赖系统 msvcrt.dll 的 _time32 / _mktime32。

依赖 binutils 的 as / dlltool / ld（在 PATH 中）。
所有中间文件都写在 tmp\unixtime 下；缺工具时退回 build\unixtime 里
已经构建好的 DLL。
用法:  python build\build_unixtime.py
输出:  out\unixTime.dll
"""
import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SRC = os.path.join(HERE, 'unixtime')
BUILD = os.path.join(ROOT, 'tmp', 'unixtime')
OUT = os.path.join(ROOT, 'out', 'unixTime.dll')


def run(cmd):
    print('+', ' '.join(cmd))
    r = subprocess.run(cmd, cwd=BUILD, capture_output=True, text=True)
    if r.stdout.strip():
        print(r.stdout.strip())
    if r.stderr.strip():
        print(r.stderr.strip())
    if r.returncode != 0:
        sys.exit('command failed: %s' % cmd[0])


def which(*names):
    for n in names:
        p = shutil.which(n)
        if p:
            return p
    return None


def fallback(reason):
    for cand in (os.path.join(SRC, 'unixTime.dll'), OUT):
        if os.path.isfile(cand) and os.path.abspath(cand) != os.path.abspath(OUT):
            os.makedirs(os.path.dirname(OUT), exist_ok=True)
            shutil.copyfile(cand, OUT)
            print('缺少 %s，已使用现有 %s (%d 字节)'
                  % (reason, cand, os.path.getsize(OUT)))
            return 0
    print('缺少 %s，且没有可用的 unixTime.dll。' % reason)
    return 1


def main():
    as_ = which('as', 'i686-w64-mingw32-as')
    dlltool = which('dlltool', 'i686-w64-mingw32-dlltool')
    ld = which('ld', 'i686-w64-mingw32-ld')
    missing = [n for n, v in (('as', as_), ('dlltool', dlltool), ('ld', ld)) if not v]
    if missing:
        return fallback('/'.join(missing))

    os.makedirs(BUILD, exist_ok=True)
    for name in ('unixtime.s', 'msvcrt.def'):
        shutil.copyfile(os.path.join(SRC, name), os.path.join(BUILD, name))

    # 32 位导入库（-m i386 -f --32 缺一不可，否则 dlltool 会用 64 位汇编器）
    run([dlltool, '-m', 'i386', '-f', '--32', '-d', 'msvcrt.def', '-l', 'libmsvcrt.a'])
    run([as_, '--32', '-o', 'unixtime.o', 'unixtime.s'])
    run([ld, '-m', 'i386pe', '--dll', '--export-all-symbols',
         '--entry', '_DllMainCRTStartup',
         '-o', 'unixTime.dll', 'unixtime.o', 'libmsvcrt.a'])

    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    shutil.copyfile(os.path.join(BUILD, 'unixTime.dll'), OUT)
    print('written %s (%d bytes)' % (OUT, os.path.getsize(OUT)))
    return 0


if __name__ == '__main__':
    sys.exit(main())
