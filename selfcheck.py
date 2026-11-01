#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""enigma 启动器环境自检。

用法:
    python selfcheck.py
    python selfcheck.py --exe D:\Games\enigma\your.exe
    python selfcheck.py --config launcher.json

检查项:
    1. Python 版本（>=3.8）
    2. 主程序解析（--exe / 配置文件 / 自动探测）
    3. 主程序所在目录的游戏数据
    4. 是否已有残留的进程
    5. 是否已有注册对话框或游戏窗口

只读检查，不修改任何文件、不启动游戏。
"""
import ctypes
import os
import subprocess
import sys
from ctypes import wintypes as wt

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import enigma_launch as L                                     # noqa: E402

ok_count = 0
bad_count = 0


def ok(msg):
    global ok_count
    ok_count += 1
    print(f'  [OK]   {msg}')


def bad(msg, hint=''):
    global bad_count
    bad_count += 1
    print(f'  [!!]   {msg}')
    if hint:
        print(f'         → {hint}')


def info(msg):
    print(f'  [..]   {msg}')


def windows():
    u32 = ctypes.WinDLL('user32', use_last_error=True)
    u32.EnumWindows.argtypes = [ctypes.c_void_p, wt.LPARAM]
    u32.GetWindowThreadProcessId.argtypes = [wt.HWND, ctypes.POINTER(wt.DWORD)]
    u32.GetClassNameW.argtypes = [wt.HWND, wt.LPWSTR, ctypes.c_int]
    u32.GetWindowTextW.argtypes = [wt.HWND, wt.LPWSTR, ctypes.c_int]
    ENUM = ctypes.WINFUNCTYPE(wt.BOOL, wt.HWND, wt.LPARAM)
    out = []

    def cb(h, _):
        p = wt.DWORD()
        u32.GetWindowThreadProcessId(h, ctypes.byref(p))
        c = ctypes.create_unicode_buffer(256)
        u32.GetClassNameW(h, c, 256)
        t = ctypes.create_unicode_buffer(512)
        u32.GetWindowTextW(h, t, 512)
        out.append((p.value, c.value, t.value))
        return True

    u32.EnumWindows(ENUM(cb), 0)
    return out


def main():
    args = L.build_parser().parse_args()
    print('=' * 60)
    print(' enigma 启动器 · 环境自检')
    print('=' * 60)

    # 1. Python
    v = sys.version_info
    if v >= (3, 8):
        ok(f'Python {v.major}.{v.minor}.{v.micro}')
    else:
        bad(f'Python {v.major}.{v.minor} 太旧', '需要 3.8+')

    # 2. 配置
    try:
        cfg = L.load_config(args.config)
    except Exception as exc:                                 # noqa: BLE001
        bad(f'读取配置失败: {exc}')
        cfg = {}
    if cfg:
        src = args.config or os.path.join(HERE, 'launcher.json')
        ok(f'配置文件: {os.path.abspath(src)}')
        info(f'内容: {cfg}')
    else:
        info('未使用配置文件（自动探测）')

    # 3. 主程序解析
    exe = L.resolve_exe(args.exe, args.game_dir, cfg)
    if exe and os.path.isfile(exe):
        ok(f'主程序: {exe}')
        ok(f'大小: {os.path.getsize(exe):,} 字节')
    else:
        bad('找不到主程序',
            '用 --exe 指定，或把启动器放到游戏目录（见 docs/06）')

    # 4. 游戏数据
    if exe:
        gdir = os.path.dirname(exe)
        ok(f'工作目录: {gdir}')
        for sub in ('data', 'graphic', 'map', 'sound', 'save', 'user'):
            p = os.path.join(gdir, sub)
            if os.path.isdir(p):
                ok(f'数据目录 {sub}\\ 存在')
            else:
                info(f'数据目录 {sub}\\ 不存在（部分版本可忽略）')
        tmp = os.path.join(HERE, 'tmp')
        if os.path.isdir(tmp):
            ok(f'临时目录: {tmp}')
        else:
            info(f'临时目录尚未创建（运行时会自动创建 {tmp}）')
    # 5. 启动器本体
    if os.path.isfile(os.path.join(HERE, 'enigma_launch.py')):
        ok('启动器 enigma_launch.py 存在')
    else:
        bad('缺少 enigma_launch.py')

    # 6. 残留进程
    r = subprocess.run(['tasklist', '/FO', 'CSV', '/NH'],
                       capture_output=True, text=True, errors='ignore')
    low = r.stdout.lower()
    name = os.path.basename(exe).lower() if exe else 'crackme.exe'
    if name in low:
        bad(f'{name} 正在运行',
            f'先 taskkill /F /IM {name}，否则会提示"已经在运行"')
    else:
        ok(f'没有残留的 {name}')

    # 7. 窗口
    ws = windows()
    dialogs = [w for w in ws if 'TEnigmaProtectorLoaderRegistrationForm' in w[1]]
    games = [w for w in ws if L.is_game_window_tuple(w)]
    if dialogs:
        bad('注册对话框已经开着', '可能已有启动器实例在运行')
    else:
        ok('没有残留的注册对话框')
    if games:
        info(f'游戏已在运行：{games[0][2]!r}')
    else:
        ok('游戏当前未运行')

    print('-' * 60)
    print(f' 通过 {ok_count} 项，异常 {bad_count} 项')
    if bad_count == 0:
        print(' 可以双击「启动游戏.bat」开始。')
    else:
        print(' 请先处理上面的 [!!] 项（详见 docs/04-故障排查.md）。')
    return 0 if bad_count == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
