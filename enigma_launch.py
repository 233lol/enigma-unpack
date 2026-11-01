#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""enigma 一键启动器 —— 绕过 Enigma Protector 注册校验。

原理速览
--------
test\crackme.exe（原始备份在 bk\）被 Enigma Protector 5.x 加壳，启动时弹出注册对话框。
注册判定跑在 Enigma 自己的虚拟机里，判定结果决定「显示哪条消息」和
「是否保存注册信息并继续运行原程序」。直接改代码会被壳的完整性校验发现
（启动后 0.3 秒内改动 → "Internal Protection Error"），但**在启动校验跑完之后**
（对话框已经出现，约 1.4 秒之后）再去改虚拟机的描述符数据，就不会被发现。

两个描述符（映像内偏移，运行时基址 = 映像基址 + 偏移）：

    0x07615A8   条件分支，标记 0x2C，被指令索引 20686 使用
                （守住「保存注册信息 + 继续进入游戏」的那段）
    0x075AF1C   条件分支，标记 0x2C，被指令索引 19191 使用
                （决定显示"成功注册"还是"注册没成功"）

把这两个描述符的标记改成 0x03（= 永不跳转，即强制走顺序执行的那条路），
再点「注册」，壳就会写许可文件、报告成功，并在同一进程内解密运行原游戏。

本脚本做的是纯运行时内存补丁：不修改磁盘上的任何文件。
每次启动游戏都需要跑一次本脚本。

用法
----
    python enigma_launch.py                       # 自动探测
    python enigma_launch.py 玩家名
    python enigma_launch.py D:\Games\enigma        # 直接给游戏目录
    python enigma_launch.py D:\Games\enigma\my.exe # 直接给主程序（任意名字）
    python enigma_launch.py --exe D:\x\game.exe --wait 1.5
    python enigma_launch.py --config my.json
    python enigma_launch.py --check               # 只检查解析结果

路径解析优先级
--------------
    1. --exe / 位置参数给出的文件（或目录）
    2. --game-dir / 位置参数给出的目录
    3. --config 指定的配置文件（默认同目录 launcher.json）
    4. 自动探测项目内的 test\crackme.exe / bk\crackme.exe
配置文件 launcher.json（可选）：
    {
      "game_dir": "test",
      "source_exe": "bk/crackme.exe",
      "exe": "test/crackme.exe",
      "player": "enigma",
      "wait": 1.2
    }

所有子进程的 TEMP/TMP 都会被指向 <项目>\tmp，不会写到项目外。
"""
import argparse
import ctypes
import json
import os
import struct
import subprocess
import sys
import time
from ctypes import wintypes as wt

HERE = os.path.dirname(os.path.abspath(__file__))
KNOWN_EXE_NAMES = ('crackme.exe')
DEFAULT_WAIT = 1.2

# ---------------------------------------------------------------- 目标参数
IMG_FALLBACK = 0x453000            # 映像基址（实测值；下面会自动探测）
OFF_SAVE = 0x07615A8               # 描述符：保存许可 + 继续
OFF_MSG = 0x075AF1C                # 描述符：消息分支
PATCH = struct.pack('<I', 0x03)    # 标记 0x03 = 永不跳转
MARKERS = {0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x34, 0x35, 0x36, 0x37, 0x38, 0x3B}
BTN_REGISTER = '\u6ce8\u518c'      # 注册
BTN_OK = '&OK'
GAME_CLASS = 'hspwnd0'
# 目标窗口标题关键字：从 launcher.json 的 "window_title" 读取；
# 留空表示只按窗口类名匹配。
GAME_TITLE = ''


def window_keyword():
    """目标窗口标题里需要包含的关键字（launcher.json: window_title）。"""
    try:
        return load_config().get('window_title') or GAME_TITLE
    except (OSError, ValueError):
        return GAME_TITLE


def is_game_window(w):
    """enum_windows() 返回的 dict：类名 + 标题关键字。"""
    return GAME_CLASS in w.get('cls', '') and window_keyword() in w.get('text', '')


def is_game_window_tuple(w):
    """selfcheck 的 (hwnd, cls, text) 元组形式。"""
    return w[1] == GAME_CLASS and window_keyword() in w[2]


# ---------------------------------------------------------------- 路径解析
def load_config(path=None):
    """读取启动器配置。返回 dict（含 exe/game_dir/player/wait）。"""
    if path is None:
        path = os.path.join(HERE, 'launcher.json')
        if not os.path.isfile(path):
            return {}
    path = os.path.abspath(os.path.expanduser(path))
    if not os.path.isfile(path):
        raise FileNotFoundError(path)
    with open(path, 'r', encoding='utf-8-sig') as f:
        cfg = json.load(f)
    if not isinstance(cfg, dict):
        raise ValueError('配置文件必须是 JSON 对象')
    base = os.path.dirname(path)
    for key in ('exe', 'game_dir'):
        v = cfg.get(key)
        if v and not os.path.isabs(v):
            cfg[key] = os.path.normpath(os.path.join(base, v))
    return cfg


def _exe_in_dir(d):
    """在目录里找已知名称的主程序。"""
    d = os.path.abspath(os.path.expanduser(d))
    for nm in KNOWN_EXE_NAMES:
        p = os.path.join(d, nm)
        if os.path.isfile(p):
            return p
    # 目录里只有一个 exe 时也接受（支持任意改名）
    try:
        exes = [os.path.join(d, f) for f in os.listdir(d)
                if f.lower().endswith('.exe')]
    except OSError:
        return None
    if len(exes) == 1:
        return exes[0]
    return None


def resolve_exe(explicit=None, game_dir=None, config=None):
    """按优先级解析主程序完整路径；解析失败返回 None。"""
    cfg = config or {}
    cand = explicit
    if not cand and game_dir:
        cand = _exe_in_dir(game_dir)
        if cand:
            return cand
    if not cand:
        cand = cfg.get('exe')
    if not cand and cfg.get('game_dir'):
        cand = _exe_in_dir(cfg['game_dir'])
        if cand:
            return cand
    if cand:
        p = os.path.abspath(os.path.expanduser(cand))
        if os.path.isdir(p):
            hit = _exe_in_dir(p)
            if hit:
                return hit
        elif os.path.isfile(p):
            return p
        cand = None
    # 自动探测：项目内的 test / bk（不访问项目外）
    bases = [HERE]
    seen = set()
    for base in bases:
        if base in seen:
            continue
        seen.add(base)
        for sub in ('test', 'bk', ''):
            d = os.path.join(base, sub) if sub else base
            if os.path.isdir(d):
                hit = _exe_in_dir(d)
                if hit:
                    return os.path.abspath(hit)
    return None


def build_parser():
    p = argparse.ArgumentParser(
        prog='enigma_launch.py',
        description='enigma 启动器（Enigma Protector 注册绕过）',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='示例:\n'
               '  python enigma_launch.py\n'
               '  python enigma_launch.py D:\\Games\\enigma\n'
               '  python enigma_launch.py D:\\Games\\enigma\\enigma.exe\n'
               '  python enigma_launch.py --exe test\\crackme.exe --wait 1.5\n'
               '  python enigma_launch.py --check\n')
    p.add_argument('target', nargs='?', default=None,
                   help='玩家名，或游戏目录 / 主程序路径')
    p.add_argument('-e', '--exe', metavar='PATH',
                   help='主程序路径（文件，或包含主程序的目录）')
    p.add_argument('-g', '--game-dir', metavar='DIR',
                   help='游戏目录（自动在其中查找 crackme.exe）')
    p.add_argument('-c', '--config', metavar='FILE',
                   help='配置文件（默认：同目录 launcher.json）')
    p.add_argument('-w', '--wait', type=float, metavar='SEC',
                   help=f'注册对话框出现后的等待秒数（默认 {DEFAULT_WAIT}）')
    p.add_argument('--check', action='store_true',
                   help='只解析并打印路径，不启动游戏')
    return p


# ---------------------------------------------------------------- win32
k32 = ctypes.WinDLL('kernel32', use_last_error=True)
u32 = ctypes.WinDLL('user32', use_last_error=True)

k32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
k32.OpenProcess.restype = wt.HANDLE
k32.ReadProcessMemory.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
                                  ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
k32.WriteProcessMemory.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
                                   ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
u32.EnumWindows.argtypes = [ctypes.c_void_p, wt.LPARAM]
u32.EnumChildWindows.argtypes = [wt.HWND, ctypes.c_void_p, wt.LPARAM]
u32.GetWindowThreadProcessId.argtypes = [wt.HWND, ctypes.POINTER(wt.DWORD)]
u32.GetClassNameW.argtypes = [wt.HWND, wt.LPWSTR, ctypes.c_int]
u32.GetWindowTextW.argtypes = [wt.HWND, wt.LPWSTR, ctypes.c_int]
u32.GetWindowRect.argtypes = [wt.HWND, ctypes.POINTER(wt.RECT)]
u32.SendMessageW.argtypes = [wt.HWND, wt.UINT, wt.WPARAM, wt.LPARAM]
u32.PostMessageW.argtypes = [wt.HWND, wt.UINT, wt.WPARAM, wt.LPARAM]

WM_CHAR = 0x0102
WM_SETFOCUS = 0x0007
BM_CLICK = 0x00F5
ENUMPROC = ctypes.WINFUNCTYPE(wt.BOOL, wt.HWND, wt.LPARAM)


def enum_windows():
    """所有顶层窗口 + 它们的子控件"""
    out = []

    def take(hwnd):
        pid = wt.DWORD()
        u32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        cls = ctypes.create_unicode_buffer(256)
        u32.GetClassNameW(hwnd, cls, 256)
        txt = ctypes.create_unicode_buffer(512)
        u32.GetWindowTextW(hwnd, txt, 512)
        r = wt.RECT()
        u32.GetWindowRect(hwnd, ctypes.byref(r))
        out.append(dict(hwnd=hwnd, pid=pid.value, cls=cls.value, text=txt.value,
                        top=r.top, left=r.left))
        return True

    top = []

    def cb(hwnd, _):
        top.append(hwnd)
        take(hwnd)
        return True

    u32.EnumWindows(ENUMPROC(cb), 0)
    for h in top:
        u32.EnumChildWindows(h, ENUMPROC(lambda w, _: take(w)), 0)
    return out


def find_window(cls_part, text=None, pid=None):
    for w in enum_windows():
        if cls_part not in w['cls']:
            continue
        if text is not None and w['text'].strip() != text:
            continue
        if pid is not None and w['pid'] != pid:
            continue
        return w
    return None


def post_click(hwnd):
    """按钮用 Post：它的处理函数会跑虚机校验并弹模态框，SendMessage 会卡死。"""
    u32.PostMessageW(hwnd, BM_CLICK, 0, 0)


def type_text(hwnd, text):
    u32.SendMessageW(hwnd, WM_SETFOCUS, 0, 0)
    for ch in text:
        u32.SendMessageW(hwnd, WM_CHAR, ord(ch), 1)


class Mem:
    def __init__(self, pid):
        self.h = k32.OpenProcess(0x0008 | 0x0010 | 0x0020 | 0x0400, False, pid)
        if not self.h:
            raise OSError(f'OpenProcess({pid}) 失败: {ctypes.get_last_error()}')

    def read(self, addr, size):
        buf = ctypes.create_string_buffer(size)
        got = ctypes.c_size_t(0)
        if not k32.ReadProcessMemory(self.h, ctypes.c_void_p(addr), buf, size,
                                     ctypes.byref(got)):
            return b''
        return buf.raw[:got.value]

    def write(self, addr, data):
        buf = ctypes.create_string_buffer(bytes(data), len(data))
        got = ctypes.c_size_t(0)
        if not k32.WriteProcessMemory(self.h, ctypes.c_void_p(addr), buf, len(data),
                                      ctypes.byref(got)):
            raise OSError(f'WriteProcessMemory({addr:#x}) 失败: '
                          f'{ctypes.get_last_error()}')

    def regions(self):
        class MBI(ctypes.Structure):
            _fields_ = [('BaseAddress', ctypes.c_void_p),
                        ('AllocationBase', ctypes.c_void_p),
                        ('AllocationProtect', ctypes.c_ulong),
                        ('PartitionId', ctypes.c_ushort),
                        ('RegionSize', ctypes.c_size_t),
                        ('State', ctypes.c_ulong),
                        ('Protect', ctypes.c_ulong),
                        ('Type', ctypes.c_ulong)]
        out, addr, mbi = [], 0, MBI()
        while addr < 0x80000000:
            if not k32.VirtualQueryEx(self.h, ctypes.c_void_p(addr),
                                      ctypes.byref(mbi), ctypes.sizeof(mbi)):
                break
            b = mbi.BaseAddress or 0
            out.append((b, mbi.RegionSize, mbi.State, mbi.Protect, mbi.Type))
            nxt = b + mbi.RegionSize
            if nxt <= addr:
                break
            addr = nxt
        return out


def markers_ok(mem, base):
    d1 = mem.read(base + OFF_SAVE, 4)
    d2 = mem.read(base + OFF_MSG, 4)
    if len(d1) != 4 or len(d2) != 4:
        return None
    m1, m2 = struct.unpack('<I', d1)[0], struct.unpack('<I', d2)[0]
    return (m1, m2) if (m1 in MARKERS and m2 in MARKERS) else None


def image_base(mem):
    """解壳后映像的运行时基址。

    它不是进程主模块（主模块是壳自己的 PE），而是壳额外映射的映像。
    实测固定在 0x453000；这里先验证再扫描，最后兜底。
    """
    if markers_ok(mem, IMG_FALLBACK):
        return IMG_FALLBACK
    for base, size, state, _prot, _typ in mem.regions():
        if state != 0x1000 or size < 0x1000:
            continue
        if markers_ok(mem, base):
            print(f'  扫描到映像基址 {base:#x}')
            return base
    return IMG_FALLBACK


def local_temp():
    """项目的 tmp 目录；子进程的 TEMP/TMP 都指向这里。"""
    d = os.path.join(HERE, 'tmp')
    os.makedirs(d, exist_ok=True)
    return d


def run(exe, name='player', wait=DEFAULT_WAIT):
    t0 = time.time()
    free_dir = os.path.dirname(os.path.abspath(exe))

    def log(msg):
        print(f'[{time.time() - t0:6.2f}s] {msg}', flush=True)

    if not os.path.isfile(exe):
        print(f'找不到游戏程序: {exe}')
        return 2

    if find_window('hspwnd0') or find_window('TEnigmaProtectorLoaderRegistrationForm'):
        print('游戏（或它的注册对话框）已经在运行，无需重复启动。')
        return 0

    log(f'启动 {os.path.basename(exe)}')
    log(f'工作目录 {free_dir}')
    env = os.environ.copy()
    tmp = local_temp()
    for key in ('TEMP', 'TMP', 'TMPDIR'):
        env[key] = tmp
    log(f'临时目录 {tmp}')
    proc = subprocess.Popen([exe], cwd=free_dir, env=env)
    pid = proc.pid
    mem = Mem(pid)

    # 1) 等注册对话框
    while time.time() - t0 < 20:
        if find_window('TEnigmaProtectorLoaderRegistrationForm', pid=pid):
            break
        if proc.poll() is not None:
            print(f'进程提前退出，代码 {proc.poll():#x}')
            return 4
        time.sleep(0.02)
    else:
        print('等不到注册对话框')
        return 4
    log('注册对话框已出现')

    # 2) 跳过启动完整性校验，再打补丁
    time.sleep(wait)
    base = image_base(mem)
    mk = markers_ok(mem, base)
    pretty = f'{mk[0]:#x} / {mk[1]:#x}' if mk else '(与预期不同，请注意)'
    log(f'映像基址 {base:#x}，描述符标记 {pretty}')
    mem.write(base + OFF_SAVE, PATCH)
    mem.write(base + OFF_MSG, PATCH)
    log(f'已打补丁: 描述符 {OFF_SAVE:#x} / {OFF_MSG:#x} = 0x03')

    # 3) 填注册信息（内容无关紧要，但两个框都不能空）
    wins = [w for w in enum_windows() if w['pid'] == pid]
    edits = sorted((w for w in wins if 'LoaderEdit' in w['cls']), key=lambda w: w['top'])
    memo = next((w for w in wins if 'LoaderMemo' in w['cls']), None)
    if edits:
        type_text(edits[-1]['hwnd'], name or 'player')
    if memo:
        type_text(memo['hwnd'], 'AAAA-BBBB-CCCC-DDDD-EEEE-FFFF')
    time.sleep(0.3)

    # 4) 点「注册」
    btn = find_window('LoaderButton', BTN_REGISTER, pid)
    if not btn:
        print('找不到「注册」按钮，请把窗口截图发给作者。')
        return 5
    post_click(btn['hwnd'])
    log('已点击「注册」')

    # 5) 点消息框的 OK，然后等游戏窗口
    ok_done = False
    deadline = time.time() + 40
    while time.time() < deadline:
        if not ok_done:
            b = find_window('LoaderButton', BTN_OK, pid)
            if b:
                time.sleep(0.3)
                post_click(b['hwnd'])
                ok_done = True
                log('已点击「成功注册」提示框的 OK')
        game = find_window(GAME_CLASS)
        if game and window_keyword() in game['text']:
            log(f'游戏已启动：{game["text"]!r} (窗口 {game["hwnd"]:#x})')
            print('\n成功，祝游玩愉快。')
            return 0
        if proc.poll() is not None:
            log(f'loader 退出，代码 {proc.poll():#x}')
            return 6
        time.sleep(0.1)

    print('超时：没等到游戏窗口')
    return 7


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)

    # 方便用法：直接把「文件或目录」作为第一个参数
    if argv and not argv[0].startswith('-'):
        cand = os.path.abspath(os.path.expanduser(argv[0]))
        if os.path.isfile(cand) or os.path.isdir(cand):
            argv = ['--exe', argv[0]] + argv[1:]

    args = build_parser().parse_args(argv)

    try:
        cfg = load_config(args.config)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f'读取配置失败: {exc}')
        return 2

    exe = resolve_exe(args.exe, args.game_dir, cfg)
    if not exe or not os.path.isfile(exe):
        print('找不到游戏主程序。')
        print('可以这样指定：')
        print('  python enigma_launch.py --exe "D:\\Games\\enigma\\你的文件名.exe"')
        print('  python enigma_launch.py "D:\\Games\\enigma"')
        print('  python enigma_launch.py --config launcher.json')
        print(f'当前目录: {HERE}')
        return 2

    name = args.target or cfg.get('player') or 'player'
    # 如果 target 实际是路径（上面已转成 --exe），这里不会拿到路径
    wait = args.wait if args.wait is not None else float(cfg.get('wait', DEFAULT_WAIT))

    if args.check:
        print('解析结果：')
        print(f'  主程序 : {exe}')
        print(f'  工作目录: {os.path.dirname(exe)}')
        print(f'  玩家名 : {name}')
        print(f'  等待   : {wait} 秒')
        return 0

    try:
        return run(exe, name, wait)
    except Exception as exc:                                    # noqa: BLE001
        print(f'出错: {exc!r}')
        return 1


if __name__ == '__main__':
    sys.exit(main())
