#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""恢复剧情脚本 scene1.hsp / scene2.hsp。

来源（按优先级）
----------------
1. **壳的虚拟文件（默认，真正的从零来源）**
   原版把 `scene1.hsp` / `scene2.hsp` 放在 Enigma 的虚拟文件系统里，运行时
   映射为 `%TEMP%\scene1.hsp` / `%TEMP%\scene2.hsp`（磁盘上看不到）。启动一次
   原程序后，用 HSP 自己的读文件函数（`0x4018F0`）读出即可——**不需要
   `data.dpm`，也不用进游戏**。

2. **进游戏扫描内存（退路）**
   `noteload` 在进入剧情时才把整份文件读进内存；本工具会轮询内存，按结构
   （`{0}` 序章 + `{N}` 场景 + `{end}` 收尾）裁切并校验；`{0}` 被覆盖时用残留的
   `{txt}` 补回，**缺 `{0}` 一律判失败**，不写盘。

3. **从现成的 DPM 文件里取**（`--from-dpm data.dpm`）
   解析 `DPMX` 目录取出 `scene1.hsp` / `scene2.hsp`。

用法:
    python extract\extract_scene.py [--exe <crackme.exe>] [--timeout 180]
    python extract\extract_scene.py --from-dpm <游戏目录>\data.dpm
"""
import argparse
import os
import re
import shutil
import struct
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

import paths                                                    # noqa: E402
import winmem                                                   # noqa: E402
import enigma_launch                                             # noqa: E402

# 末场固定签名的二进制形式（不把剧情正文写进源码）。
TAIL_MARKER = bytes.fromhex(
    '457465726e616c204c6561677565206f66204e6566696120506c7573')
FILE_TAIL = TAIL_MARKER + b'\r\n\xa1\xb6\xcd\xea\xa1\xb7'
SCENE_ID = re.compile(rb'\{(\d+)\}\r?\n')
# 序章场景在文件最前面的固定开头（HSP scene 引擎的 {pic}/{mc}/{txt} 指令）
PROLOGUE_HEADER = b'{0}\r\n{pic}\t"bg3"\r\n{mc}\t"mcIntro"\r\n{txt}\r\n'
PROLOGUE_START = b'{0}\r\n'
MIN_SIZE = 0x4000

# 原程序里 HSP 的 DPM/文件读取函数（本机这份 3.5 构建，地址稳定）
DPM_GETSIZE = 0x401280
DPM_GETFILE = 0x4018F0


def strip_comment(blob):
    """去掉文件开头的 `;` 注释行（原版 scene1.hsp 带一行 `;######...`）。"""
    while blob[:1] == b';':
        nl = blob.find(b'\n')
        if nl < 0:
            break
        blob = blob[nl + 1:]
    return blob


def validate(blob, full=True):
    """校验剧情脚本。

    full=True  ：中文剧情 scene1.hsp，必须包含序章和全部场景；
    full=False ：scene2.hsp（英文分支）可以很小，只要求是合法场景文件。
    """
    blob = strip_comment(blob)
    if len(blob) < (MIN_SIZE if full else 64):
        return False
    if not blob.startswith(PROLOGUE_START):
        return False
    if blob.count(b'{end}') < (30 if full else 1):
        return False
    if full:
        ids = [int(m.group(1)) for m in SCENE_ID.finditer(blob)]
        if len(ids) < 30 or ids[0] != 0:
            return False
    if b'\x00' in blob:
        return False
    return True


def _tail_end(blob, start, window=0x400000):
    hi = min(len(blob), start + window)
    # 用文件最后一场的固定结尾（…Plus + 《完》）定位真正的结尾，
    # 避免把缓冲区后面无关数据的 {end} 也算进来。
    t = blob.find(FILE_TAIL, start, hi)
    if t >= 0:
        e = blob.find(b'{end}', t, hi)
        if e >= 0:
            end = e + len(b'{end}')
            if blob[end:end + 2] == b'\r\n':
                end += 2
            return end
    e = blob.rfind(b'{end}', start, hi)
    if e < 0:
        return None
    end = e + len(b'{end}')
    if blob[end:end + 2] == b'\r\n':
        end += 2
    return end


def salvage_prologue(blob, one_start):
    """`{1}` 之前的 `{0}` 区域被覆盖时，尽量把序章文本补回来。

    返回 (`{0}` 场景 bytes) 或 None。只在能确认是序章文本时才返回。
    """
    lo = max(0, one_start - 0x3000)
    window = blob[lo:one_start]

    # 情况 1：{0} 区域基本完好，只是前面被塞了垃圾 -> 从 {0} 开始截
    j = window.rfind(PROLOGUE_START)
    if j >= 0:
        cand = window[j:]
        if b'\x00' not in cand:
            return cand

    # 情况 2：只剩正文。序章里有多段 {txt}，必须取**最早**的可用那段，
    # 取最后一个会把前面的正文整段丢掉。
    marker = b'{txt}\r\n'
    pos = window.find(marker)
    while pos >= 0:
        text = window[pos + len(marker):]
        # 正文要一直干净地接到 {end} 为止
        if (len(text) > 64 and b'\x00' not in text
                and text.rstrip().endswith(b'{end}')):
            if not text.endswith(b'\r\n'):
                text += b'\r\n'
            cand = PROLOGUE_HEADER + text
            if b'\x00' not in cand:
                return cand
        pos = window.find(marker, pos + 1)
    return None


def carve_blob(blob):
    """在内存块里找出完整脚本，返回 bytes 或 None。"""
    best = None

    # A. 正常路径：从 {0} 开始，到缓冲里最后一个 {end}
    for m in re.finditer(rb'\{0\}\r\n', blob):
        start = m.start()
        end = _tail_end(blob, start)
        if end is None:
            continue
        cand = blob[start:end]
        if validate(cand) and (best is None or len(cand) > len(best)):
            best = cand

    # B. 从 {1} 开始，尝试把被覆盖的 {0} 补回来
    for m in re.finditer(rb'\{1\}\r\n', blob):
        start = m.start()
        end = _tail_end(blob, start)
        if end is None:
            continue
        rest = blob[start:end]
        if b'\x00' in rest or rest.count(b'{end}') < 30:
            continue
        pro = salvage_prologue(blob, start)
        cand = (pro + rest) if pro else None
        if cand and validate(cand) and (best is None or len(cand) > len(best)):
            best = cand

    return best


def find_scenes(mem, log):
    """扫描内存，返回去重后的完整脚本列表。"""
    found = []
    for base, size, data in mem.iter_readable():
        if b'{end}' not in data:
            continue
        blob = carve_blob(data)
        if blob:
            found.append(blob)
            log('  候选剧情脚本 @ %#x，%d 字节，%d 个场景'
                % (base, len(blob), blob.count(b'{end}')))
            if len(found) >= 4:
                break
    uniq = []
    for b in found:
        if all(b != u for u in uniq):
            uniq.append(b)
    uniq.sort(key=len, reverse=True)
    return uniq


# ------------------------------------------------------------------ DPM 来源
def from_dpm(dpm_path, out_dir=None):
    d = open(dpm_path, 'rb').read()
    if d[:4] != b'DPMX':
        print('%s 不是 DPM 文件' % dpm_path)
        return 2
    optr, dent, _ns = struct.unpack_from('<III', d, 4)
    out_dir = out_dir or paths.WORK
    os.makedirs(out_dir, exist_ok=True)
    got = 0
    for i in range(dent):
        e = d[16 + i * 32:16 + (i + 1) * 32]
        name = e[:16].split(b'\0')[0].decode('latin-1')
        if name not in ('scene1.hsp', 'scene2.hsp'):
            continue
        _flags, _key, off, size = struct.unpack_from('<IIII', e, 16)
        blob = d[optr + off:optr + off + size]
        ok = validate(blob, full=(name == 'scene1.hsp'))
        dst = os.path.join(out_dir, name)
        if ok:
            open(dst, 'wb').write(strip_comment(blob))
            print('已写出 %s (%d 字节，含序章)' % (dst, len(strip_comment(blob))))
            got += 1
        else:
            print('警告：%s 里的 %s 不完整（缺少 {0} 序章），已跳过' % (dpm_path, name))
    if got == 0:
        return 3
    # 只取到一份时，另一份用同样的内容补齐（中文版实际只读 scene1）
    s1 = os.path.join(out_dir, 'scene1.hsp')
    s2 = os.path.join(out_dir, 'scene2.hsp')
    if os.path.isfile(s1) and not os.path.isfile(s2):
        shutil.copyfile(s1, s2)
        print('已用 scene1.hsp 补齐 scene2.hsp')
    elif os.path.isfile(s2) and not os.path.isfile(s1):
        shutil.copyfile(s2, s1)
        print('已用 scene2.hsp 补齐 scene1.hsp')
    return 0


# ------------------------------------------------------- 原版虚拟文件（首选）
def from_virtual_temp(exe, out_dir=None, log=print):
    """启动原程序，读出 Enigma 映射到 <项目>\\tmp 的 scene1/2.hsp。

    这是最干净的“从零”来源：原版把剧情放在壳的虚拟文件里，磁盘上没有
    data.dpm / scene1.hsp；但进程内用 HSP 自己的读文件函数可以拿到。
    不需要进游戏、不需要存档、不需要 data.dpm。

    注意：启动子进程时会把 TEMP/TMP 指向 <项目>\\tmp，所以壳映射出来的
    虚拟文件也在项目内，不会碰到系统临时目录。
    """
    paths.use_local_temp()
    out_dir = out_dir or paths.WORK
    os.makedirs(out_dir, exist_ok=True)
    s1 = os.path.join(out_dir, 'scene1.hsp')
    s2 = os.path.join(out_dir, 'scene2.hsp')
    temp = paths.TMP
    log('启动原程序，读取 Enigma 映射出的 %s\\scene1/2.hsp …' % temp)

    exe_name = os.path.basename(exe)
    winmem.kill(exe_name)
    time.sleep(0.5)
    enigma_launch.run(exe, 'player', enigma_launch.DEFAULT_WAIT)
    pid = winmem.find_pid(exe_name)
    if not pid:
        log('找不到运行中的 %s' % exe_name)
        return 4
    mem = winmem.Mem(pid)
    remote = winmem.Remote(mem)
    ok1 = ok2 = False
    try:
        for name, full, dst in (('scene1.hsp', True, s1),
                                ('scene2.hsp', False, s2)):
            path = os.path.join(temp, name)
            arg = remote.alloc(0x400)
            try:
                remote.write(arg, path.encode('mbcs') + b'\x00')
                size = remote.call(DPM_GETSIZE, [arg])
                if not size or size == 0xFFFFFFFF or size > 0x2000000:
                    log('  读不到 %s（size=%s）' % (path, size))
                    continue
                buf = remote.call(DPM_GETFILE, [arg])
                if not buf or buf >= 0x80000000:
                    log('  读取 %s 失败' % path)
                    continue
                data = mem.read(buf, size)
                if not data or not validate(data, full=full):
                    log('  %s 内容不完整（%d 字节）' % (name, len(data or b'')))
                    continue
                open(dst, 'wb').write(strip_comment(data))
                log('  已写出 %s (%d 字节)' % (dst, len(strip_comment(data))))
                if full:
                    ok1 = True
                else:
                    ok2 = True
            finally:
                remote.free(arg)
    finally:
        remote.close()
        mem.close()
        winmem.kill(exe_name)
    if ok1 and not ok2:
        shutil.copyfile(s1, s2)
        log('  scene2.hsp 未取到，已用 scene1.hsp 补齐')
        ok2 = True
    return 0 if (ok1 and ok2) else 3


# ------------------------------------------------------------------ 内存来源
def run(exe, out_dir=None, timeout=180, log=print):
    paths.use_local_temp()
    paths.ensure_dirs()
    out_dir = out_dir or paths.WORK
    s1 = os.path.join(out_dir, 'scene1.hsp')
    s2 = os.path.join(out_dir, 'scene2.hsp')
    os.makedirs(out_dir, exist_ok=True)
    if os.path.isfile(s1) and validate(open(s1, 'rb').read()):
        log('已有完整的 %s，跳过。' % s1)
        return 0

    # 1) 原版壳里的虚拟文件（真正的从零来源，不需要 data.dpm / 进游戏）
    if (from_virtual_temp(exe, out_dir, log) == 0
            and os.path.isfile(s1) and validate(open(s1, 'rb').read())):
        return 0

    # 2) 某些构建会把文件解到 <项目>\tmp（真实文件）
    temp = paths.TMP
    for nm, full, dst in (('scene1.hsp', True, s1), ('scene2.hsp', False, s2)):
        src = os.path.join(temp, nm)
        if os.path.isfile(src):
            blob = open(src, 'rb').read()
            if validate(blob, full=full):
                open(dst, 'wb').write(strip_comment(blob))
                log('从 %s 取得 %s' % (src, nm))

    # 3) 游戏目录的 data.dpm（可选，有就用，快）
    dpm = os.path.join(os.path.dirname(os.path.abspath(exe)), 'data.dpm')
    if os.path.isfile(dpm):
        log('发现 %s，直接从脚本库读取剧情 …' % dpm)
        if (from_dpm(dpm, out_dir) == 0 and os.path.isfile(s1)
                and validate(open(s1, 'rb').read())):
            return 0
        log('脚本库里的剧情不完整，改为进游戏扫描内存。')

    winmem.kill(os.path.basename(exe))
    time.sleep(0.6)
    log('启动游戏；请在窗口里「开新游戏 / 进入有剧情的画面」以加载剧情脚本。')
    enigma_launch.run(exe, 'player', enigma_launch.DEFAULT_WAIT)
    exe_name = os.path.basename(exe)
    pid = winmem.find_pid(exe_name)
    if not pid:
        log('找不到运行中的 %s' % exe_name)
        return 4
    mem = winmem.Mem(pid)

    deadline = time.time() + timeout
    scenes = []
    while time.time() < deadline:
        scenes = find_scenes(mem, log)
        if scenes:
            break
        time.sleep(0.5)
    winmem.kill(exe_name)

    if not scenes:
        log('没抓到剧情脚本（可能还没进入剧情）。')
        return 3
    best = scenes[0]
    open(s1, 'wb').write(best)
    log('已写出 %s (%d 字节，%d 个场景)' % (s1, len(best), best.count(b'{end}')))
    second = next((b for b in scenes[1:] if b != best), best)
    open(s2, 'wb').write(second)
    log('已写出 %s (%d 字节)' % (s2, len(second)))
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description='恢复 scene1/2.hsp（内存抓取或从 DPM 取）')
    ap.add_argument('--exe', help='crackme.exe 路径')
    ap.add_argument('-g', '--game-dir', help='游戏目录')
    ap.add_argument('--timeout', type=int, default=180, help='等待剧情加载的秒数')
    ap.add_argument('--from-dpm', help='从现成的 data.dpm 里取剧情脚本')
    ap.add_argument('--out-dir', help='输出目录（默认 tmp\\work\\）')
    args = ap.parse_args(argv)

    paths.use_local_temp()
    if args.from_dpm:
        return from_dpm(args.from_dpm, args.out_dir)

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
        return run(exe, args.out_dir, args.timeout)
    finally:
        paths.cleanup_extract_exe()


if __name__ == '__main__':
    sys.exit(main())
