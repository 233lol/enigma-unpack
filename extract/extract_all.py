#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""一键提取：从 crackme.exe 得到重建所需的全部原料。

     tmp\work\app_img_oep.bin   OEP（CRT 前）原程序映像
     tmp\work\start.ax          脚本主体（明文 HSP3 对象）
     tmp\work\scene1.hsp        剧情脚本（可选，--with-scene）

用法:
    python extract\extract_all.py [--exe <crackme.exe>] [--force] [--with-scene]
"""
import argparse
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

import paths                                                    # noqa: E402
import extract_oep                                              # noqa: E402
import extract_script                                           # noqa: E402
import extract_scene                                            # noqa: E402


def _scene_ok(path):
    if not os.path.isfile(path):
        return False
    b = open(path, 'rb').read()
    while b[:1] == b';':
        nl = b.find(b'\n')
        if nl < 0:
            break
        b = b[nl + 1:]
    return (len(b) >= 0x4000 and b.startswith(b'{0}\r\n')
            and b.count(b'{end}') >= 30 and b'\x00' not in b)


def main(argv=None):
    ap = argparse.ArgumentParser(description='从 crackme.exe 提取重建原料')
    ap.add_argument('--exe', help='crackme.exe 路径')
    ap.add_argument('-g', '--game-dir', help='游戏目录')
    ap.add_argument('--force', action='store_true', help='即使已存在也重新提取')
    ap.add_argument('--with-scene', action='store_true', help='顺带尝试恢复剧情脚本')
    ap.add_argument('--scene-timeout', type=int, default=180)
    ap.add_argument('--scene-dpm', help='从指定的 data.dpm 里取剧情脚本（兜底）')
    args = ap.parse_args(argv)

    paths.use_local_temp()
    src = paths.find_source_exe(args.exe)
    if not src:
        print('找不到原始 crackme.exe（默认 bk\\crackme.exe）。')
        return 2
    exe = paths.ensure_target_game(src)
    if not exe:
        print('无法准备 test\\crackme.exe。')
        return 2
    exe = paths.prepare_extract_exe() or exe
    paths.ensure_dirs()
    print('crackme.exe = %s' % exe)
    print('work        = %s' % paths.WORK)

    oep = os.path.join(paths.WORK, 'app_img_oep.bin')
    ax = os.path.join(paths.WORK, 'start.ax')

    if args.force or not os.path.isfile(oep):
        print('\n[1/3] 抓取 OEP 原程序映像 …')
        rc = extract_oep.run(exe, out=oep)
        if rc != 0:
            print('失败：OEP 映像未取得（代码 %d）' % rc)
            return rc
    else:
        print('\n[1/3] 已有 %s，跳过' % oep)

    if args.force or not os.path.isfile(ax):
        print('\n[2/3] 提取脚本 start.ax …')
        rc = extract_script.run(exe, out=ax)
        if rc != 0:
            print('失败：start.ax 未取得（代码 %d）' % rc)
            return rc
    else:
        print('\n[2/3] 已有 %s，跳过' % ax)

    s1 = os.path.join(paths.WORK, 'scene1.hsp')
    if args.with_scene and (args.force or not _scene_ok(s1)):
        print('\n[3/3] 尝试恢复剧情脚本 …')
        rc = extract_scene.run(exe, timeout=args.scene_timeout)
        if rc != 0 or not _scene_ok(s1):
            src = args.scene_dpm or os.path.join(os.path.dirname(exe), 'data.dpm')
            if os.path.isfile(src):
                print('  内存抓取没得到完整脚本，改从 %s 取 …' % src)
                extract_scene.from_dpm(src, paths.WORK)
        if not _scene_ok(s1):
            print('  （没有完整剧情脚本；重建时会再尝试 data.dpm，或加 --no-scene）')
    else:
        print('\n[3/3] 跳过剧情脚本（可用 --with-scene 尝试）')

    paths.cleanup_extract_exe()
    print('\n提取完成。')
    return 0


if __name__ == '__main__':
    sys.exit(main())
