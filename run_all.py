#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""enigma「从零到可运行」一键流水线。

    bk\crackme.exe  ──提取──►  tmp\work\*  ──重建──►  out\*  ──安装──►  test\*

默认从 bk\crackme.exe 出发：先把 test\ 恢复成一份可运行的原始程序副本，
再从 test\crackme.exe 现场提取 OEP 映像 / start.ax / scene1.hsp / scene2.hsp，
重建出无壳可执行文件，装进 test\ 并试跑。整个过程不读取、不写入项目文件夹
以外的路径；临时文件全部在 tmp\ 下。

用法:
    python run_all.py                    # 提取 + 重建 + 安装（缺原料时才提取）
    python run_all.py --from-scratch     # 清掉 tmp\work 与 out 后从零重建
    python run_all.py --force            # 强制重新提取并重建
    python run_all.py --skip-extract     # 只用 tmp\work 里已有的原料重建
    python run_all.py --with-scene       # 顺带恢复剧情脚本（默认构建阶段会做）
    python run_all.py --verify           # 重建后放进 test\ 试跑，确认出现游戏窗口
    python run_all.py --restore-test     # 先用 bk\ 覆盖 test\ 的原始文件再重建
    python run_all.py --no-scene         # 不打包剧情（进入剧情会报错）
    python run_all.py --exe bk\crackme.exe --game-dir test

产出（out\）：
    unenigma.exe          双文件版主程序（需同目录 data.dpm + unixTime.dll）
    data.dpm              脚本库（start.ax 预 XOR + scene 明文）
    unenigma_single.exe   单文件版（脚本库内嵌，只需再带 unixTime.dll）
    unixTime.dll          替代 DLL（需要 binutils 才能重建；缺则用已带版本）
"""
import argparse
import os
import shutil
import subprocess
import sys
import time

sys.dont_write_bytecode = True

ROOT = os.path.dirname(os.path.abspath(__file__))
EXTRACT = os.path.join(ROOT, 'extract')
BUILD = os.path.join(ROOT, 'build')
sys.path.insert(0, EXTRACT)
sys.path.insert(0, ROOT)

import paths                                                    # noqa: E402
from enigma_launch import enum_windows, is_game_window                           # noqa: E402

WORK = paths.WORK
OUT = paths.OUT
PY = sys.executable or 'python'


def run_script(path, *args, optional=False):
    cmd = [PY, path] + [str(a) for a in args]
    print('  $ %s' % ' '.join(os.path.basename(c) if os.path.isabs(c) else c for c in cmd),
          flush=True)
    r = subprocess.run(cmd)
    if r.returncode != 0:
        if optional:
            print('  （可选步骤失败，继续）')
            return False
        raise SystemExit('步骤失败（代码 %d）：%s' % (r.returncode, path))
    return True


def wipe_scratch():
    for d in (paths.WORK, paths.OUT, paths.CRASH):
        if os.path.isdir(d):
            print('  删除 %s' % d)
            shutil.rmtree(d, ignore_errors=True)
    paths.ensure_dirs()


def extract(exe, force, with_scene, scene_timeout):
    import extract_oep
    import extract_script
    import extract_scene
    oep = os.path.join(WORK, 'app_img_oep.bin')
    ax = os.path.join(WORK, 'start.ax')
    if force or not os.path.isfile(oep):
        print('\n== [1/3] 抓取 OEP 原程序映像 ==')
        if extract_oep.run(exe, out=oep) != 0:
            raise SystemExit('OEP 映像提取失败')
    else:
        print('\n== [1/3] 已有 app_img_oep.bin，跳过 ==')
    if force or not os.path.isfile(ax):
        print('\n== [2/3] 提取脚本 start.ax ==')
        if extract_script.run(exe, out=ax) != 0:
            raise SystemExit('start.ax 提取失败')
    else:
        print('\n== [2/3] 已有 start.ax，跳过 ==')
    s1 = os.path.join(WORK, 'scene1.hsp')
    if with_scene and (force or not scene_ok(s1)):
        print('\n== [3/3] 尝试恢复剧情脚本 ==')
        extract_scene.run(exe, timeout=scene_timeout)
        if not scene_ok(s1):
            print('  没抓到完整剧情脚本；构建阶段会再从壳的虚拟文件 / data.dpm 取。')
    else:
        print('\n== [3/3] 剧情脚本由构建阶段自动补齐 ==')


def _strip_scene_comment(blob):
    while blob[:1] == b';':                 # 原版 scene1.hsp 带一行 ;### 注释
        nl = blob.find(b'\n')
        if nl < 0:
            break
        blob = blob[nl + 1:]
    return blob


def scene_ok(path, full=True):
    if not os.path.isfile(path):
        return False
    blob = _strip_scene_comment(open(path, 'rb').read())
    if b'\x00' in blob or not blob.startswith(b'{0}\r\n'):
        return False
    if not full:
        return b'{end}' in blob
    return len(blob) >= 0x4000 and blob.count(b'{end}') >= 30


def prep_scenes(run_exe, game_dir, scene_dpm, no_scene):
    """返回要打包的 scene 文件列表；从原程序虚拟文件 / DPM 自动补齐。"""
    s1 = os.path.join(WORK, 'scene1.hsp')
    s2 = os.path.join(WORK, 'scene2.hsp')
    if no_scene:
        print('  已指定 --no-scene：不打包剧情脚本。')
        return []
    if scene_ok(s1) and scene_ok(s2, full=False):
        return [s1, s2]

    import extract_scene

    # 1) 原版壳里的虚拟文件（真正的从零来源，不需要 data.dpm、也不用进游戏）
    if run_exe:
        print('  从原程序读取剧情（Enigma 映射到 tmp 的 scene1/2.hsp）…')
        try:
            extract_scene.from_virtual_temp(run_exe, WORK)
            if scene_ok(s1):
                if not scene_ok(s2, full=False):
                    shutil.copyfile(s1, s2)
                return [s1, s2]
        except Exception as exc:                                # noqa: BLE001
            print('  从原程序读取剧情失败：%s' % exc)

    # 2) 现成的脚本库（可选，有就用）
    srcs = []
    if scene_dpm:
        srcs.append(scene_dpm)
    if game_dir:
        srcs.append(os.path.join(game_dir, 'data.dpm'))
    srcs.append(os.path.join(OUT, 'data.dpm'))
    for src in srcs:
        if not os.path.isfile(src):
            continue
        print('  从 %s 读取剧情脚本 …' % src)
        try:
            if extract_scene.from_dpm(src, WORK) == 0 and scene_ok(s1):
                if not scene_ok(s2, full=False):
                    shutil.copyfile(s1, s2)
                return [s1, s2]
        except Exception as exc:                                # noqa: BLE001
            print('  从 %s 取剧情脚本失败：%s' % (src, exc))

    if scene_ok(s1):
        if not scene_ok(s2, full=False):
            shutil.copyfile(s1, s2)
        return [s1, s2]
    raise SystemExit(
        '没有完整可用的剧情脚本（必须带 {0} 序章）。\n'
        '  - 从原程序自动取：python extract\\extract_scene.py\n'
        '  - 或从现有脚本库取：python extract\\extract_scene.py --from-dpm <data.dpm>\n'
        '  - 或把完整的 scene1.hsp 放进 %s\n'
        '  - 只想要无剧情版：加 --no-scene（进入剧情时会报错）' % WORK)


def build(run_exe, game_dir=None, scene_dpm=None, no_scene=False):
    main = os.path.join(OUT, 'unenigma.exe')
    dpm = os.path.join(OUT, 'data.dpm')
    single = os.path.join(OUT, 'unenigma_single.exe')
    img = os.path.join(WORK, 'app_img_oep.bin')
    ax = os.path.join(WORK, 'start.ax')

    for f in (img, ax):
        if not os.path.isfile(f):
            raise SystemExit('缺少原料：%s（先运行提取，或去掉 --skip-extract）' % f)

    print('\n== 重建可执行文件 ==')
    run_script(os.path.join(BUILD, 'build_exe.py'), main, img)      # PE + 导入表
    run_script(os.path.join(BUILD, 'restore_winmain.py'), main)     # 写回原生 WinMain
    run_script(os.path.join(BUILD, 'add_entry.py'), main)           # 入口桩 + AddressOfEntryPoint
    run_script(os.path.join(BUILD, 'add_tls.py'), main)             # TLS 数据目录

    print('\n== 构造脚本库 data.dpm ==')
    extras = prep_scenes(run_exe, game_dir, scene_dpm, no_scene)
    if extras:
        # 序章脚本必须能在 %TEMP% 下被打开（原版由 Enigma 虚拟文件提供），
        # 把校验过的 scene 文件写进 exe 的启动桩里。
        run_script(os.path.join(BUILD, 'add_scene_boot.py'), main, *extras)
    run_script(os.path.join(BUILD, 'build_dpm.py'), dpm, ax, *extras)

    print('\n== 生成单文件版 ==')
    run_script(os.path.join(BUILD, 'build_singlefile.py'), main, single, dpm)

    print('\n== 重建 unixTime.dll（可选，需 binutils）==')
    run_script(os.path.join(BUILD, 'build_unixtime.py'), optional=True)

    print('\n产物：')
    for f in (main, dpm, single, os.path.join(OUT, 'unixTime.dll')):
        if os.path.isfile(f):
            print('  %-32s %s' % (os.path.basename(f), '{:,}'.format(os.path.getsize(f))))
    if not os.path.isfile(os.path.join(OUT, 'unixTime.dll')):
        print('  （未生成 unixTime.dll：请安装 binutils(as/dlltool/ld) 后重跑，'
              '或从别处把 unixTime.dll 放进 out\\）')


def install(game_dir):
    """把最终产物装进 test\\（这是实际运行目录）。"""
    if not game_dir:
        return
    mapping = {
        'unenigma.exe': 'unenigma.exe',
        'data.dpm': 'data.dpm',
        'unenigma_single.exe': 'unenigma_single.exe',
        'unixTime.dll': 'unixTime.dll',
    }
    print('\n== 安装到 %s ==' % game_dir)
    for src_name, dst_name in mapping.items():
        src = os.path.join(OUT, src_name)
        if not os.path.isfile(src):
            continue
        dst = os.path.join(game_dir, dst_name)
        shutil.copyfile(src, dst)
        print('  %-24s -> %s' % (src_name, dst))


def verify(game_dir, timeout=40):
    """直接运行 test\\unenigma_single.exe，确认出现游戏窗口。"""
    import winmem
    single = os.path.join(game_dir, 'unenigma_single.exe')
    dll = os.path.join(game_dir, 'unixTime.dll')
    if not os.path.isfile(single):
        print('  （没有单文件版，跳过校验）')
        return True
    if not os.path.isfile(dll) and os.path.isfile(os.path.join(OUT, 'unixTime.dll')):
        shutil.copyfile(os.path.join(OUT, 'unixTime.dll'), dll)
    winmem.kill(os.path.basename(single))
    time.sleep(0.5)
    print('  试跑 %s …' % single)
    env = os.environ.copy()
    for k in ('TEMP', 'TMP', 'TMPDIR'):
        env[k] = paths.TMP
    p = subprocess.Popen([single], cwd=game_dir, env=env)
    t0 = time.time()
    ok = False
    while time.time() - t0 < timeout:
        for w in enum_windows():
            if is_game_window(w):
                print('  [%5.2fs] 游戏窗口：%r' % (time.time() - t0, w['text']))
                ok = True
                break
        if ok or p.poll() is not None:
            break
        time.sleep(0.1)
    try:
        p.kill()
    except Exception:
        pass
    winmem.kill(os.path.basename(single))
    if ok:
        print('  校验通过：重建出的程序可以进入游戏。')
    else:
        print('  校验未通过（没看到游戏窗口）。')
    return ok


def main(argv=None):
    ap = argparse.ArgumentParser(description='enigma 从零到可运行的一键流水线')
    ap.add_argument('--exe', help='原始 crackme.exe 路径（默认 bk\\crackme.exe）')
    ap.add_argument('-g', '--game-dir', help='运行/测试目录（默认 test\\）')
    ap.add_argument('--force', action='store_true', help='强制重新提取')
    ap.add_argument('--from-scratch', action='store_true',
                    help='清掉 tmp\\work / out\\ 后从零开始')
    ap.add_argument('--restore-test', action='store_true',
                    help='先用 bk\\ 覆盖 test\\ 的原始文件（保留 save/user）')
    ap.add_argument('--skip-extract', action='store_true', help='跳过提取，直接用 tmp\\work 原料')
    ap.add_argument('--with-scene', action='store_true', help='尝试恢复剧情脚本')
    ap.add_argument('--scene-timeout', type=int, default=180)
    ap.add_argument('--scene-dpm', help='从指定的 data.dpm 里取剧情脚本（缺失/损坏时）')
    ap.add_argument('--no-scene', action='store_true', help='不打包剧情脚本（进入剧情会报错）')
    ap.add_argument('--verify', action='store_true', help='重建后试跑校验')
    ap.add_argument('--no-verify', action='store_true', help=argparse.SUPPRESS)
    args = ap.parse_args(argv)

    paths.use_local_temp()
    paths.ensure_dirs()
    if args.from_scratch:
        print('== 从零开始：清理 tmp\\work 与 out ==')
        wipe_scratch()

    source = paths.find_source_exe(args.exe)
    if not source:
        print('找不到原始 crackme.exe（默认 bk\\crackme.exe）。'
              '用 --exe 指定，或先确认 bk\\ 完整。')
        return 2
    if not paths._inside(source):
        print('拒绝访问项目文件夹以外的路径：%s' % source)
        print('请把原始程序放进 bk\\，或用项目内的路径。')
        return 2
    run_exe = paths.ensure_target_game(source, restore=args.restore_test)
    if not run_exe:
        print('无法准备 test\\crackme.exe；请检查 bk\\ 是否完整。')
        return 2
    extract_exe = paths.prepare_extract_exe()
    if extract_exe:
        run_exe = extract_exe
    game_dir = paths.find_game_dir(args.game_dir) or os.path.dirname(run_exe)
    if os.path.abspath(game_dir) == os.path.abspath(paths.SOURCE_DIR):
        print('  bk\\ 是原始备份，不能作为运行目录；改用 test\\。')
        game_dir = paths.TARGET_DIR
        run_exe = extract_exe or os.path.join(game_dir, 'crackme.exe')

    print('项目根目录 : %s' % ROOT)
    print('原始备份   : %s' % source)
    print('运行目录   : %s' % game_dir)
    print('临时目录   : %s' % paths.TMP)
    print('运行程序   : %s' % run_exe)

    try:
        if not args.skip_extract:
            need = not (os.path.isfile(os.path.join(WORK, 'app_img_oep.bin'))
                        and os.path.isfile(os.path.join(WORK, 'start.ax')))
            extract(run_exe, args.force or need, args.with_scene, args.scene_timeout)
        else:
            print('\n== 跳过提取，直接重建 ==')

        build(run_exe, game_dir, args.scene_dpm, args.no_scene)
        install(game_dir)

        if args.verify and game_dir:
            print('\n== 试跑校验 ==')
            verify(game_dir)
        elif args.verify:
            print('\n（没找到运行目录，无法校验；用 --game-dir 指定）')
    finally:
        paths.cleanup_extract_exe()
    print('\n完成。')
    return 0


if __name__ == '__main__':
    sys.exit(main())
