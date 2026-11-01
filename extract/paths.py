#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""项目路径解析（供 extract / build / run_all 共用）。

本项目完全自包含，不访问项目文件夹以外的路径：

    bk\       原始程序备份（crackme.exe + 游戏资源，保持原样）
    test\     测试用的工作目录（从 bk 复制；重建产物也装到这里）
    tmp\      所有临时文件（提取中间产物、崩溃转储、工具构建目录）
    out\      最终产物（unenigma*.exe / data.dpm / unixTime.dll）

优先级：
  1. 命令行显式给出的路径
  2. 环境变量 ENIGMA_GAME / ENIGMA_SOURCE / ENIGMA_EXE
  3. 项目根目录下的 launcher.json
  4. 项目内固定目录 test\（运行/测试）与 bk\（原始备份）

重要：所有子进程（crackme.exe / 重建后的游戏）都会把 TEMP/TMP 指向
<项目>\tmp，避免往系统 %TEMP% 或项目外写任何文件。
"""
import hashlib
import json
import os
import shutil
import sys
import tempfile

# 临时文件一律放 <项目>\tmp，也不要生成 __pycache__
sys.dont_write_bytecode = True

HERE = os.path.dirname(os.path.abspath(__file__))          # ...\extract
ROOT = os.path.dirname(HERE)                               # ...\project

TMP = os.path.join(ROOT, 'tmp')                            # 所有临时文件
WORK = os.path.join(TMP, 'work')                           # 提取中间产物
CRASH = os.path.join(TMP, 'crashdumps')                    # WER 转储
OUT = os.path.join(ROOT, 'out')                            # 最终产物
SOURCE_DIR = os.path.join(ROOT, 'bk')                      # 原始备份
TARGET_DIR = os.path.join(ROOT, 'test')                    # 测试目录

CRACKME_NAMES = ('crackme.exe',)
# restore 时不要从备份覆盖的运行期文件（配置、许可、错误日志、产物）
SKIP_TOP = {'config.txt', '0_lts_option.ini', 'license.s2', 'error.txt',
            'data.dpm'}


def use_local_temp():
    """把本进程及所有子进程的临时目录重定向到 <项目>\\tmp。"""
    os.makedirs(TMP, exist_ok=True)
    for key in ('TEMP', 'TMP', 'TMPDIR'):
        os.environ[key] = TMP
    # tempfile 会缓存 gettempdir() 的结果，这里清掉缓存
    tempfile.tempdir = TMP
    return TMP


def ensure_dirs():
    for d in (TMP, WORK, CRASH, OUT, TARGET_DIR):
        os.makedirs(d, exist_ok=True)


def _exe_in_dir(d, names=CRACKME_NAMES):
    d = os.path.abspath(os.path.expanduser(d))
    for nm in names:
        p = os.path.join(d, nm)
        if os.path.isfile(p):
            return p
    return None


def _config():
    path = os.path.join(ROOT, 'launcher.json')
    if not os.path.isfile(path):
        return {}
    try:
        with open(path, 'r', encoding='utf-8-sig') as f:
            cfg = json.load(f)
    except (OSError, ValueError):
        return {}
    if not isinstance(cfg, dict):
        return {}
    base = os.path.dirname(path)
    for key in ('exe', 'game_dir', 'source_exe', 'source_dir', 'target_dir'):
        v = cfg.get(key)
        if v and not os.path.isabs(v):
            cfg[key] = os.path.normpath(os.path.join(base, v))
    return cfg


def _config_dir(key):
    cfg = _config()
    v = cfg.get(key)
    if not v:
        return None
    d = v if os.path.isdir(v) else os.path.dirname(v)
    return d if os.path.isdir(d) else None


def _inside(path):
    try:
        p = os.path.abspath(path)
        return os.path.commonpath([p, ROOT]) == ROOT
    except (ValueError, OSError):
        return False


def find_game_dir(explicit=None):
    """返回运行/测试用的游戏目录（默认 test\\），找不到返回 None。"""
    cands = []
    if explicit:
        cands.append(explicit)
    if os.environ.get('ENIGMA_GAME'):
        cands.append(os.environ['ENIGMA_GAME'])
    cfg_dir = _config_dir('game_dir')
    if cfg_dir:
        cands.append(cfg_dir)
    exe = os.environ.get('ENIGMA_EXE')
    if exe:
        cands.append(os.path.dirname(os.path.abspath(exe)))
    cfg_exe = _config().get('exe')
    if cfg_exe:
        cands.append(os.path.dirname(cfg_exe))
    cands += [TARGET_DIR, SOURCE_DIR]

    for c in cands:
        if not c:
            continue
        c = os.path.abspath(os.path.expanduser(c))
        if _inside(c) and os.path.isdir(c) and _exe_in_dir(c):
            return c
    for c in cands:
        if not c:
            continue
        c = os.path.abspath(os.path.expanduser(c))
        if _inside(c) and os.path.isdir(c):
            return c
    return None


def find_source_exe(explicit=None):
    """返回原始 crackme.exe（默认 bk\\crackme.exe；只在项目内查找）。"""
    if explicit:
        p = os.path.abspath(os.path.expanduser(explicit))
        if os.path.isfile(p):
            return p
        if os.path.isdir(p):
            return _exe_in_dir(p)
        return None
    cfg = _config()
    for key in ('source_exe', 'exe'):
        v = cfg.get(key)
        if v:
            p = v if os.path.isfile(v) else _exe_in_dir(os.path.dirname(v))
            if p and os.path.isfile(p):
                return p
    for env in ('ENIGMA_SOURCE', 'ENIGMA_EXE', 'ENIGMA_GAME'):
        v = os.environ.get(env)
        if not v:
            continue
        p = os.path.abspath(os.path.expanduser(v))
        if os.path.isfile(p):
            return p
        if os.path.isdir(p):
            hit = _exe_in_dir(p)
            if hit:
                return hit
    p = _exe_in_dir(SOURCE_DIR)
    if p:
        return p
    return _exe_in_dir(TARGET_DIR)


def find_crackme(explicit=None, game_dir=None):
    """返回要运行/提取的 crackme.exe（优先 test\\，其次 bk\\）。"""
    if explicit:
        p = os.path.abspath(os.path.expanduser(explicit))
        if os.path.isfile(p):
            return p
        if os.path.isdir(p):
            return _exe_in_dir(p)
        return None
    d = find_game_dir(game_dir)
    if d:
        p = _exe_in_dir(d)
        if p:
            return p
    return find_source_exe()


def _sha256(path, chunk=1 << 20):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        while True:
            b = f.read(chunk)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def same_file(a, b):
    if not (os.path.isfile(a) and os.path.isfile(b)):
        return False
    if os.path.getsize(a) != os.path.getsize(b):
        return False
    return _sha256(a) == _sha256(b)


def _link_or_copy(src, dst):
    try:
        if os.path.exists(dst):
            os.remove(dst)
        os.link(src, dst)          # 同卷硬链接，不占额外空间
    except OSError:
        shutil.copy2(src, dst)


def extract_name():
    """提取时使用的映像名；默认 target_extract.exe。"""
    return os.environ.get('ENIGMA_EXTRACT_NAME', 'target_extract.exe')


WER_KEY = (r'Software\Microsoft\Windows\Windows Error Reporting'
           r'\LocalDumps\%s')


def _wer_hklm_configured(name):
    """HKLM 里是否有该映像名的 LocalDumps 配置（WER 只认 HKLM）。"""
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, WER_KEY % name):
            return True
    except OSError:
        return False


def prepare_extract_exe():
    """准备一个用于提取的临时副本（不同文件名）。

    WER LocalDumps 是按「映像名」配置的（HKLM，需要管理员）。如果系统里
    已经给 crackme.exe 配了别的目录，反复崩溃后也可能被 WER 节流；用一个
    单独的名字跑提取，就能只走本项目自己的配置（<项目>\\tmp\\crashdumps）。
    如果该名字还没有配置、而 crackme.exe 已经配置，则自动退回主程序本身；
    也可以用 ENIGMA_EXTRACT_NAME 显式指定映像名。
    """
    src = os.path.join(TARGET_DIR, 'crackme.exe')
    if not os.path.isfile(src):
        return None
    name = extract_name()
    if not name or name.lower() == 'crackme.exe':
        return src
    explicit = os.environ.get('ENIGMA_EXTRACT_NAME')
    if not explicit and not _wer_hklm_configured(name) \
            and _wer_hklm_configured('crackme.exe'):
        return src
    dst = os.path.join(TARGET_DIR, name)
    if not os.path.isfile(dst) or not same_file(src, dst):
        _link_or_copy(src, dst)
    return dst


def cleanup_extract_exe():
    name = extract_name()
    if not name or name.lower() == 'crackme.exe':
        return
    p = os.path.join(TARGET_DIR, name)
    try:
        if os.path.isfile(p):
            os.remove(p)
    except OSError:
        pass


def ensure_target_game(source=None, restore=False, log=print):
    """确保 test\\ 是一份可运行的原始程序副本。

    - crackme.exe 缺失或与备份不一致 -> 从备份恢复；
    - 资源目录/文件缺失 -> 从备份补齐（不按名字写死，整目录同步）；
    - restore=True -> 用备份覆盖 test 的顶层文件和目录，但保留
      config / licence / save / user 等运行数据。
    返回 test\\crackme.exe 路径。
    """
    ensure_dirs()
    os.makedirs(TARGET_DIR, exist_ok=True)
    src_dir = SOURCE_DIR
    if source:
        src_dir = os.path.dirname(os.path.abspath(source))
    src_exe = _exe_in_dir(src_dir) or find_source_exe()
    dst_exe = os.path.join(TARGET_DIR, 'crackme.exe')

    if src_exe and os.path.abspath(src_exe) != os.path.abspath(dst_exe):
        need = restore or not os.path.isfile(dst_exe) or not same_file(src_exe, dst_exe)
        if need:
            shutil.copy2(src_exe, dst_exe)
            log('  已从 %s 恢复 %s' % (src_exe, dst_exe))
    elif not os.path.isfile(dst_exe):
        log('  警告：找不到可用于恢复的 crackme.exe')

    if os.path.isdir(src_dir) and os.path.abspath(src_dir) != os.path.abspath(TARGET_DIR):
        for name in sorted(os.listdir(src_dir)):
            if name in SKIP_TOP:
                continue
            s = os.path.join(src_dir, name)
            d = os.path.join(TARGET_DIR, name)
            if os.path.isdir(s):
                if not os.path.isdir(d):
                    shutil.copytree(s, d)
                    log('  已从 %s 补齐目录 %s\\' % (src_dir, name))
            elif os.path.isfile(s) and (restore or not os.path.isfile(d)):
                shutil.copy2(s, d)
                log('  已从 %s 补齐 %s' % (src_dir, name))

    return dst_exe if os.path.isfile(dst_exe) else None
