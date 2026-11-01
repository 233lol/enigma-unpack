#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""配置 Windows 错误报告 (WER) 的 LocalDumps，让提取程序崩溃时写全量转储。

OEP 提取需要它：给 crackme.exe 设硬件断点后，命中会产生未处理异常，
由 WER 写出进程转储，我们从转储里读出原程序映像。

提取时实际运行的是 test\target_extract.exe（crackme.exe 的临时硬链接副本），
这样 WER 会只使用本项目自己的 HKCU 配置，不受系统里已有的 crackme.exe
配置影响。这里两个名字都会配置。

配置写入：
    HKLM\Software\Microsoft\Windows\Windows Error Reporting\LocalDumps\<name>
    （需要管理员权限；写不进去则退回 HKCU）

用法:
    python extract\enable_dumps.py [--dir tmp\crashdumps]
（双击 启用错误转储.bat 会用管理员权限运行本脚本）
"""
import argparse
import os
import subprocess
import sys
import time
import winreg

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import paths                                                    # noqa: E402

KEY = r'Software\Microsoft\Windows\Windows Error Reporting\LocalDumps\%s'
NAMES = ('crackme.exe', 'target_extract.exe')


def configure(folder):
    os.makedirs(folder, exist_ok=True)
    ok_any = False
    for name in NAMES:
        wrote = []
        for label, hk in (('HKLM', winreg.HKEY_LOCAL_MACHINE),
                          ('HKCU', winreg.HKEY_CURRENT_USER)):
            try:
                with winreg.CreateKeyEx(hk, KEY % name, 0, winreg.KEY_SET_VALUE) as k:
                    winreg.SetValueEx(k, 'DumpFolder', 0, winreg.REG_EXPAND_SZ, folder)
                    winreg.SetValueEx(k, 'DumpType', 0, winreg.REG_DWORD, 2)
                    winreg.SetValueEx(k, 'DumpCount', 0, winreg.REG_DWORD, 10)
                wrote.append(label)
                ok_any = True
            except OSError as exc:
                print('%s %s 写入失败：%s' % (label, name, exc))
        if wrote:
            print('%s 已配置：DumpFolder=%s  DumpType=2' % (name, folder))

    # 让 WER 重新读取配置（需要管理员；失败也不影响后续手动重试）
    if ok_any:
        try:
            subprocess.run(['sc', 'stop', 'WerSvc'], capture_output=True)
            time.sleep(1)
            subprocess.run(['sc', 'start', 'WerSvc'], capture_output=True)
            print('已重启 Windows Error Reporting 服务。')
        except OSError:
            pass
        return 0
    print('无法写入注册表。请右键「启用错误转储.bat」→以管理员身份运行。')
    return 1


def main(argv=None):
    ap = argparse.ArgumentParser(description='配置 WER LocalDumps（OEP 提取需要）')
    ap.add_argument('--dir', default=paths.CRASH,
                    help='转储目录（默认 tmp\\crashdumps）')
    args = ap.parse_args(argv)
    return configure(os.path.abspath(args.dir))


if __name__ == '__main__':
    sys.exit(main())
