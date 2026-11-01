#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""构造脚本库 DPM（data.dpm / 单文件版内嵌包）。

内容：
    start.ax    从运行进程恢复的脚本主体，按 hsprt-XOR-eg 预 XOR 存储
                （运行时 Hsp3::Reset 会用它自身的固定 pad 解密这一份）
    scene1.hsp  剧情场景（中文版实际加载的文件）—— 明文（可选）
    scene2.hsp  ditto（英文分支用；中文版不读，放同内容做保险）—— 明文（可选）

要点（均由反汇编确认）：
  * Hsp3::Reset 只 XOR 它加载的脚本缓冲（= start.ax），不影响 DPM 其它文件；
  * HSP 的文件读取先查 DPM、查不到再回退磁盘；
  * DPM 目录是线性查找（0x401A30），条目 32 字节：name[16], +16 flags,
    +20 key, +24 数据区偏移, +28 大小；顺序无关。

用法:
    python build_dpm.py <out.dpm> <script.ax | *.dpm> [scene1.hsp scene2.hsp ...]

第一个参数是明文脚本来源：
  - 若是 HSP3 对象文件（以 'HSP3' 开头），直接使用；
  - 若是 DPM（以 'DPMX' 开头），从中取出 start.ax 条目；
  - 否则在文件里搜索 'HSP3' 并按其 allsize 截取。
"""
import os
import struct
import sys

PAD = bytes.fromhex(
    'cdeb2d4724fc454281ca53f143772af50e01b0e3cf21fd7e39dc1e9ccfc185b6'
    'bec12e1f41c65ee3c2ea1863a459387bb1df3f773a27bc94d5927241e0d3170'
    '18b21c9f3a91830')


def _from_dpm(d):
    optr, dent, _ns = struct.unpack_from('<III', d, 4)
    for i in range(dent):
        e = d[16 + i * 32:16 + (i + 1) * 32]
        name = e[:16].split(b'\0')[0]
        _flags, _key, off, size = struct.unpack_from('<IIII', e, 16)
        if name == b'start.ax':
            return d[optr + off:optr + off + size]
    sys.exit('DPM 里没有 start.ax 条目')


def load_plain(src):
    """从各种来源取出明文的 start.ax 对象。"""
    d = open(src, 'rb').read()
    if d[:4] == b'DPMX':
        obj = _from_dpm(d)
    elif d[:4] == b'HSP3':
        allsize = struct.unpack_from('<I', d, 12)[0]
        obj = d[:allsize]
    else:
        off = d.find(b'HSP3')
        if off < 0:
            sys.exit('%s 里找不到 HSP3 对象' % src)
        allsize = struct.unpack_from('<I', d, off + 12)[0]
        obj = d[off:off + allsize]
    if len(obj) != struct.unpack_from('<I', obj, 12)[0] or obj[:4] != b'HSP3':
        sys.exit('脚本对象不完整: %s' % src)
    return obj


def script_blob(obj):
    """对明文 start.ax 预 XOR（运行时 Hsp3::Reset 会再解一次）。"""
    enc = bytes(b ^ PAD[i % len(PAD)] for i, b in enumerate(obj))
    if bytes(b ^ PAD[i % len(PAD)] for i, b in enumerate(enc[:4])) != b'HSP3':
        sys.exit('XOR 自检失败')
    return enc


def build(entries):
    """entries: list of (name, blob). Returns DPM bytes."""
    dent = len(entries)
    optr = 16 + 32 * dent
    out = bytearray(b'DPMX' + struct.pack('<III', optr, dent, 0))
    data = bytearray()
    for name, blob in entries:
        nm = name.encode('ascii')
        if len(nm) > 15:
            sys.exit('名字过长（DPM 条目上限 15 字符）: %s' % name)
        e = bytearray(32)
        e[0:len(nm)] = nm
        struct.pack_into('<I', e, 16, 0xFFFFFFFF)   # name/flags
        struct.pack_into('<I', e, 20, 0)            # per-file key
        struct.pack_into('<I', e, 24, len(data))    # offset in data area
        struct.pack_into('<I', e, 28, len(blob))    # size
        out += e
        data += blob
    out += data
    return bytes(out)


def _strip_scene_comment(blob):
    if isinstance(blob, str):
        return blob
    while blob[:1] == b';':
        nl = blob.find(b'\n')
        if nl < 0:
            break
        blob = blob[nl + 1:]
    return blob


def scene_ok(blob, full=True):
    """剧情脚本必须带有 {0} 序章；缺了它游戏进入剧情时会崩。

    full=False 用于 scene2.hsp（英文分支可以只有一小段）。
    """
    blob = _strip_scene_comment(blob)
    if not blob.startswith(b'{0}\r\n') or b'\x00' in blob:
        return False
    if not full:
        return b'{end}' in blob
    return len(blob) >= 0x4000 and blob.count(b'{end}') >= 30


def main():
    argv = list(sys.argv[1:])
    allow_partial = '--allow-partial-scene' in argv
    argv = [a for a in argv if a != '--allow-partial-scene']
    if len(argv) < 2:
        sys.exit(__doc__.strip().splitlines()[-6:])
    out_path = argv[0]
    obj = load_plain(argv[1])

    entries = [('start.ax', script_blob(obj))]
    for p in argv[2:]:
        name = os.path.basename(p)
        blob = open(p, 'rb').read()
        is_scene = name.startswith('scene') and name.endswith('.hsp')
        if is_scene:
            if not scene_ok(blob, full=name.startswith('scene1')):
                msg = ('%s 不是完整的剧情脚本（必须以 {0} 序章开头、含全部 {end}）。\n'
                       '  缺序章的场景会在创建角色后触发 HspError 12 崩溃。\n'
                       '  修法：python extract\\extract_scene.py\n'
                       '        或把完整的 scene1.hsp / scene2.hsp 放进 tmp\\work\\。' % p)
                if not allow_partial:
                    sys.exit(msg)
                print('警告：' + msg)
            blob = _strip_scene_comment(blob)
        entries.append((name, blob))

    dpm = build(entries)
    open(out_path, 'wb').write(dpm)
    print('DPM %s  %d files  %d bytes' % (out_path, len(entries), len(dpm)))
    for name, blob in entries:
        print('   %-16s %10d' % (name, len(blob)))
    print('   checksum %#06x' % (sum(dpm) & 0xFFFF))


if __name__ == '__main__':
    main()
