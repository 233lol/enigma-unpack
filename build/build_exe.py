r"""Rebuild a standalone game executable from the decrypted application image.

Inputs:
    tmp/app_img.bin    decrypted application image (base 0x400000, 340 KB)
    tmp/app_iat.tsv    resolved imports: RVA \t value \t dll \t function

Output:
    <out>.exe          normal PE: the app's own sections plus a freshly built
                       import directory, entry = 0x4204BF (WinMainCRTStartup)

usage: python build_exe.py [out.exe]
"""
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
IMG_PATH = (sys.argv[2] if len(sys.argv) > 2
            else os.path.join(HERE, '..', 'tmp', 'work', 'app_img_oep.bin'))
IMG = open(IMG_PATH, 'rb').read()
BASE = 0x400000
ENTRY = 0x204BF                      # 0x4204BF - ImageBase
KEEP = 5                             # sections 0..4 (code, data, .rsrc)
NEW_VA = 0x53000                     # right after .rsrc

out = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else
                      os.path.join(HERE, '..', 'out', 'unenigma.exe'))


def u16(d, o):
    return struct.unpack_from('<H', d, o)[0]


def u32(d, o):
    return struct.unpack_from('<I', d, o)[0]


def w16(d, o, v):
    struct.pack_into('<H', d, o, v)


def w32(d, o, v):
    struct.pack_into('<I', d, o, v)


def align(v, a):
    return (v + a - 1) // a * a


# ------------------------------------------------------------------ header
e = u32(IMG, 0x3c)
coff = e + 4
nsec = u16(IMG, coff + 2)
optsize = u16(IMG, coff + 16)
opt = coff + 20
ibase = u32(IMG, opt + 28)
secalign = u32(IMG, opt + 32)
filealign = u32(IMG, opt + 36)
sizehdr = u32(IMG, opt + 60)
print(f'原头: {nsec} 区段  ImageBase {ibase:#x}  SecAlign {secalign:#x}  '
      f'FileAlign {filealign:#x}  SizeOfHeaders {sizehdr:#x}')
assert ibase == BASE

secs = []
for i in range(nsec):
    s = opt + optsize + i * 40
    secs.append(dict(name=IMG[s:s + 8], vsize=u32(IMG, s + 8), va=u32(IMG, s + 12),
                     rsize=u32(IMG, s + 16), roff=u32(IMG, s + 20),
                     chars=u32(IMG, s + 36), hdr=s))
    print(f'   区段{i}: VA {secs[-1]["va"]:#08x} VSize {secs[-1]["vsize"]:#08x} '
          f'RawOff {secs[-1]["roff"]:#08x} RawSize {secs[-1]["rsize"]:#08x} '
          f'chars {secs[-1]["chars"]:#x}')

# ------------------------------------------------------------------ imports
slots = []
tsv = os.path.join(HERE, 'app_iat_ok.tsv')
if not os.path.isfile(tsv):
    tsv = os.path.join(HERE, '..', 'app_iat.tsv')
print('导入清单:', os.path.basename(tsv))
for line in open(tsv, encoding='ascii'):
    p = line.rstrip('\n').split('\t')
    if len(p) == 4:
        slots.append((int(p[0], 16), p[2], p[3]))
slots.sort()
print(f'\n导入槽 {len(slots)} 个')
# 丢弃落进 .text（VA 0x1000..0x3C000）的伪槽位：IAT 不可能在代码段里，
# 这些是早期映射表的误报，写回会把代码改坏。
_bad = [s for s in slots if 0x1000 <= s[0] < 0x3C000]
if _bad:
    print('丢弃 .text 内的伪 IAT 槽:', [hex(r) for r, _, _ in _bad])
    slots = [s for s in slots if not (0x1000 <= s[0] < 0x3C000)]

# 壳「包装」的 API 槽：运行时指向壳自己的虚拟化实现，必须换成真实 API。
# 身份由调用点证据确定（参数个数 / 立即数 / 字符串常量）。
IDENTIFIED = {
    0x03C0CC: ('KERNEL32.DLL', 'CreateFileW'),      # 7 args, GENERIC_WRITE, INVALID_HANDLE 检查
    0x03C118: ('KERNEL32.DLL', 'ReadFile'),         # 5 args + 读取字节数检查
    0x03C19C: ('KERNEL32.DLL', 'GetProcAddress'),   # 传入函数名字符串
    0x03C200: ('KERNEL32.DLL', 'LoadLibraryW'),     # 传入 "Atl.dll"
    0x03C1D4: ('KERNEL32.DLL', 'ExitProcess'),   # 传入 STATUS_STACK_BUFFER_OVERRUN
    0x03C1E4: ('KERNEL32.DLL', 'GetTickCount'),  # 紧跟 GetSystemTimeAsFileTime
    0x03C394: ('KERNEL32.DLL', 'GetACP'),   # 字符串比较循环之前
    0x03C398: ('KERNEL32.DLL', 'GetOEMCP'),   # 成对出现
    0x03C1A0: ('KERNEL32.DLL', 'GetModuleHandleA'),
    0x03C11C: ('KERNEL32.DLL', 'LoadLibraryExW'),
    0x03C154: ('KERNEL32.DLL', 'CloseHandle'),
    0x03C18C: ('KERNEL32.DLL', 'GetLastError'),
    0x03C170: ('KERNEL32.DLL', 'GetCommandLineA'),  # 无参成对调用，结果存相邻全局
    0x03C0A8: ('KERNEL32.DLL', 'GetCommandLineW'),
    0x03C194: ('KERNEL32.DLL', 'LoadLibraryA'),       # 启动早期调用并检查返回值
}
print('壳包装 API 槽的识别结果:')
for _rva, (_dll, _nm) in sorted(IDENTIFIED.items()):
    print(f'   槽 {_rva:#08x} -> {_dll}!{_nm}')
    slots.append((_rva, _dll, _nm))
slots.sort()

runs = []                                     # [(dll, [(rva, name), ...])]
for rva, dll, name in slots:
    if runs and runs[-1][0] == dll and runs[-1][1][-1][0] + 4 == rva:
        runs[-1][1].append((rva, name))
    else:
        runs.append((dll, [(rva, name)]))
print(f'连续块 {len(runs)} 个（每个一个描述符）:')
for dll, items in runs:
    print(f'   {dll:16s} {len(items):3d} 项  IAT {items[0][0]:#08x}..'
          f'{items[-1][0]:#08x}')

# ------------------------------------------------------------------ section
imp = bytearray()


def emit_names():
    base = len(imp)
    rvas = {}
    for dll, _ in runs:
        if dll in rvas:
            continue
        rvas[dll] = NEW_VA + len(imp)
        imp.extend(dll.encode('ascii') + b'\0')
    return rvas


name_rva = emit_names()
hn_rva = {}
for rva, dll, name in slots:
    key = (dll, name)
    if key in hn_rva:
        continue
    hn_rva[key] = NEW_VA + len(imp)
    imp.extend(struct.pack('<H', 0))          # hint
    imp.extend(name.encode('ascii') + b'\0')


def align_imp(a=2):
    while len(imp) % a:
        imp.append(0)


align_imp()
lookup_rva = {}
for dll, items in runs:
    key = id(items)
    lookup_rva[key] = NEW_VA + len(imp)
    for rva, name in items:
        imp.extend(struct.pack('<I', hn_rva[(dll, name)]))
    imp.extend(struct.pack('<I', 0))          # terminator

align_imp(4)
desc_rva = NEW_VA + len(imp)
for dll, items in runs:
    imp.extend(struct.pack('<IIIII', lookup_rva[id(items)], 0, 0,
                           name_rva[dll], items[0][0]))
imp.extend(b'\0' * 20)                        # terminator descriptor
import_size = len(imp)
print(f'\n导入节: VA {NEW_VA:#x}  {import_size} 字节  '
      f'描述符 {desc_rva:#x}')

# ------------------------------------------------------------------ output
outbuf = bytearray(IMG[:sizehdr])
# 恢复 .data 可写：OEP dump 的段头继承了 Enigma 在 OEP 时设置的只读保护
# (Characteristics 0x40000040)。原始 app 的这段含 IAT 与游戏全局变量，必须可写，
# 否则运行期写全局会失败（新游戏场景初始化表为空 -> "invalid chara position"）。
for i in range(KEEP):
    if secs[i]['va'] == 0x3C000:
        w32(outbuf, secs[i]['hdr'] + 36, 0xC0000040)
        print(f'  段 {secs[i]["va"]:#x} 保护恢复为 RW (0xC0000040)')
w32(outbuf, coff + 2, KEEP + 1)               # NumberOfSections
w32(outbuf, opt + 16, ENTRY)                  # AddressOfEntryPoint
w32(outbuf, opt + 56, 0)                      # SizeOfImage (later)
w32(outbuf, opt + 64, 0)                      # CheckSum
for i in range(16):                           # clear all directories
    w32(outbuf, opt + 96 + i * 8, 0)
    w32(outbuf, opt + 100 + i * 8, 0)

# section headers: keep 0..4, add the import section
sec_off = opt + optsize
new_hdr = sec_off + KEEP * 40
outbuf[new_hdr:new_hdr + 8] = b'.idata\0\0'
w32(outbuf, new_hdr + 8, import_size)
w32(outbuf, new_hdr + 12, NEW_VA)
w32(outbuf, new_hdr + 36, 0xE0000040)         # RWX（里面有可执行探针桩）

# lay out sections
pos = sizehdr
sec_pos = {}
for i in range(KEEP):
    s = secs[i]
    vsz = s['vsize']
    raw = align(vsz, filealign)
    sec_pos[i] = pos
    w32(outbuf, s['hdr'] + 20, pos)
    w32(outbuf, s['hdr'] + 16, raw)
    data = IMG[s['va']:s['va'] + vsz]
    if len(data) < vsz:
        data = data + b'\0' * (vsz - len(data))
    outbuf += data
    outbuf += b'\0' * (raw - len(data))
    pos += raw

# 清掉指向「旧进程堆区」的陈旧指针（0x01000000-0x400000）：
# 映像是从运行中的进程 dump 的，这些位置残留上次运行的堆指针，
# 在新进程里必然无效，会被当作字符串指针传给 CRT -> FAST_FAIL_INVALID_ARG
heap_cleared = 0
for i in range(1, KEEP):          # 只清数据区段（跳过代码段）
    s = secs[i]
    off0 = sec_pos[i]
    for k in range(0, s['vsize'] - 3, 4):
        fo = off0 + k
        v = u32(outbuf, fo)
        if 0x01000000 <= v < 0x400000:
            w32(outbuf, fo, 0)
            heap_cleared += 1
print(f'clear stale heap pointers: {heap_cleared}')

# 清掉指向 DLL 空间的陈旧指针：映像是从运行中的进程 dump 的，那些位置
# 还留着「上一次运行解析出来的地址」，在新进程里是无效的。原文件里它们本该是 0。
SLOT_RVAS = {rva for rva, _, _ in slots}
cleared = 0
CLEAR_STALE = False          # 清零陈旧 DLL 指针会让程序更早崩溃，默认关闭
for i in range(KEEP) if CLEAR_STALE else []:
    s = secs[i]
    off0 = sec_pos[i]
    va0 = s['va']
    for k in range(0, s['vsize'] - 3, 4):
        fo = off0 + k
        v = u32(outbuf, fo)
        if 0x60000000 <= v < 0x80000000 and (va0 + k) not in SLOT_RVAS:
            w32(outbuf, fo, 0)
            cleared += 1
print(f'清掉陈旧 DLL 指针 {cleared} 个')

print('\n壳包装的 API 槽识别结果（调用点证据）:')

# 可选：数据区段用更早（更接近"刚解密"）的 dump，避免运行期脏指针
STAGE2 = os.path.join(HERE, '..', 'tmp', 'work', 'app_img_stage2.bin')
IMG_ALT = None
if os.path.isfile(STAGE2):
    alt = open(STAGE2, 'rb').read()
    if len(alt) >= 0x53000:
        IMG_ALT = alt
        print('数据区段将使用 stage2（点 OK 后 0.05s）的 dump')
else:
    print('（没有 stage2 dump，全部用 app_img.bin）')
# 剥离版里壳的映像不存在，留着旧地址会跳进未映射内存，先用「返回 0」的小桩占位。
code_ref = set()
_k = 0
while _k < len(IMG) - 6:
    _b = IMG[_k]
    _a = None
    if _b == 0xFF and IMG[_k + 1] in (0x15, 0x25):
        _a = u32(IMG, _k + 2)
        _k += 6
    elif _b == 0xA1:
        _a = u32(IMG, _k + 1)
        _k += 5
    elif _b == 0x8B and IMG[_k + 1] in (0x05, 0x0D, 0x15, 0x1D, 0x35, 0x3D):
        _a = u32(IMG, _k + 2)
        _k += 6
    else:
        _k += 1
        continue
    if 0x1000 <= _a - BASE < len(IMG):
        code_ref.add(_a - BASE)

wrapped = [o for o in range(0x1000, len(IMG) - 4, 4)
           if 0x453000 <= u32(IMG, o) < 0xC32000 and o in code_ref
           and o not in IDENTIFIED
           # 排除字符串数据（如 "Windows" / "notify" 的中间 4 字节）：
           # 这些位置的值恰好落在壳映像范围，但它们不是函数指针。
           and not all(0x20 <= b < 0x7f or b == 0 for b in IMG[o:o + 4])]
print(f'\n壳包装的 API 槽 {len(wrapped)} 个（已识别 {len(IDENTIFIED)} 个接真函数）:'
      f' {[hex(x) for x in wrapped]}')
# 诊断模式：把 combase/ole32 的导入槽也换成探针桩，看崩溃前最后的 COM 调用
DEBUG_STUB_COM = False
com_slots = [rva for rva, dll, nm in slots
             if dll.lower() in ('combase.dll', 'ole32.dll')] if DEBUG_STUB_COM else []
if com_slots:
    print(f'诊断：{len(com_slots)} 个 COM 槽改为探针桩: {[hex(x) for x in com_slots]}')
    slots = [(rva, dll, nm) for rva, dll, nm in slots if rva not in com_slots]

STUB_ARGS = {}
stub_of = {}
PROBE_CNT = NEW_VA + 0x2000
PROBE_BUF = NEW_VA + 0x2004
for _o in wrapped:
    _n = STUB_ARGS.get(_o, 0)
    _va = NEW_VA + len(imp)
    _code = bytearray()
    _code += b'\x60'                                   # pushad
    _code += b'\x8b\x44\x24\x20'                    # mov eax,[esp+0x20] 返回地址
    _code += b'\x8b\x0d' + struct.pack('<I', PROBE_CNT)
    _code += b'\x83\xf9\x3f'                         # cmp ecx,0x3f
    _code += b'\x7f\x08'                              # jg +8
    _code += b'\x89\x04\x8d' + struct.pack('<I', PROBE_BUF)
    _code += b'\x41'                                   # inc ecx
    _code += b'\x89\x0d' + struct.pack('<I', PROBE_CNT)
    _code += b'\x61'                                   # popad
    _code += b'\x31\xc0'                              # xor eax,eax
    _code += b'\xc2' + struct.pack('<H', _n * 4)       # ret N
    imp.extend(bytes(_code))
    stub_of[_o] = _va
imp.extend(b'\0' * 0x1000)
print(f'probe stubs: cnt@{PROBE_CNT:#x} buf@{PROBE_BUF:#x}')
print('per-slot stubs: ' + ', '.join(
    f'{k:#x}->ret {STUB_ARGS.get(k, 0) * 4:#x}' for k in sorted(stub_of)))
for o in wrapped:
    _st = stub_of.get(o)
    if _st is None:
        continue
    for i in range(KEEP):
        s = secs[i]
        if s['va'] <= o < s['va'] + s['vsize']:
            w32(outbuf, sec_pos[i] + (o - s['va']), _st)
            break

# IAT slots in the file must hold the lookup values
for dll, items in runs:
    for rva, name in items:
        va = rva
        for i in range(KEEP):
            s = secs[i]
            if s['va'] <= va < s['va'] + s['vsize']:
                off = sec_pos[i] + (va - s['va'])
                w32(outbuf, off, hn_rva[(dll, name)])
                break
        else:
            print(f'   !! 槽 {rva:#x} 不在保留区段内')

# import section data
raw = align(len(imp), filealign)
w32(outbuf, sec_off + KEEP * 40 + 20, pos)
w32(outbuf, sec_off + KEEP * 40 + 16, raw)
outbuf += bytes(imp)
outbuf += b'\0' * (raw - len(imp))
pos += raw

sizeimg = align(NEW_VA + import_size, secalign)
w32(outbuf, opt + 56, sizeimg)
# data directories
w32(outbuf, opt + 96 + 1 * 8, desc_rva)
w32(outbuf, opt + 100 + 1 * 8, (len(runs) + 1) * 20)
w32(outbuf, opt + 96 + 2 * 8, 0x51000)
w32(outbuf, opt + 100 + 2 * 8, 0x1608)
w32(outbuf, opt + 96 + 12 * 8, slots[0][0])
w32(outbuf, opt + 100 + 12 * 8, slots[-1][0] + 4 - slots[0][0])

open(out, 'wb').write(outbuf)
print(f'\n写出 {out}  ({len(outbuf):,} 字节)')
print(f'   入口 RVA {ENTRY:#x}   区段 {KEEP + 1}   导入描述符 {desc_rva:#x} '
      f'({len(runs)} 个)   SizeOfImage {sizeimg:#x}')
