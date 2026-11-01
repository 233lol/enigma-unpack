#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""底层 Win32 内存/线程访问工具（纯 ctypes，无第三方依赖）。"""
import ctypes
import struct
import subprocess
from ctypes import wintypes as wt

k32 = ctypes.WinDLL('kernel32', use_last_error=True)

k32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
k32.OpenProcess.restype = wt.HANDLE
k32.ReadProcessMemory.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
                                  ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
k32.WriteProcessMemory.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
                                   ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
k32.VirtualQueryEx.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]
k32.CreateToolhelp32Snapshot.argtypes = [wt.DWORD, wt.DWORD]
k32.CreateToolhelp32Snapshot.restype = wt.HANDLE
k32.OpenThread.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
k32.OpenThread.restype = wt.HANDLE
k32.Wow64GetThreadContext.argtypes = [wt.HANDLE, ctypes.c_void_p]
k32.Wow64SetThreadContext.argtypes = [wt.HANDLE, ctypes.c_void_p]
k32.TerminateProcess.argtypes = [wt.HANDLE, wt.UINT]
k32.VirtualAllocEx.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.c_size_t,
                               wt.DWORD, wt.DWORD]
k32.VirtualAllocEx.restype = ctypes.c_void_p
k32.VirtualFreeEx.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.c_size_t, wt.DWORD]
k32.CreateRemoteThread.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.c_size_t,
                                   ctypes.c_void_p, ctypes.c_void_p, wt.DWORD,
                                   ctypes.POINTER(wt.DWORD)]
k32.CreateRemoteThread.restype = wt.HANDLE
k32.WaitForSingleObject.argtypes = [wt.HANDLE, wt.DWORD]
k32.GetExitCodeThread.argtypes = [wt.HANDLE, ctypes.POINTER(wt.DWORD)]

PROCESS_ALL = 0x0008 | 0x0010 | 0x0020 | 0x0400 | 0x0100
TH32CS_SNAPTHREAD = 0x00000004
MEM_COMMIT = 0x1000
PAGE_NOACCESS = 0x01
PAGE_GUARD = 0x100

CONTEXT_ALL_WOW64 = 0x00010007 | 0x00010010


class MBI(ctypes.Structure):
    _fields_ = [('BaseAddress', ctypes.c_void_p), ('AllocationBase', ctypes.c_void_p),
                ('AllocationProtect', ctypes.c_ulong), ('PartitionId', ctypes.c_ushort),
                ('RegionSize', ctypes.c_size_t), ('State', ctypes.c_ulong),
                ('Protect', ctypes.c_ulong), ('Type', ctypes.c_ulong)]


class THREADENTRY32(ctypes.Structure):
    _fields_ = [('dwSize', wt.DWORD), ('cntUsage', wt.DWORD), ('th32ThreadID', wt.DWORD),
                ('th32OwnerProcessID', wt.DWORD), ('tpBasePri', ctypes.c_long),
                ('tpDeltaPri', ctypes.c_long), ('dwFlags', wt.DWORD)]


class WOW64_CONTEXT(ctypes.Structure):
    _fields_ = [('ContextFlags', wt.DWORD),
                ('Dr0', wt.DWORD), ('Dr1', wt.DWORD), ('Dr2', wt.DWORD), ('Dr3', wt.DWORD),
                ('Dr6', wt.DWORD), ('Dr7', wt.DWORD),
                ('FloatSave', ctypes.c_byte * 112),
                ('SegGs', wt.DWORD), ('SegFs', wt.DWORD), ('SegEs', wt.DWORD), ('SegDs', wt.DWORD),
                ('Edi', wt.DWORD), ('Esi', wt.DWORD), ('Ebx', wt.DWORD), ('Edx', wt.DWORD),
                ('Ecx', wt.DWORD), ('Eax', wt.DWORD), ('Ebp', wt.DWORD), ('Eip', wt.DWORD),
                ('SegCs', wt.DWORD), ('EFlags', wt.DWORD), ('Esp', wt.DWORD), ('SegSs', wt.DWORD),
                ('ExtendedRegisters', ctypes.c_byte * 512)]


def find_pid(name):
    """按映像名查找进程（如 'crackme.exe'）。"""
    out = subprocess.run(['tasklist', '/FO', 'CSV', '/NH'], capture_output=True,
                         text=True, errors='ignore').stdout
    for line in out.splitlines():
        p = line.split('","')
        if len(p) >= 2 and p[0].strip('"').lower() == name.lower():
            try:
                return int(p[1])
            except ValueError:
                pass
    return None


def kill(exe_name):
    subprocess.run(['taskkill', '/F', '/IM', exe_name], capture_output=True)


class Mem:
    """目标进程的内存读写与区段枚举。"""

    def __init__(self, pid, access=PROCESS_ALL):
        self.pid = pid
        self.h = k32.OpenProcess(access, False, pid)
        if not self.h:
            raise OSError('OpenProcess(%d) 失败: %d' % (pid, ctypes.get_last_error()))

    def close(self):
        if self.h:
            k32.CloseHandle(self.h)
            self.h = None

    def read(self, addr, size):
        buf = ctypes.create_string_buffer(size)
        got = ctypes.c_size_t(0)
        if not k32.ReadProcessMemory(self.h, ctypes.c_void_p(addr), buf, size,
                                     ctypes.byref(got)):
            return None
        return buf.raw[:got.value]

    def write(self, addr, data):
        buf = ctypes.create_string_buffer(bytes(data), len(data))
        got = ctypes.c_size_t(0)
        if not k32.WriteProcessMemory(self.h, ctypes.c_void_p(addr), buf, len(data),
                                      ctypes.byref(got)):
            raise OSError('WriteProcessMemory(%#x) 失败: %d' %
                          (addr, ctypes.get_last_error()))

    def regions(self):
        """[(base, size, state, protect, type)]"""
        out, addr, mbi = [], 0, MBI()
        while addr < 0x80000000:
            if not k32.VirtualQueryEx(self.h, ctypes.c_void_p(addr), ctypes.byref(mbi),
                                      ctypes.sizeof(mbi)):
                break
            b = mbi.BaseAddress or 0
            out.append((b, mbi.RegionSize, mbi.State, mbi.Protect, mbi.Type))
            nxt = b + mbi.RegionSize
            if nxt <= addr:
                break
            addr = nxt
        return out

    def iter_readable(self, max_region=0x10000000):
        """遍历已提交、可读的区段；逐段返回 (base, size, bytes)。"""
        for base, size, state, prot, _typ in self.regions():
            if state != MEM_COMMIT or size == 0 or size > max_region:
                continue
            if (prot & 0xff) in (0, PAGE_NOACCESS) or (prot & PAGE_GUARD):
                continue
            pos, end = base, base + size
            while pos < end:
                n = min(0x100000, end - pos)
                d = self.read(pos, n)
                if d:
                    yield pos, len(d), d
                pos += n

    def terminate(self, code=1):
        try:
            k32.TerminateProcess(self.h, code)
        except Exception:
            pass


def threads(pid):
    snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
    if snap in (0, -1):
        return []
    out = []
    te = THREADENTRY32()
    te.dwSize = ctypes.sizeof(te)
    ok = k32.Thread32First(snap, ctypes.byref(te))
    while ok:
        if te.th32OwnerProcessID == pid:
            out.append(te.th32ThreadID)
        ok = k32.Thread32Next(snap, ctypes.byref(te))
    k32.CloseHandle(snap)
    return out


def arm_dr0_space_for_oep(pid, oep):
    """给进程的每个线程设置 DR0=oep（硬件执行断点）。

    进程没有被调试器附加时，命中会产生 STATUS_SINGLE_STEP（0x80000004）未处理
    异常，从而触发 Windows 错误报告转储。返回设成功的线程数。
    """
    n = 0
    for tid in threads(pid):
        h = k32.OpenThread(0x0008 | 0x0010 | 0x0002, False, tid)
        if not h:
            continue
        ctx = WOW64_CONTEXT()
        ctx.ContextFlags = CONTEXT_ALL_WOW64
        if k32.Wow64GetThreadContext(h, ctypes.byref(ctx)):
            ctx.Dr0 = oep
            ctx.Dr7 = 1
            ctx.ContextFlags = CONTEXT_ALL_WOW64
            if k32.Wow64SetThreadContext(h, ctypes.byref(ctx)):
                n += 1
        k32.CloseHandle(h)
    return n


def stitch(mem, base, size):
    """从区段拼接出 [base, base+size) 的字节；空洞补 0。"""
    img = bytearray(size)
    for rbase, rsize, state, _p, _t in mem.regions():
        lo, hi = max(rbase, base), min(rbase + rsize, base + size)
        if lo >= hi:
            continue
        d = mem.read(lo, hi - lo)
        if d:
            img[lo - base:lo - base + len(d)] = d
    return bytes(img)


class Remote:
    """在目标进程里调用 x86 函数（cdecl / stdcall），返回 EAX。

    用 CreateRemoteThread 执行一小段桩代码；不依赖目标进程的调试器。
    适用于 Enigma 进程里读取它映射出来的虚拟文件（如 %TEMP%\\scene1.hsp）。
    """

    def __init__(self, mem):
        self.mem = mem
        self.scratch = k32.VirtualAllocEx(mem.h, None, 0x1000, 0x3000, 0x40)
        if not self.scratch:
            raise OSError('VirtualAllocEx 失败: %d' % ctypes.get_last_error())
        self.code = self.scratch + 0x100
        self.result = self.scratch + 0x800

    def alloc(self, size, protect=0x04):
        return k32.VirtualAllocEx(self.mem.h, None, size, 0x3000, protect)

    def free(self, addr):
        if addr:
            k32.VirtualFreeEx(self.mem.h, ctypes.c_void_p(addr), 0, 0x8000)

    def read(self, addr, size):
        return self.mem.read(addr, size)

    def write(self, addr, data):
        self.mem.write(addr, data)

    def call(self, fn, args=(), cdecl=True, timeout=15000):
        stub = bytearray(b'\x55\x8b\xec')                 # push ebp; mov ebp,esp
        for a in reversed(args):
            stub += b'\x68' + struct.pack('<I', a & 0xFFFFFFFF)
        stub += b'\xb8' + struct.pack('<I', fn)            # mov eax, fn
        stub += b'\xff\xd0'                                # call eax
        if cdecl and args:
            stub += b'\x83\xc4' + bytes([(4 * len(args)) & 0xFF])
        stub += b'\xa3' + struct.pack('<I', self.result)   # mov [result], eax
        stub += b'\x31\xc0\x5d\xc2\x04\x00'                # xor eax,eax; pop ebp; ret 4
        self.mem.write(self.code, bytes(stub))
        tid = wt.DWORD(0)
        th = k32.CreateRemoteThread(self.mem.h, None, 0, self.code, None, 0,
                                    ctypes.byref(tid))
        if not th:
            return None
        k32.WaitForSingleObject(th, timeout)
        code = wt.DWORD(0)
        k32.GetExitCodeThread(th, ctypes.byref(code))
        d = self.mem.read(self.result, 4)
        return struct.unpack('<I', d)[0] if d and len(d) == 4 else None

    def close(self):
        if self.scratch:
            k32.VirtualFreeEx(self.mem.h, ctypes.c_void_p(self.scratch), 0, 0x8000)
            self.scratch = None

