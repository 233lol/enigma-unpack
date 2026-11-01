"""32-bit target helpers: enumerate WOW64 modules and resolve IAT slots."""
import ctypes
import struct

from winmem import k32, wt                                        # noqa: E402

PROCESS_WOW64_INFORMATION = 26
ntdll = ctypes.WinDLL('ntdll')


def wow64_peb(mem):
    buf = ctypes.create_string_buffer(8)
    got = ctypes.c_uint(0)
    fn = ntdll.NtQueryInformationProcess
    fn.argtypes = [wt.HANDLE, ctypes.c_uint, ctypes.c_void_p, ctypes.c_uint,
                   ctypes.POINTER(ctypes.c_uint)]
    st = fn(mem.h, PROCESS_WOW64_INFORMATION, buf, 8, ctypes.byref(got))
    if st != 0:
        return None
    return struct.unpack_from('<I', buf.raw, 0)[0]


def modules32(mem):
    """[(base, size, name)] from the 32-bit PEB loader list."""
    peb = wow64_peb(mem)
    if not peb:
        return []
    ldr = struct.unpack('<I', mem.read(peb + 0x0C, 4))[0]
    head = ldr + 0x14                       # InMemoryOrderModuleList
    out = []
    cur = struct.unpack('<I', mem.read(head, 4))[0]
    for _ in range(256):
        if not cur or cur == head:
            break
        entry = cur - 0x08                   # InMemoryOrderLinks
        d = mem.read(entry, 0x40)
        if not d or len(d) < 0x40:
            break
        base = struct.unpack_from('<I', d, 0x18)[0]
        size = struct.unpack_from('<I', d, 0x20)[0]
        ln = struct.unpack_from('<H', d, 0x2C)[0]
        bp = struct.unpack_from('<I', d, 0x30)[0]
        name = ''
        if bp and ln:
            b = mem.read(bp, ln)
            if b:
                name = b.decode('utf-16le', 'replace')
        out.append((base, size, name))
        cur = struct.unpack('<I', mem.read(cur, 4))[0]
    return out


def pe_import_slot(mem, base, dll_sub, func):
    """Return the IAT slot VA for dll_sub!func inside a loaded module."""
    hdr = mem.read(base, 0x400)
    if not hdr or hdr[:2] != b'MZ':
        return None
    e = struct.unpack_from('<I', hdr, 0x3C)[0]
    pe = mem.read(base + e, 0x100)
    if not pe or pe[:4] != b'PE\0\0':
        return None
    opt = 24
    optsize = struct.unpack_from('<H', pe, 20)[0]
    imp_rva = struct.unpack_from('<I', pe, opt + 96 + 8)[0]
    if not imp_rva:
        return None
    desc = base + imp_rva
    for i in range(64):
        d = mem.read(desc + i * 20, 20)
        if not d or len(d) < 20:
            break
        oft, ts, fc, name_rva, ft = struct.unpack('<IIIII', d)
        if not name_rva:
            break
        nb = mem.read(base + name_rva, 128)
        dll = nb.split(b'\0')[0].decode('latin-1', 'replace') if nb else ''
        if dll_sub.lower() in dll.lower():
            thunk = oft or ft
            for k in range(512):
                v = mem.read(base + thunk + k * 4, 4)
                if not v or len(v) < 4:
                    break
                rva = struct.unpack('<I', v)[0]
                if rva == 0:
                    break
                if rva & 0x80000000:
                    continue
                nm = mem.read(base + rva + 2, 64)
                fn = nm.split(b'\0')[0].decode('latin-1', 'replace') if nm else ''
                if fn == func:
                    return base + ft + k * 4
    return None
