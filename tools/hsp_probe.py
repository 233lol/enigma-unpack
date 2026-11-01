"""Read HSP3 runtime variable tables out of a live game process.

Layouts are from OpenHSP (src/hsp3/hsp3struct.h, hspvar_core.h), 32-bit build:

  HSPCTX:  +0 hsphed, +4 mcs, +8 mem_mcs, +12 mem_mds,
           +16 mem_di, +20 mem_ot, +44 mem_var
  PVal:    +0 short flag, +2 short mode, +4 int len[5], +24 int size,
           +28 char *pt, +32 void *master, +36 u16 support,
           +38 short arraycnt, +40 int offset, +44 int arraymul   (48 bytes)

The script object (HSPHED, starts with 'HSP3') is found by scanning heap for
the magic.  HSPCTX is found by scanning memory for a pointer to that object and
validating mem_mcs / mem_var.
"""
import struct
import sys

sys.path[:0] = ['extract', '.']
import winmem                                                    # noqa: E402

PVAL_SIZE = 48
CTX_MEM_VAR = 44
CTX_MEM_MCS = 8
CTX_MEM_DI = 16


def find_script(mem):
    """(va, allsize, pt_cs, max_cs, max_val, pt_dinfo, max_dinfo)"""
    best = None
    for base, size, data in mem.iter_readable():
        i = 0
        while True:
            i = data.find(b'HSP3', i)
            if i < 0:
                break
            va = base + i
            hd = mem.read(va, 0x30)
            if hd and len(hd) == 0x30:
                allsize = struct.unpack_from('<I', hd, 12)[0]
                pt_cs = struct.unpack_from('<I', hd, 16)[0]
                max_cs = struct.unpack_from('<I', hd, 20)[0]
                if (0x10000 <= allsize <= 0x4000000 and 0 < max_cs < allsize
                        and 0 < pt_cs < max_cs):
                    if best is None or allsize > best[1]:
                        best = (va, allsize, pt_cs, max_cs,
                                struct.unpack_from('<I', hd, 8)[0],
                                struct.unpack_from('<I', hd, 40)[0],
                                struct.unpack_from('<I', hd, 44)[0])
            i += 1
    return best


def find_ctx(mem, script_va, pt_cs, max_cs):
    pat = struct.pack('<I', script_va)
    cands = []
    for base, size, data in mem.iter_readable():
        i = 0
        while True:
            i = data.find(pat, i)
            if i < 0:
                break
            cands.append(base + i)
            i += 1
    ok = []
    for c in cands:
        d = mem.read(c, 48)
        if not d or len(d) < 48:
            continue
        mcs = struct.unpack_from('<I', d, 4)[0]
        mem_mcs = struct.unpack_from('<I', d, 8)[0]
        mem_mds = struct.unpack_from('<I', d, 12)[0]
        mem_var = struct.unpack_from('<I', d, CTX_MEM_VAR)[0]
        # HSP3 copies the code/data segments out of the object file, so
        # mem_mcs is not script_va + pt_cs.  Validate by dereferencing:
        # mem_var must look like a PVal array and both buffers must be readable.
        if not (0x10000 <= mem_var < 0x80000000):
            continue
        if not (0x10000 <= mem_mcs < 0x80000000 and
                0x10000 <= mem_mds < 0x80000000):
            continue
        pv = mem.read(mem_var, PVAL_SIZE)
        if not pv or len(pv) < PVAL_SIZE:
            continue
        flag = struct.unpack_from('<h', pv, 0)[0]
        len0 = struct.unpack_from('<i', pv, 4)[0]
        if not (1 <= flag <= 6 and len0 == 1):
            continue
        if not mem.read(mem_mcs, 16) or not mem.read(mem_mds, 16):
            continue
        ok.append((c, mcs, mem_var))
    return ok


def read_vars(mem, mem_var, count):
    d = mem.read(mem_var, count * PVAL_SIZE)
    out = []
    if not d:
        return out
    for i in range(min(count, len(d) // PVAL_SIZE)):
        o = i * PVAL_SIZE
        flag, mode = struct.unpack_from('<hh', d, o)
        lens = struct.unpack_from('<5i', d, o + 4)
        size = struct.unpack_from('<i', d, o + 24)[0]
        pt = struct.unpack_from('<I', d, o + 28)[0]
        master = struct.unpack_from('<I', d, o + 32)[0]
        support, arraycnt = struct.unpack_from('<Hh', d, o + 36)
        offset = struct.unpack_from('<i', d, o + 40)[0]
        out.append(dict(idx=i, flag=flag, mode=mode, len=lens, size=size, pt=pt,
                        master=master, support=support, arraycnt=arraycnt,
                        offset=offset))
    return out


def dump(pid, count=None):
    mem = winmem.Mem(pid)
    try:
        sc = find_script(mem)
        if not sc:
            raise SystemExit('no HSP3 script object')
        va, allsize, pt_cs, max_cs, max_val, pt_dinfo, max_dinfo = sc
        print('script %#x allsize %#x pt_cs %#x max_cs %#x max_val %d '
              'dinfo %#x/%#x' % (va, allsize, pt_cs, max_cs, max_val,
                                 pt_dinfo, max_dinfo))
        ctxs = find_ctx(mem, va, pt_cs, max_cs)
        print('ctx candidates:', [(hex(c), hex(m), hex(v)) for c, m, v in ctxs])
        if not ctxs:
            raise SystemExit('no HSPCTX')
        c, mcs, mem_var = ctxs[0]
        n = count or max_val
        vars_ = read_vars(mem, mem_var, n)
        print('vars read', len(vars_))
        for v in vars_:
            if any(v['len']):
                print('%5d flag=%d mode=%d len=%s size=%d pt=%#x off=%d' %
                      (v['idx'], v['flag'], v['mode'], v['len'], v['size'],
                       v['pt'], v['offset']))
        return dict(script=sc, ctx=c, vars=vars_)
    finally:
        mem.close()


if __name__ == '__main__':
    dump(int(sys.argv[1]) if len(sys.argv) > 1 else winmem.find_pid(sys.argv[2]))
