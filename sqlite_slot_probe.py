#!/usr/bin/env python3
"""Locate sqlite3_* import slots in searchpartyd's __auth_got / __got.
Uses LC_DYLD_CHAINED_FIXUPS import table (symbol names) + binds found by
scanning GOT pointer words. Read-only, no deps.
"""
import struct, sys, os

path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(__file__), "bin", "searchpartyd")
data = open(path, "rb").read()
U16 = lambda o: struct.unpack_from("<H", data, o)[0]
U32 = lambda o: struct.unpack_from("<I", data, o)[0]
U64 = lambda o: struct.unpack_from("<Q", data, o)[0]

ncmds = U32(16)
off = 32
cf = None
segs = {}     # name -> (vmaddr, vmsize, fileoff, filesize)
sects = []    # (seg,sect,addr,size,offset)
dylib_order = []  # 1-based ordinal -> install name
for i in range(ncmds):
    cmd = U32(off); cmdsize = U32(off + 4)
    if cmd == 0x19:  # SEGMENT_64
        seg = data[off+8:off+24].rstrip(b"\0").decode()
        vm = U64(off+24); vs = U64(off+32); fo = U64(off+40); fs = U64(off+48)
        segs[seg] = (vm, vs, fo, fs)
        so = off + 72
        for s in range(U32(off+64)):
            sn = data[so:so+16].rstrip(b"\0").decode()
            sg = data[so+16:so+32].rstrip(b"\0").decode()
            sects.append((sg, sn, U64(so+32), U64(so+40), U32(so+48), U32(so+56), U32(so+60)))
            so += 80
    elif cmd in (0xc, 0x18, 0x1c, 0x8000001c, 0xd):
        noff = U32(off+8)
        p = data[off+noff:off+cmdsize].split(b"\0")[0].decode()
        if cmd != 0xd: dylib_order.append(p)
    elif cmd in (0x34, 0x80000034):
        cf = (U32(off+8), U32(off+12))
    off += cmdsize

assert cf, "no LC_DYLD_CHAINED_FIXUPS"
base, size = cf
ver = U32(base); starts_off=U32(base+4); imports_off=U32(base+8); symbols_off=U32(base+12)
imports_count=U32(base+16); symbols_format=U32(base+20); imports_format=U32(base+24)
print(f"chained fixups ver={ver} starts=+{starts_off:#x} imports=+{imports_off:#x} symbols=+{symbols_off:#x} count={imports_count} sym_fmt={symbols_format} imp_fmt={imports_format}")

# symbols table: array of offsets into cstring pool at base+symbols_off
sym_pool = base + symbols_off
def sym_at(name_off):
    p = sym_pool + name_off
    return data[p:data.index(b"\0", p)].decode("utf-8", "replace")

imports = []
for i in range(imports_count):
    v = U32(base + imports_off + 4*i)
    lib_ord = (v >> 0) & 0xff
    weak = (v >> 8) & 1
    name_off = (v >> 9) & 0x7fffff
    imports.append((lib_ord, weak, sym_at(name_off)))

print(f"\n=== dylib ordinals referenced by sqlite imports ===")
ord_seen = sorted({o for o, w, s in imports if "sqlite" in s})
for o in ord_seen:
    print(f"  ordinal {o}: {dylib_order[o-1] if 0 < o <= len(dylib_order) else '?'}")

print(f"\n=== sqlite3_* imports (ordinal, weak, name) ===")
for i, (o, w, s) in enumerate(imports):
    if "sqlite3" in s:
        print(f"  imp#{i:4} ord={o:2} weak={w} {s}")

# Scan GOT sections. In chained fixups ARM64E, an auth bind pointer has:
#   bit63 bind=1, bit62 auth=1, ordinal=low16
# A plain bind pointer: bit63 bind=1, bit62 auth=0, ordinal=low16
def classify(v):
    bind = (v >> 63) & 1
    auth = (v >> 62) & 1
    if not bind: return None
    return ("auth" if auth else "plain", v & 0xffff, (v >> 51) & 0x7ff, (v >> 32) & 0xffff)

target = {}
for sg, sn, addr, sz, ofs, nr, ro in sects:
    if sn not in ("__auth_got", "__got"): continue
    print(f"\n=== {sg},{sn} vm={addr:#x} size={sz:#x} ({sz//8} slots) ===")
    for idx in range(sz // 8):
        v = U64(ofs + 8*idx)
        c = classify(v)
        if not c: continue
        kind, ordinal, nxt, div = c
        if ordinal >= len(imports): continue
        name = imports[ordinal][2]
        if "sqlite3" in name:
            slot_addr = addr + 8*idx
            print(f"  slot#{idx:4} vm={slot_addr:#x} {kind:5} ord={ordinal:3} next={nxt} div={div:#x} -> {name}")
            target.setdefault(name, []).append((sn, idx, slot_addr, kind, ordinal))

print(f"\n=== resolved sqlite3_step / prepare_v2 slots ===")
for name in ("_sqlite3_step", "_sqlite3_prepare_v2", "_sqlite3_finalize", "_sqlite3_sql", "_sqlite3_exec"):
    print(f"  {name}: {target.get(name, 'NOT FOUND in GOT')}")
