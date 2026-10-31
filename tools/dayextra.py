#!/usr/bin/env python3
"""Extra analysers for Huntress Binary RE days 16-30: Java classfile parsing,
PK19 / RS20 packed overlays, and synthetic-crash trace handling."""
import hashlib
import json
import struct
import zipfile

import hcfg


# --------------------------------------------------------------------------
# Java .class / JAR
# --------------------------------------------------------------------------
def _parse_constant_pool(b, off):
    count = struct.unpack_from(">H", b, off)[0]
    off += 2
    cp = [None] * count
    i = 1
    while i < count:
        tag = b[off]; off += 1
        if tag == 1:  # Utf8
            ln = struct.unpack_from(">H", b, off)[0]; off += 2
            cp[i] = ("utf8", b[off:off + ln].decode("utf-8", "replace")); off += ln
        elif tag in (7, 8, 16, 19, 20):      # Class/String/MethodType/Module/Package (u2)
            cp[i] = (tag, struct.unpack_from(">H", b, off)[0]); off += 2
        elif tag in (3, 4, 9, 10, 11, 12, 17, 18):  # int/float/refs/NameAndType/dynamic (u4)
            cp[i] = (tag, b[off:off + 4]); off += 4
        elif tag in (5, 6):                   # long/double take two slots
            cp[i] = (tag, b[off:off + 8]); off += 8; i += 1
        elif tag == 15:                       # MethodHandle (u3)
            cp[i] = (tag, b[off:off + 3]); off += 3
        else:
            break
        i += 1
    return cp, off


def classfile_info(b):
    """Return {this_class, access_flags, methods:[names in table order]}."""
    assert b[:4] == b"\xca\xfe\xba\xbe", "not a classfile"
    cp, off = _parse_constant_pool(b, 8)
    access_flags = struct.unpack_from(">H", b, off)[0]; off += 2
    this_class = struct.unpack_from(">H", b, off)[0]; off += 2
    off += 2  # super_class
    icount = struct.unpack_from(">H", b, off)[0]; off += 2 + 2 * icount
    def utf8(idx):
        e = cp[idx]
        return e[1] if e and e[0] == "utf8" else None
    def class_name(idx):
        e = cp[idx]  # Class -> name_index -> utf8
        return utf8(e[1]) if e else None
    # fields
    fcount = struct.unpack_from(">H", b, off)[0]; off += 2
    for _ in range(fcount):
        off += 6  # access,name,desc
        acount = struct.unpack_from(">H", b, off)[0]; off += 2
        for _ in range(acount):
            alen = struct.unpack_from(">I", b, off + 2)[0]; off += 6 + alen
    # methods
    mcount = struct.unpack_from(">H", b, off)[0]; off += 2
    methods = []
    for _ in range(mcount):
        off += 2  # access_flags
        name_idx = struct.unpack_from(">H", b, off)[0]; off += 2
        off += 2  # descriptor
        methods.append(utf8(name_idx))
        acount = struct.unpack_from(">H", b, off)[0]; off += 2
        for _ in range(acount):
            alen = struct.unpack_from(">I", b, off + 2)[0]; off += 6 + alen
    return {"this_class": class_name(this_class),
            "access_flags": access_flags, "methods": methods}


def jar_main_class_entry(z):
    try:
        mf = z.read("META-INF/MANIFEST.MF").decode("latin1")
    except KeyError:
        return None
    for line in mf.splitlines():
        if line.lower().startswith("main-class:"):
            return line.split(":", 1)[1].strip().replace(".", "/") + ".class"
    return None


def jar_primary_classinfo(path):
    """Classinfo for the Main-Class (or the non-inner primary) class in a jar."""
    z = zipfile.ZipFile(path)
    entry = jar_main_class_entry(z)
    if entry and entry in z.namelist():
        return classfile_info(z.read(entry))
    classes = [n for n in z.namelist() if n.endswith(".class") and "$" not in n]
    if classes:
        return classfile_info(z.read(classes[0]))
    any_cls = [n for n in z.namelist() if n.endswith(".class")]
    return classfile_info(z.read(any_cls[0])) if any_cls else None


def crash_trace(path):
    z = zipfile.ZipFile(path)
    for n in z.namelist():
        if n.endswith("trace.json"):
            return json.loads(z.read(n))
    return None


# --------------------------------------------------------------------------
# PK19 / RS20 overlays
# --------------------------------------------------------------------------
def _ror8(x, n):
    return ((x >> n) | (x << (8 - n))) & 0xff


def pk19(path):
    """Parse the final PK19 packed overlay; return dict with keys, offsets and
    the decoded HCFG config (campaign/domain/url/mutex/crc32/version)."""
    d = open(path, "rb").read()
    i = d.rfind(b"PK19")
    if i < 0:
        return None
    k1, k2 = d[i + 5], d[i + 6]
    plen = struct.unpack_from("<I", d, i + 8)[0]
    packed = d[i + 44:i + 44 + plen]
    unp = bytes(_ror8(b ^ k2, 3) ^ k1 for b in packed)
    cfg = hcfg.find_config_bytes(unp) if hasattr(hcfg, "find_config_bytes") else None
    return {"offset": i, "size": len(d) - i, "k1": k1, "k2": k2, "unpacked": unp,
            "config": cfg}


def rs20(path):
    d = open(path, "rb").read()
    i = d.rfind(b"RS20")
    if i < 0:
        return None
    # RS20(4) version(u32) resource_size(u32le @ +8) ...
    size = struct.unpack_from("<I", d, i + 8)[0]
    return {"offset": i, "size": len(d) - i, "resource_size": size, "raw": d[i:]}


# --------------------------------------------------------------------------
# HGRF (day 30): HCFG-layout record holding a campaign graph JSON
# --------------------------------------------------------------------------
def find_record_backward(data, magic=b"HGRF"):
    """Last CRC32-valid record with the HCFG 12-byte layout, scanning backward."""
    import zlib
    i = len(data)
    while True:
        i = data.rfind(magic, 0, i)
        if i < 0:
            return None
        if i + 12 <= len(data):
            key = data[i + 5]
            ln = struct.unpack_from("<H", data, i + 6)[0]
            crc = struct.unpack_from("<I", data, i + 8)[0]
            if i + 12 + ln <= len(data):
                pl = bytes(b ^ key for b in data[i + 12:i + 12 + ln])
                if (zlib.crc32(pl) & 0xffffffff) == crc:
                    try:
                        return json.loads(pl.decode("utf-8"))
                    except Exception:
                        pass
        if i == 0:
            return None


def hgrf_graph_config(path):
    rec = find_record_backward(open(path, "rb").read())
    if not rec:
        return None
    g = rec.get("graph", rec)
    return g.get("config") if isinstance(g, dict) else None


def hgau(path, magic=b"HGAU"):
    """Return {'xor_key','crc32','json'} for the last CRC-valid HGAU-layout
    record (same 12-byte header as HCFG), else None."""
    import zlib
    data = open(path, "rb").read()
    i = len(data)
    while True:
        i = data.rfind(magic, 0, i)
        if i < 0:
            return None
        if i + 12 <= len(data):
            key = data[i + 5]
            ln = struct.unpack_from("<H", data, i + 6)[0]
            crc = struct.unpack_from("<I", data, i + 8)[0]
            if i + 12 + ln <= len(data):
                pl = bytes(b ^ key for b in data[i + 12:i + 12 + ln])
                if (zlib.crc32(pl) & 0xffffffff) == crc:
                    try:
                        return {"xor_key": key, "crc32": crc, "json": json.loads(pl.decode("utf-8"))}
                    except Exception:
                        pass
        if i == 0:
            return None
