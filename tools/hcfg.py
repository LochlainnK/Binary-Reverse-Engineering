#!/usr/bin/env python3
"""Universal HCFG config extractor for the Huntress CTF Binary RE lane.

Every specimen from Day 2 onward embeds a malware-style configuration blob with
the layout::

    "HCFG" | version(u8) | xor_key(u8) | payload_len(u16 LE) | crc32(u32 LE) | XOR(payload)

where ``payload`` is a UTF-8 JSON object (campaign/domain/url/mutex/...) XORed
byte-wise with ``xor_key``, and ``crc32`` is CRC-32 of the *decoded* payload.

The blob is carried three different ways depending on the toolchain:
  * raw in the file (C++, Go, Rust, Swift, Zig, Pascal, .NET)   -> literal "HCFG"
  * Base64 string constant (Java/Kotlin, Nim, D, Crystal)        -> decode first
  * inside a JAR -> a Base64 constant within a .class entry

``find_config`` returns the first blob whose CRC validates and whose payload
contains ``"campaign"``, so false positives (assertion strings, decoys) are
rejected automatically.
"""
import base64
import json
import re
import struct
import zlib
import zipfile

B64_RE = re.compile(rb'[A-Za-z0-9+/]{40,}={0,2}')


class Config:
    def __init__(self, blob, *, carrier, file_offset=None, b64_offset=None):
        self.version = blob[4]
        self.xor_key = blob[5]
        self.length = struct.unpack('<H', blob[6:8])[0]
        self.crc32 = struct.unpack('<I', blob[8:12])[0]
        self.payload = bytes(b ^ self.xor_key for b in blob[12:12 + self.length])
        self.crc_ok = (zlib.crc32(self.payload) & 0xffffffff) == self.crc32
        self.carrier = carrier            # 'raw' | 'base64' | 'jar'
        self.file_offset = file_offset    # offset of literal "HCFG" in the file (raw carrier)
        self.b64_offset = b64_offset      # offset of the base64 string (base64 carrier)
        try:
            self.json = json.loads(self.payload.decode('utf-8'))
        except Exception:
            self.json = None

    def as_dict(self):
        return {
            "version": self.version,
            "xor_key": self.xor_key,
            "xor_key_hex": f"{self.xor_key:02x}",
            "length": self.length,
            "crc32": self.crc32,
            "crc32_hex": f"{self.crc32:08x}",
            "crc_ok": self.crc_ok,
            "carrier": self.carrier,
            "file_offset": self.file_offset,
            "b64_offset": self.b64_offset,
            "config": self.json,
        }


def _valid(blob):
    if len(blob) < 12 or blob[:4] != b'HCFG':
        return False
    ln = struct.unpack('<H', blob[6:8])[0]
    if 12 + ln > len(blob):
        return False
    key = blob[5]
    pl = bytes(b ^ key for b in blob[12:12 + ln])
    crc = struct.unpack('<I', blob[8:12])[0]
    return (zlib.crc32(pl) & 0xffffffff) == crc and b'"campaign"' in pl


_B64CHARS = set(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")


def _b64_at(data, i):
    """Extend a base64 token starting at i and decode it."""
    j = i
    n = len(data)
    while j < n and data[j] in _B64CHARS:
        j += 1
    tok = data[i:j]
    tok += b"=" * ((4 - len(tok) % 4) % 4)
    try:
        return base64.b64decode(tok)
    except Exception:
        return b""


def _scan_bytes(data):
    """Yield Config objects found directly in *data* (raw or base64 carriers).

    Fast path: literal ``HCFG`` (raw) and ``SENG`` (= base64 of "HCF...") byte
    searches, which are C-speed even on 60+ MB binaries. Only if neither hits
    do we fall back to the full base64 regex (small files, odd alignment).
    """
    # raw literal HCFG blobs
    start = 0
    while True:
        i = data.find(b'HCFG', start)
        if i < 0:
            break
        if _valid(data[i:i + 12 + 0x10000]):
            yield Config(data[i:i + 12 + struct.unpack('<H', data[i+6:i+8])[0]],
                         carrier='raw', file_offset=i)
        start = i + 1
    # base64-encoded HCFG blobs: a blob begins "HCFG" -> base64 begins "SENG"
    start = 0
    hit = False
    while True:
        i = data.find(b'SENG', start)
        if i < 0:
            break
        blob = _b64_at(data, i)
        if _valid(blob):
            yield Config(blob, carrier='base64', b64_offset=i)
            hit = True
        start = i + 1
    if hit:
        return
    # fallback: full regex (only reached for small/odd inputs)
    for m in B64_RE.finditer(data):
        try:
            blob = base64.b64decode(m.group())
        except Exception:
            continue
        if _valid(blob):
            yield Config(blob, carrier='base64', b64_offset=m.start())


def find_config(path):
    """Return the first validated Config in *path* (handles ELF/PE/JAR)."""
    with open(path, 'rb') as fh:
        data = fh.read()
    if data[:2] == b'PK':  # zip/jar: search each entry
        try:
            z = zipfile.ZipFile(path)
            for n in z.namelist():
                for cfg in _scan_bytes(z.read(n)):
                    cfg.carrier = 'jar'
                    return cfg
        except Exception:
            pass
    for cfg in _scan_bytes(data):
        return cfg
    return None


if __name__ == '__main__':
    import sys
    for p in sys.argv[1:]:
        cfg = find_config(p)
        print(p)
        print(json.dumps(cfg.as_dict(), indent=2) if cfg else "  no config found")
