#!/usr/bin/env python3
"""ELF / PE metadata extraction for the Huntress Binary RE lane.

Pure-stdlib parsing of the fields the Game Master asks about: class, data
(endianness), machine, type, entry point, section names, symbols, .symtab
presence, the custom ``.huntress`` marker, and the ``recover_code`` constant.
Falls back to ``readelf``/``objdump`` only for x86 disassembly of the recovery
constant.
"""
import struct
import subprocess

# e_machine code -> readelf-style name
EM = {
    0x3e: "Advanced Micro Devices X86-64",
    0x03: "Intel 80386",
    0xb7: "AArch64",
    0x28: "ARM",
    0xf3: "RISC-V",
    0x08: "MIPS R3000",
    0x3a: "Renesas SH",
    0x15: "PowerPC64",
    0x14: "PowerPC",
}
EM_SHORT = {0x3e: "x86-64", 0x03: "i386", 0xb7: "aarch64", 0x28: "arm", 0xf3: "riscv"}
# Game Master canonical ELF type strings use the ET_ enum form.
ET = {0: "ET_NONE", 1: "ET_REL", 2: "ET_EXEC", 3: "ET_DYN", 4: "ET_CORE"}


class ELF:
    def __init__(self, path):
        self.path = path
        with open(path, "rb") as fh:
            self.data = fh.read()
        d = self.data
        assert d[:4] == b"\x7fELF", "not ELF"
        self.ei_class = d[4]           # 1=32, 2=64
        self.ei_data = d[5]            # 1=LSB, 2=MSB
        self.is64 = self.ei_class == 2
        self.end = "<" if self.ei_data == 1 else ">"
        e = self.end
        self.e_type = struct.unpack_from(e + "H", d, 16)[0]
        self.e_machine = struct.unpack_from(e + "H", d, 18)[0]
        if self.is64:
            self.e_entry = struct.unpack_from(e + "Q", d, 24)[0]
            self.e_shoff = struct.unpack_from(e + "Q", d, 40)[0]
            self.e_shentsize = struct.unpack_from(e + "H", d, 58)[0]
            self.e_shnum = struct.unpack_from(e + "H", d, 60)[0]
            self.e_shstrndx = struct.unpack_from(e + "H", d, 62)[0]
        else:
            self.e_entry = struct.unpack_from(e + "I", d, 24)[0]
            self.e_shoff = struct.unpack_from(e + "I", d, 32)[0]
            self.e_shentsize = struct.unpack_from(e + "H", d, 46)[0]
            self.e_shnum = struct.unpack_from(e + "H", d, 48)[0]
            self.e_shstrndx = struct.unpack_from(e + "H", d, 50)[0]
        self._parse_sections()

    def _parse_sections(self):
        d, e = self.data, self.end
        self.sections = []  # (name, type, addr, offset, size)
        raw = []
        for i in range(self.e_shnum):
            off = self.e_shoff + i * self.e_shentsize
            name_off = struct.unpack_from(e + "I", d, off)[0]
            sh_type = struct.unpack_from(e + "I", d, off + 4)[0]
            if self.is64:
                addr = struct.unpack_from(e + "Q", d, off + 16)[0]
                foff = struct.unpack_from(e + "Q", d, off + 24)[0]
                size = struct.unpack_from(e + "Q", d, off + 32)[0]
                link = struct.unpack_from(e + "I", d, off + 40)[0]
                entsz = struct.unpack_from(e + "Q", d, off + 56)[0]
            else:
                addr = struct.unpack_from(e + "I", d, off + 12)[0]
                foff = struct.unpack_from(e + "I", d, off + 16)[0]
                size = struct.unpack_from(e + "I", d, off + 20)[0]
                link = struct.unpack_from(e + "I", d, off + 24)[0]
                entsz = struct.unpack_from(e + "I", d, off + 36)[0]
            raw.append((name_off, sh_type, addr, foff, size, link, entsz))
        strtab_off = raw[self.e_shstrndx][3]

        def getname(o):
            endp = d.index(b"\x00", strtab_off + o)
            return d[strtab_off + o:endp].decode("latin1")

        self._raw = raw
        for (name_off, sh_type, addr, foff, size, link, entsz) in raw:
            self.sections.append({
                "name": getname(name_off), "type": sh_type, "addr": addr,
                "offset": foff, "size": size, "link": link, "entsize": entsz,
            })

    # --- field accessors -------------------------------------------------
    def elf_class(self):
        return "ELF64" if self.is64 else "ELF32"

    def endianness(self):
        # Game Master canonical byte-order string.
        return "little" if self.ei_data == 1 else "big"

    def machine(self):
        return EM.get(self.e_machine, f"0x{self.e_machine:x}")

    def machine_short(self):
        return EM_SHORT.get(self.e_machine, f"0x{self.e_machine:x}")

    def elf_type(self):
        return ET.get(self.e_type, str(self.e_type))

    def entry_point(self):
        return f"0x{self.e_entry:x}"

    def section_names(self):
        return [s["name"] for s in self.sections if s["name"]]

    def has_symtab(self):
        return any(s["name"] == ".symtab" for s in self.sections)

    def section_bytes(self, name):
        for s in self.sections:
            if s["name"] == name:
                return self.data[s["offset"]:s["offset"] + s["size"]]
        return None

    def huntress_marker(self):
        b = self.section_bytes(".huntress")
        if b is None:
            return None
        return b.split(b"\x00")[0].decode("latin1")

    def symbols(self):
        """Return list of dicts for .symtab entries: name,bind,type,value,shndx."""
        d, e = self.data, self.end
        symtab = next((s for s in self.sections if s["name"] == ".symtab"), None)
        if not symtab:
            symtab = next((s for s in self.sections if s["type"] == 2), None)  # SHT_SYMTAB
        if not symtab:
            return []
        strt = self.sections[symtab["link"]]
        stroff = strt["offset"]
        out = []
        entsz = symtab["entsize"] or (24 if self.is64 else 16)
        n = symtab["size"] // entsz
        for i in range(n):
            off = symtab["offset"] + i * entsz
            name_off = struct.unpack_from(e + "I", d, off)[0]
            if self.is64:
                info = d[off + 4]; shndx = struct.unpack_from(e + "H", d, off + 6)[0]
                value = struct.unpack_from(e + "Q", d, off + 8)[0]
            else:
                value = struct.unpack_from(e + "I", d, off + 4)[0]
                info = d[off + 12]; shndx = struct.unpack_from(e + "H", d, off + 14)[0]
            endp = d.index(b"\x00", stroff + name_off)
            name = d[stroff + name_off:endp].decode("latin1")
            out.append({"name": name, "bind": info >> 4, "type": info & 0xf,
                        "value": value, "shndx": shndx})
        return out

    def global_funcs(self):
        return [s for s in self.symbols()
                if s["type"] == 2 and s["bind"] == 1 and s["shndx"] != 0]

    def recover_symbol(self):
        """The designated analysis symbol: prefer one literally named recover_code,
        else a non-libc global FUNC that is not main/_start."""
        syms = self.global_funcs()
        for s in syms:
            if s["name"] == "recover_code":
                return s
        junk = {"main", "_start", "_init", "_fini", "_dl_relocate_static_pie"}
        cand = [s for s in syms if s["name"] not in junk and not s["name"].startswith("__")]
        return cand[0] if cand else None

    def recover_constant(self):
        """Return the integer constant returned by the recover function.

        Prefers the resolved symbol; if the binary is stripped, scans ``.text``
        for the unique ``mov eax, imm32; ret`` (``b8 imm32 c3``) stub.
        """
        sym = self.recover_symbol()
        if not sym:
            import re as _re
            text = next((s for s in self.sections if s["name"] == ".text"), None)
            if text:
                tb = self.data[text["offset"]:text["offset"] + text["size"]]
                hits = [struct.unpack("<i", m.group(1))[0]
                        for m in _re.finditer(rb"\xb8(....)\xc3", tb)]
                if len(hits) == 1:
                    return hits[0]
                # multiple: prefer the stub at the conventional 0x401120
                off = text["offset"] + (0x401120 - text["addr"])
                if 0 <= off <= len(self.data) - 6 and self.data[off:off+1] == b"\xb8":
                    return struct.unpack("<i", self.data[off+1:off+5])[0]
                if hits:
                    return hits[0]
            return None
        # locate section containing the function to compute file offset
        for s in self.sections:
            if s["addr"] <= sym["value"] < s["addr"] + s["size"] and s["offset"]:
                foff = s["offset"] + (sym["value"] - s["addr"])
                code = self.data[foff:foff + 16]
                # mov eax, imm32 = b8 imm32 ; mov eax,imm then ret c3
                if code[:1] == b"\xb8":
                    return struct.unpack_from("<i", code, 1)[0]
                # xor eax,eax (31 c0) -> 0
                if code[:2] == b"\x31\xc0":
                    return 0
                break
        # fallback: objdump
        try:
            out = subprocess.check_output(
                ["objdump", "-d", self.path, "-M", "intel",
                 f"--start-address=0x{sym['value']:x}",
                 f"--stop-address=0x{sym['value']+16:x}"],
                text=True, stderr=subprocess.DEVNULL)
            import re
            m = re.search(r"mov\s+eax,0x([0-9a-f]+)", out)
            if m:
                return int(m.group(1), 16)
        except Exception:
            pass
        return None


def format_label(path):
    """ELF64 / ELF32 / PE32 / PE32+ from the first bytes."""
    with open(path, "rb") as fh:
        head = fh.read(0x200)
    if head[:4] == b"\x7fELF":
        return "ELF64" if head[4] == 2 else "ELF32"
    if head[:2] == b"MZ":
        pe = struct.unpack_from("<I", head, 0x3c)[0]
        with open(path, "rb") as fh:
            fh.seek(pe)
            sig = fh.read(0x40)
        if sig[:4] == b"PE\x00\x00":
            magic = struct.unpack_from("<H", sig, 24)[0]
            return "PE32+" if magic == 0x20b else "PE32"
        return "PE"
    return None


if __name__ == "__main__":
    import sys, json
    for p in sys.argv[1:]:
        e = ELF(p)
        print(json.dumps({
            "class": e.elf_class(), "endianness": e.endianness(),
            "machine": e.machine(), "machine_short": e.machine_short(),
            "type": e.elf_type(), "entry": e.entry_point(),
            "has_symtab": e.has_symtab(), "marker": e.huntress_marker(),
            "recover_symbol": (e.recover_symbol() or {}).get("name"),
            "recover_constant": e.recover_constant(),
            "nsections": len(e.sections),
        }, indent=2))
