#!/usr/bin/env python3
"""End-to-end automated solver for the Huntress CTF Binary RE lane.

Because Time Trial / Mastery attempts run on a short server-enforced countdown
(as little as 30 seconds), the whole loop must happen in one fast process:

    start|retry  ->  download artifact  ->  extract  ->  answer every field  ->  submit

Run::

    HUNTRESS_GM_TOKEN_FILE=... python3 autosolve.py <challenge-id> [--retry]
        [--run-for-time] [--start] [--dry-run] [--work DIR]

``--retry`` spends a fresh variant (a new scored attempt); ``--start`` just
reconnects to the current attempt; default auto-picks: retry when the current
attempt is already solved/expired, else start.
"""
import argparse
import hashlib
import io
import json
import os
import re
import struct
import sys
import time
import zipfile
import zlib
from urllib.parse import urlencode

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gm  # noqa: E402  (curl wrapper + token handling)
from elfmeta import ELF, format_label, EM, EM_SHORT  # noqa: E402
import hcfg  # noqa: E402

ZIP_PASSWORD = b"infected"


def _cjson(obj):
    """Compact JSON (no spaces) as the grader expects for array answers."""
    return json.dumps(obj, separators=(",", ":"))


# --------------------------------------------------------------------------
# artifact download + extraction
# --------------------------------------------------------------------------
def download_artifact(challenge, work, delivery=None):
    params = {"op": "artifact", "challenge": challenge}
    if delivery is not None:
        params["delivery"] = delivery
    raw = gm._get(params)
    suffix = f"_{delivery}" if delivery is not None else ""
    path = os.path.join(work, f"artifact{suffix}.zip")
    with open(path, "wb") as fh:
        fh.write(raw)
    return path


def _run_incremental(challenge, start, answer_ids, set_ids, work, t0):
    """Per-set pipeline: each set downloads, solves and submits in its own
    thread so correct answers bank the instant they're ready. A final combined
    submit (all sets) tips the attempt to CORRECT once everything is in."""
    import threading
    questions = start.get("questions")
    by_set = {}
    for aid in answer_ids:
        m = re.match(r"set(\d+)\.", aid)
        by_set.setdefault(int(m.group(1)) - 1 if m else 0, []).append(aid)
    all_answers = {}
    lock = threading.Lock()
    results = {}

    def one(idx):
        d = os.path.join(work, f"set{idx}")
        os.makedirs(d, exist_ok=True)
        files = extract(download_artifact(challenge, d, delivery=idx), d)
        ans, _ = solve(by_set[idx], {idx: files}, questions)
        payload = {k: v for k, v in ans.items() if v is not None}
        res = json.loads(gm._post({"challenge": challenge, "answers": payload}).decode())
        with lock:
            all_answers.update(payload)
            results[idx] = res.get("result")
        print(f"[set{idx+1}] {len(payload)}/{len(by_set[idx])} submitted -> "
              f"{res.get('result')} rem={res.get('remaining')} ({time.time()-t0:.2f}s)")

    threads = [threading.Thread(target=one, args=(i,)) for i in set_ids]
    for th in threads:
        th.start()
    for th in threads:
        th.join()
    # final combined submit to settle the attempt (idempotent for banked answers)
    res = json.loads(gm._post({"challenge": challenge, "answers": all_answers}).decode())
    print(f"[=] final: {res.get('result')} rem={res.get('remaining')} "
          f"elapsed={time.time()-t0:.2f}s")
    with open(os.path.join(work, "result.json"), "w") as fh:
        json.dump(res, fh, indent=1)
    return res.get("result")


def _download_sets(challenge, set_ids, work):
    """Download & extract one delivery per set, concurrently. Returns {set_idx: files}."""
    import concurrent.futures as cf
    out = {}

    def one(idx):
        d = os.path.join(work, f"set{idx}")
        os.makedirs(d, exist_ok=True)
        zp = download_artifact(challenge, d, delivery=idx)
        return idx, extract(zp, d)

    with cf.ThreadPoolExecutor(max_workers=len(set_ids)) as ex:
        for idx, files in ex.map(one, set_ids):
            out[idx] = files
    return out


def extract(zip_path, work):
    """Extract (AES 'infected' or plain) into work/ex, return {name: abspath}."""
    outdir = os.path.join(work, "ex")
    os.makedirs(outdir, exist_ok=True)
    files = {}
    try:
        import pyzipper
        with pyzipper.AESZipFile(zip_path) as z:
            z.setpassword(ZIP_PASSWORD)
            for n in z.namelist():
                data = z.read(n)
                p = os.path.join(outdir, os.path.basename(n))
                with open(p, "wb") as fh:
                    fh.write(data)
                files[os.path.basename(n)] = p
        return files
    except Exception:
        pass
    with zipfile.ZipFile(zip_path) as z:
        try:
            z.extractall(outdir, pwd=ZIP_PASSWORD)
        except Exception:
            z.extractall(outdir)
        for n in z.namelist():
            if not n.endswith("/"):
                files[os.path.basename(n)] = os.path.join(outdir, os.path.basename(n))
    return files


# --------------------------------------------------------------------------
# field computation
# --------------------------------------------------------------------------
def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def cpp_symbols(path):
    """Return dict with vtable/typeinfo presence and score/vtable symbol names
    by scanning the ELF .symtab/.dynsym strings for Itanium-mangled names."""
    data = open(path, "rb").read()
    names = set(re.findall(rb"_Z[A-Za-z0-9_]+", data))
    names = {n.decode("latin1") for n in names}
    vtable = sorted(n for n in names if n.startswith("_ZTV"))
    typeinfo = sorted(n for n in names if n.startswith("_ZTI"))
    score = sorted(n for n in names if "score" in n.lower() and n.startswith("_Z"))
    # the user class vtable (skip cxxabiv internal ones)
    user_vtable = [n for n in vtable if "cxxabiv" not in n]
    return {
        "has_cpp_vtable": bool(vtable),
        "has_cpp_typeinfo": bool(typeinfo),
        "vtable_symbol": (user_vtable or vtable or [None])[0],
        "score_symbol": (score or [None])[0],
    }


def jar_compression_methods(path):
    methods = set()
    with zipfile.ZipFile(path) as z:
        for i in z.infolist():
            methods.add(i.compress_type)  # 0=stored, 8=deflated
    return sorted(methods)


class Specimen:
    """Lazily analyze one artifact file and answer any field asked of it."""
    def __init__(self, path):
        self.path = path
        self.data = open(path, "rb").read()
        self.kind = self._kind()
        self._elf = None
        self._cfg = None
        self._cpp = None
        self._symn = None

    def _kind(self):
        if self.data[:4] == b"\x7fELF":
            return "elf"
        if self.data[:2] == b"MZ":
            return "pe"
        if self.data[:4] == b"\x00asm":
            return "wasm"
        if self.data[:3] == b"NEK" or self.data[:5] == b"NEKO\x00":
            return "neko"
        if self.data[:2] == b"PK":
            return "zip"
        return "unknown"

    @property
    def elf(self):
        if self._elf is None and self.kind == "elf":
            self._elf = ELF(self.path)
        return self._elf

    @property
    def cfg(self):
        if self._cfg is None:
            self._cfg = hcfg.find_config(self.path)
        return self._cfg

    @property
    def cpp(self):
        if self._cpp is None:
            self._cpp = cpp_symbols(self.path)
        return self._cpp

    # --- generic field answerer --------------------------------------------
    def answer(self, field, fmt=None):
        e = self.elf
        c = self.cfg
        kind = (fmt or {}).get("kind")
        # --- container / arch ---
        if field in ("elf_class", "analysis_elf_class"):
            if not e:
                return "none"
            if kind == "integer":           # some days want the bare class number
                return "64" if e.is64 else "32"
            return e.elf_class()
        if field in ("endianness", "analysis_endianness"):
            return e.endianness()
        if field in ("machine", "analysis_machine"):
            if kind == "integer":          # raw e_machine / IMAGE_FILE_MACHINE code
                if e:
                    return str(e.e_machine)
                if self.kind == "pe":
                    return str(struct.unpack_from("<H", self.data,
                               struct.unpack_from("<I", self.data, 0x3c)[0] + 4)[0])
                return "none"
            if self.kind == "wasm":
                return "wasm32"
            return e.machine_short() if e else self._pe_machine()
        if field in ("architecture", "analysis_architecture"):
            if self.kind == "wasm":
                return "wasm32"
            return e.machine_short() if e else self._pe_machine()
        if field in ("elf_type", "analysis_elf_type"):
            return e.elf_type()
        if field in ("format", "analysis_format", "cpp_format"):
            if kind in ("exact_text", "enum"):
                # lowercase container token; .NET PE -> pe_cli; wasm/jar/neko
                if self.kind == "pe":
                    return "pe_cli" if self._is_dotnet() else "pe"
                return {"elf": "elf", "zip": "jar", "wasm": "wasm",
                        "neko": "neko_bytecode"}.get(self.kind, (self._format() or "").lower())
            # pattern: managed (.NET) specimens want a compound container+runtime token
            return self._format(compound=self._is_dotnet())
        if field in ("entry_point", "analysis_entry_point"):
            return e.entry_point()
        # --- symbols / markers ---
        if field in ("marker", "c_marker", "analysis_marker"):
            return e.huntress_marker()
        if field in ("has_symtab", "c_has_symtab", "analysis_has_symtab"):
            return "true" if e.has_symtab() else "false"
        if field in ("exported_symbol", "analysis_exported_symbol"):
            sym = e.recover_symbol()
            return sym["name"] if sym else "none"
        if field in ("recover_code", "c_recover_code", "analysis_recover_code"):
            # keyed to the named symbol: absent (stripped) -> the field is absent
            if e.recover_symbol() is None:
                return "none"
            return str(e.recover_constant())
        if field in ("section_names", "analysis_section_names"):
            if e:
                return _cjson([s["name"] for s in e.sections])
            if self.kind == "pe":
                try:
                    return _cjson(self._pe_section_names())
                except Exception:
                    return "none"
            return "none"
        if field in ("symbols", "analysis_symbols"):
            return _cjson([s["name"] for s in e.symbols() if s["name"]])
        if field in ("disassembly", "analysis_disassembly"):
            return _cjson(e.recover_disasm())
        # --- C++ ---
        if field in ("has_cpp_vtable", "analysis_has_cpp_vtable"):
            return "true" if self.cpp["has_cpp_vtable"] else "false"
        if field in ("has_cpp_typeinfo", "analysis_has_cpp_typeinfo"):
            return "true" if self.cpp["has_cpp_typeinfo"] else "false"
        if field in ("vtable_symbol", "analysis_vtable_symbol"):
            return self._first_symbol_matching(r"ZTV.*DiscoveryEngine")
        if field in ("mangled_score_symbol", "analysis_mangled_score_symbol"):
            return self._first_symbol_matching(r"DiscoveryEngine.*score")
        # --- config (HCFG) ---
        if field in ("campaign", "analysis_config_campaign"):
            return c.json.get("campaign") if c and c.json else None
        if field in ("domain", "analysis_config_domain"):
            return c.json.get("domain") if c and c.json else None
        if field in ("url", "analysis_config_url"):
            return c.json.get("url") if c and c.json else None
        if field in ("mutex", "analysis_config_mutex"):
            return c.json.get("mutex") if c and c.json else None
        # Both schemes want lowercase hex with a 0x prefix (confirmed for the
        # day-2 standalone fields and specified for the dNN `_hex` fields).
        if field in ("cpp_config_crc32", "config_crc32", "crc32",
                     "config_crc32_hex", "analysis_config_crc32_hex", "crc32_hex"):
            return f"0x{c.crc32:08x}" if c else None
        if field in ("cpp_xor_key", "xor_key", "xor_key_hex", "analysis_xor_key_hex"):
            return f"0x{c.xor_key:02x}" if c else None
        if field in ("hcfg_version", "analysis_hcfg_version"):
            return str(c.version) if c else None
        if field in ("metadata_version", "analysis_metadata_version"):
            return self._dotnet_metadata_version()
        if field in ("hcfg_offset", "analysis_hcfg_offset"):
            if not c:
                return None
            return str(c.file_offset if c.file_offset is not None else c.b64_offset)
        if field in ("has_hcfg_section", "analysis_has_hcfg_section"):
            return "true" if self._has_hcfg_section() else "false"
        if field in ("compression_methods", "analysis_compression_methods"):
            return _cjson(jar_compression_methods(self.path))
        # --- extra HCFG json keys (later contracts) ---
        if field.endswith("config_host_model"):
            return c.json.get("host_model") if c and c.json else None
        if field.endswith("config_ipv4"):
            return c.json.get("ipv4") if c and c.json else None
        # --- ELF symbol-name counts / predicates ---
        if field.endswith("crystal_symbol_count"):
            return str(sum(1 for n in self._symnames()
                           if re.search(r"Crystal|crystal|__crystal|GC_", n)))
        if field.endswith("d_symbol_count"):
            return str(sum(1 for n in self._symnames() if re.search(r"^_D|\b_d_", n)))
        if field.endswith("handler_symbol_count"):
            return str(sum(1 for n in self._symnames()
                           if re.search(r"event_(success|decoy|failure)", n)))
        if field.endswith("symbol_count"):
            return str(len(self._symnames()))
        if field.endswith("section_count"):
            return str(e.e_shnum) if e else "none"
        if field.endswith("handler_symbols_sha256"):
            ns = sorted(n for n in self._symnames()
                        if re.search(r"event_(success|decoy|failure)", n))
            return hashlib.sha256("\n".join(ns).encode()).hexdigest()
        if field.endswith("has_go_runtime"):
            return "true" if b"runtime.main" in self.data else "false"
        if field.endswith("has_rust_mangled_symbol"):
            return "true" if any(n.startswith(("_ZN", "_R")) for n in self._symnames()) else "false"
        if field.endswith("has_nim_runtime"):
            return "true" if (b"NimString" in self.data or b"NimMain" in self.data) else "false"
        if field.endswith("has_fpc_runtime"):
            return "true" if (b"FPC" in self.data or any("FPC_" in n for n in self._symnames())) else "false"
        if field.endswith("has_gnat_runtime"):
            return "true" if (b"__gnat" in self.data or any("gnat" in n for n in self._symnames())) else "false"
        if field.endswith("has_coroutine_runtime"):
            return "true" if self._jar_has("kotlin/coroutines/Continuation.class") else "false"
        if field.endswith("has_decoy_branch"):
            return "true" if (b"decoy" in self.data or "decoy".encode("utf-16le") in self.data) else "false"
        if field.endswith("cli_runtime"):
            return self._cli_runtime()
        if field.endswith("typeinfo_symbol"):
            return self._first_symbol_matching(r"ZTI.*DiscoveryEngine")
        if field.endswith("conditional_branch_opcode_count"):
            return str(self._branch_opcode_count())
        if field.endswith("hcfg_storage"):
            return self._hcfg_storage()
        # --- hashes handled at a higher level (needs file selection) ---
        return None

    def _is_dotnet(self):
        return self.kind == "pe" and b"BSJB" in self.data

    def _format(self, compound=False):
        if self.kind == "elf":
            return self.elf.elf_class()           # ELF64 / ELF32
        if self.kind == "pe":
            pe = format_label(self.path)          # PE32 / PE32+
            if compound and self._is_dotnet():
                return f"{pe}/.NET"               # managed: container + runtime
            return pe
        if self.kind == "zip":
            return "JAR"
        return format_label(self.path)

    # --- helpers for later-day field computations -------------------------
    def _symnames(self):
        if self._symn is None:
            self._symn = ([s["name"] for s in self.elf.symbols() if s["name"]]
                          if self.kind == "elf" else [])
        return self._symn

    def _jar_has(self, entry):
        if self.kind != "zip":
            return False
        try:
            return entry in zipfile.ZipFile(self.path).namelist()
        except Exception:
            return False

    def _first_symbol_matching(self, pat):
        rx = re.compile(pat)
        if self.kind == "pe":
            for n in self._coff_symbols():   # raw COFF table order, prefixes kept
                if rx.search(n):
                    return n
            return "none"
        for n in self._symnames():           # ELF .symtab order
            if rx.search(n):
                return n
        return "none"

    def _coff_symbols(self):
        """COFF symbol names in raw table order (long names resolved via the
        string table; section prefixes like .rdata$ kept; empty names dropped)."""
        d = self.data
        try:
            pe = struct.unpack_from("<I", d, 0x3c)[0]
            sym_ptr = struct.unpack_from("<I", d, pe + 4 + 8)[0]
            nsym = struct.unpack_from("<I", d, pe + 4 + 12)[0]
        except Exception:
            return []
        if not sym_ptr or not nsym:
            return []
        strtab = sym_ptr + nsym * 18
        out = []
        i = 0
        while i < nsym:
            off = sym_ptr + i * 18
            raw = d[off:off + 8]
            if raw[:4] == b"\x00\x00\x00\x00":
                so = struct.unpack_from("<I", d, off + 4)[0]
                end = d.index(b"\x00", strtab + so)
                name = d[strtab + so:end].decode("latin1", "replace")
            else:
                name = raw.rstrip(b"\x00").decode("latin1", "replace")
            if name:
                out.append(name)
            naux = d[off + 17]
            i += 1 + naux
        return out

    def _text_bytes(self):
        if self.kind == "elf" and self.elf:
            t = next((s for s in self.elf.sections if s["name"] == ".text"), None)
            if t:
                return self.data[t["offset"]:t["offset"] + t["size"]]
        return b""

    def _branch_opcode_count(self):
        t = self._text_bytes()
        n = 0
        for i, b in enumerate(t):
            if 0x70 <= b <= 0x7f:
                n += 1
            if b == 0x0f and i + 1 < len(t) and 0x80 <= t[i + 1] <= 0x8f:
                n += 1
        return n

    def _cli_runtime(self):
        """.NET CLI header runtime major.minor (from the COM descriptor dir)."""
        try:
            d = self.data
            pe = struct.unpack_from("<I", d, 0x3c)[0]
            opt = pe + 24
            magic = struct.unpack_from("<H", d, opt)[0]
            # data directory 14 = CLR runtime header; dir array starts after opt header
            dir_off = opt + (112 if magic == 0x20b else 96) + 14 * 8
            rva = struct.unpack_from("<I", d, dir_off)[0]
            foff = self._pe_rva_to_off(rva)
            maj = struct.unpack_from("<H", d, foff + 4)[0]
            minr = struct.unpack_from("<H", d, foff + 6)[0]
            return f"{maj}.{minr}"
        except Exception:
            return "none"

    def _pe_rva_to_off(self, rva):
        d = self.data
        pe = struct.unpack_from("<I", d, 0x3c)[0]
        nsec = struct.unpack_from("<H", d, pe + 6)[0]
        optsz = struct.unpack_from("<H", d, pe + 20)[0]
        sec = pe + 24 + optsz
        for i in range(nsec):
            b = sec + i * 40
            va = struct.unpack_from("<I", d, b + 12)[0]
            vs = struct.unpack_from("<I", d, b + 8)[0]
            raw = struct.unpack_from("<I", d, b + 20)[0]
            if va <= rva < va + max(vs, 1):
                return raw + (rva - va)
        return rva

    def _hcfg_storage(self):
        c = self.cfg
        if not c:
            return "none"
        if c.carrier == "base64":
            return "base64"
        if self.kind == "wasm":
            return "wasm_data_segment"
        if self.kind == "elf" and self.elf and c.file_offset is not None:
            for s in self.elf.sections:
                if s["offset"] and s["offset"] <= c.file_offset < s["offset"] + s["size"]:
                    return "raw_hcfg_section" if s["name"] == ".hcfg" else "raw_const_array"
        return "raw"

    def _pe_section_names(self):
        d = self.data
        pe = struct.unpack_from("<I", d, 0x3c)[0]
        nsec = struct.unpack_from("<H", d, pe + 6)[0]
        optsz = struct.unpack_from("<H", d, pe + 20)[0]
        secoff = pe + 24 + optsz
        out = []
        for i in range(nsec):
            name = d[secoff + i * 40:secoff + i * 40 + 8].rstrip(b"\x00")
            out.append(name.decode("latin1", "replace"))
        return out

    def _has_hcfg_section(self):
        if self.kind == "elf" and self.elf:
            return any(s["name"] == ".hcfg" for s in self.elf.sections)
        if self.kind == "pe":
            try:
                return ".hcfg" in self._pe_section_names()
            except Exception:
                return False
        return False

    def _dotnet_metadata_version(self):
        """Extract the CLI metadata version string (e.g. 'v4.0.30319') from a
        .NET PE by locating the metadata root signature 0x424A5342 ('BSJB')."""
        i = self.data.find(b"BSJB")
        if i < 0:
            return "none"
        # BSJB(4) major(2) minor(2) reserved(4) version_len(4) version...
        vlen = struct.unpack_from("<I", self.data, i + 12)[0]
        ver = self.data[i + 16:i + 16 + vlen].split(b"\x00")[0]
        return ver.decode("latin1") or "none"

    def _pe_machine(self):
        mz = struct.unpack_from("<I", self.data, 0x3c)[0]
        m = struct.unpack_from("<H", self.data, mz + 4)[0]
        return {0x8664: "x86-64", 0x14c: "i386", 0xaa64: "aarch64"}.get(m, f"0x{m:x}")


# --------------------------------------------------------------------------
# answer_id routing
# --------------------------------------------------------------------------
def split_id(aid):
    """Return (set_idx, token, field).

    set_idx is 0-based delivery index from a ``setN.`` prefix (None if absent).
    token groups slotN / dNN / c / cpp; field is the rest.
    """
    set_idx = None
    m = re.match(r"set(\d+)\.(.+)", aid)
    if m:
        set_idx = int(m.group(1)) - 1
        aid = m.group(2)
    for rx in (r"(slot\d+)_(.+)", r"(d\d+)_(.+)", r"(c|cpp)_(.+)"):
        m = re.match(rx, aid)
        if m:
            return set_idx, m.group(1), m.group(2)
    return set_idx, None, aid


def _find(files, *patterns):
    for nm in sorted(files):
        if any(re.search(p, nm, re.I) for p in patterns):
            return files[nm]
    return None


def route_file(token, field, files):
    """Map an answer id (token+field) to the artifact file it concerns."""
    names = sorted(files)
    # slot scheme
    m = re.match(r"slot(\d+)", token or "")
    if m:
        return _find(files, rf"slot[-_]?{m.group(1)}[-_.]")
    # cumulative dNN scheme
    m = re.match(r"d(\d+)", token or "")
    if m:
        dd = int(m.group(1))
        return _find(files, rf"d0*{dd}[-_.](?!.*runtimeconfig)", rf"day0*{dd}[-_.]")
    # standalone day-2 scheme: explicit c_/cpp_ tokens
    if token == "c":
        return _find(files, r"(^|[^p])d(ay)?0*1[-_.]", r"-c\.elf$", r"\bc\.elf$") or \
               _find(files, r"day0*1", r"d0*1[-_.]")
    if token == "cpp":
        return _find(files, r"cpp")
    # bare fields: config / C++ fields belong to the primary specimen
    cpp_fields = {"campaign", "domain", "url", "mutex", "has_cpp_vtable",
                  "has_cpp_typeinfo", "mangled_score_symbol", "vtable_symbol",
                  "cpp_xor_key", "cpp_config_crc32", "cpp_format", "cpp_sha256"}
    if field in cpp_fields:
        return _find(files, r"cpp") or _find(files, r"day0*2", r"d0*2[-_.]")
    # otherwise the lone / first non-aux file
    non_aux = [files[n] for n in names if not n.endswith(".runtimeconfig.json")]
    return non_aux[0] if non_aux else (files[names[0]] if names else None)


def solve(answer_ids, files_or_sets, questions=None):
    """Compute answers for every id. Returns (answers, notes).

    ``files_or_sets`` is either a {name: path} dict (single delivery) or a
    {set_idx: {name: path}} dict when answer ids carry ``setN.`` prefixes.
    """
    specimens = {}
    def spec(path):
        if path not in specimens:
            specimens[path] = Specimen(path)
        return specimens[path]

    def files_for(set_idx):
        if set_idx is None:
            return files_or_sets if not _is_setmap(files_or_sets) else files_or_sets.get(0, {})
        return files_or_sets.get(set_idx, {})

    qmap = {q["id"]: q for q in (questions or [])}
    answers, notes = {}, {}
    for aid in answer_ids:
        set_idx, token, field = split_id(aid)
        files = files_for(set_idx)
        q = qmap.get(aid, {})
        qtext = q.get("question", "")
        af = q.get("answer_format")
        try:
            # day-level fields (operate over all members / the zip itself)
            dl = _day_level(aid, token, field, files, qtext, af)
            if dl is not _NOFIELD:
                answers[aid] = dl
                continue
            if field in ("sha256", "c_sha256", "cpp_sha256") or \
               re.match(r"artifact_sha256(_\d+)?$", field):
                path = _sha_target(aid, token, field, files)
                answers[aid] = sha256_file(path) if path else None
                continue
            # multi-file days: pick the sub-specimen by the question's basename
            # hint (or a distinguishing basename token), strip adjectives for matching.
            path, nfield = _subspec(token, field, files, qtext)
            if path is None:
                path = route_file(token, field, files)
                nfield = field
            answers[aid] = spec(path).answer(nfield, af) if path else None
        except Exception as ex:  # noqa: BLE001
            answers[aid] = None
            notes[aid] = f"ERR {type(ex).__name__}: {ex}"
    return answers, notes


def _day_files(token, files):
    m = re.match(r"d(\d+)", token or "")
    if not m:
        return []
    dd = int(m.group(1))
    return [(nm, files[nm]) for nm in files   # dict preserves central-directory order
            if re.search(rf"d0*{dd}[-_.]", nm) and not nm.endswith(".runtimeconfig.json")]


_SUBWORDS = ("unoptimized", "optimized", "compact", "direct", "stripped",
             "symbolized", "corrected", "vulnerable", "loader", "plugin",
             "primary", "gcc", "tcc", "family", "false", "friend")


def _strip_subwords(field):
    nf = field
    for w in _SUBWORDS:
        nf = re.sub(rf"(^|_){w}(_|$)", r"\1", nf)
    return nf.strip("_")


def _subspec(token, field, files, qtext=""):
    """Choose the member this field concerns and return (path, normalized_field).

    Uses the question's explicit basename hint first ("basename ends X" /
    "member N"), then a distinguishing basename token appearing in the field.
    Returns (None, field) when no day files match (let route_file handle it)."""
    df = _day_files(token, files)
    if not df:
        return None, field

    def toks(x):
        base = re.sub(r"\.(wasm|elf|exe|dll|jar|so|cmxs|bin|njs|neko|n|class|o)$", "",
                      os.path.basename(x).lower())
        return set(t for t in re.split(r"[^a-z0-9]+", base) if t)
    sets = [toks(nm) for nm, _ in df]
    common = set.intersection(*sets) if sets else set()

    def norm(path):
        """Strip the chosen file's distinguishing basename tokens + adjectives."""
        nf = _strip_subwords(field)
        for t in sorted((toks(path) - common), key=len, reverse=True):
            if len(t) >= 1:
                nf = re.sub(rf"(^|_){re.escape(t)}(_|$)", r"\1", nf)
        return nf.strip("_")

    if len(df) == 1:
        return df[0][1], norm(df[0][0])
    m = re.search(r"basename ends (?:with |in )?(\S+)", qtext)
    if m:
        suf = m.group(1).strip(". ").lower()
        for nm, p in df:
            if nm.lower().endswith(suf):
                return p, norm(nm)
    m = re.search(r"\bmember (\d+)\b", qtext)
    if m:
        idx = int(m.group(1)) - 1
        if 0 <= idx < len(df):
            return df[idx][1], norm(df[idx][0])
    # a verbatim filename tail named in the question text (longest wins), e.g.
    # "plugin.cmxs" — robust when the text also mentions the member NOT to use
    ql = (qtext or "").lower()
    cands = []
    for nm, p in df:
        b = os.path.basename(nm).lower()
        tail = re.sub(r"^d\d+--(sample[-_]?)?", "", b)
        for s in (b, tail):
            if s and s in ql:
                cands.append((len(s), p, nm))
    if cands:
        cands.sort(key=lambda x: x[0], reverse=True)
        _, p, nm = cands[0]
        return p, norm(nm)
    fwords = set(t for t in re.split(r"[^a-z0-9]+", field.lower()) if t)
    for (nm, p), s in zip(df, sets):
        if (s - common) & fwords:
            return p, norm(nm)
    return df[0][1], norm(df[0][0])


_NOFIELD = object()


def _day_level(aid, token, field, files, qtext, af):
    """Fields computed over ALL day members / the zip, not one file.
    Returns _NOFIELD when the field is not day-level."""
    import dayextra
    df = _day_files(token, files)
    jar = next((p for _, p in df if p.endswith(".jar")), None)

    if field.endswith("structural_artifact_count"):
        return str(len(df))
    if field.endswith("structural_ordered_set_sha256"):
        digs = [hashlib.sha256(open(p, "rb").read()).hexdigest() for _, p in df]
        return hashlib.sha256(":".join(digs).encode()).hexdigest()
    if field.endswith("class_count"):
        total = 0
        for _, p in df:
            try:
                total += sum(1 for n in zipfile.ZipFile(p).namelist() if n.endswith(".class"))
            except Exception:
                pass
        return str(total)
    # --- crash triage (d26) --- (before Java: 'match_methods' also ends in methods)
    if jar and field.endswith("crash_fault_method"):
        t = dayextra.crash_trace(jar)
        return t["frames"][0] if t and t.get("frames") else "none"
    if jar and field.endswith("crash_frames_match_methods"):
        t = dayextra.crash_trace(jar)
        ci = dayextra.jar_primary_classinfo(jar)
        if not t or not ci:
            return "false"
        mset = set(ci["methods"])
        return "true" if all(f in mset for f in t.get("frames", [])) else "false"
    # --- Java classfile fields ---
    if jar and (field.endswith(("_methods", "_access_flags", "_class_name",
                                 "_method_count", "_method_names_sha256", "methods"))
                and "match" not in field and "compression" not in field):
        try:
            ci = dayextra.jar_primary_classinfo(jar)
        except Exception:
            return _NOFIELD
        if ci is None:
            return _NOFIELD
        if field.endswith("access_flags"):
            return str(ci["access_flags"])
        if field.endswith("class_name"):
            return ci["this_class"]
        if field.endswith("method_count"):
            return str(len(ci["methods"]))
        if field.endswith("method_names_sha256"):
            names = sorted(set(ci["methods"]))
            return hashlib.sha256("\n".join(names).encode()).hexdigest()
        if field.endswith("methods"):
            return _cjson(ci["methods"])
    # --- packed/resource overlays (d19 PK19, d20 RS20) ---
    overlayish = ("overlay" in field or field.endswith("hcfg_resource_size")
                  or field.endswith(("packing_key_1_hex", "packing_key_2_hex"))
                  or field.endswith(("config_campaign", "config_domain", "config_url",
                                      "config_mutex", "config_crc32_hex", "hcfg_version")))
    if df and overlayish:
        data0 = open(df[0][1], "rb").read()
        if b"PK19" in data0:
            pk = dayextra.pk19(df[0][1])
            if pk:
                if field.endswith("overlay_offset"): return str(pk["offset"])
                if field.endswith("overlay_size"): return str(pk["size"])
                if field.endswith("packing_key_1_hex"): return f"0x{pk['k1']:02x}"
                if field.endswith("packing_key_2_hex"): return f"0x{pk['k2']:02x}"
                cc = pk["config"]
                if cc:
                    if field.endswith("config_campaign"): return cc.json.get("campaign")
                    if field.endswith("config_domain"): return cc.json.get("domain")
                    if field.endswith("config_url"): return cc.json.get("url")
                    if field.endswith("config_mutex"): return cc.json.get("mutex")
                    if field.endswith("config_crc32_hex"): return f"0x{cc.crc32:08x}"
                    if field.endswith("hcfg_version"): return str(cc.version)
        elif b"RS20" in data0 and ("overlay" in field or field.endswith("hcfg_resource_size")):
            rs = dayextra.rs20(df[0][1])
            if rs:
                if field.endswith("hcfg_resource_size"): return str(rs["resource_size"])
                if field.endswith("overlay_offset"): return str(rs["offset"])
                if field.endswith("overlay_size"): return str(rs["size"])
    # --- bare config on a multi-member day: use the value common to the
    # family members (e.g. d28 family-a == family-b, ignore the decoy) ---
    m = re.match(r"analysis_config_(campaign|domain|url|mutex|crc32_hex)$", field)
    if m and len(df) > 1:
        import hcfg as _h
        from collections import Counter
        key = m.group(1)
        vals = []
        for _, p in df:
            cc = _h.find_config(p)
            if cc and cc.json:
                vals.append(f"0x{cc.crc32:08x}" if key == "crc32_hex" else cc.json.get(key))
        vals = [v for v in vals if v is not None]
        if vals:
            return Counter(vals).most_common(1)[0][0]
    return _NOFIELD


def _is_setmap(d):
    return isinstance(d, dict) and all(isinstance(k, int) for k in d) and d


def _sha_target(aid, token, field, files):
    # dNN_artifact_sha256_K -> the K-th artifact file for day NN (sorted by name)
    m = re.match(r"d(\d+)", token or "")
    if m:
        dd = int(m.group(1))
        # all members for this day, in central-directory (dict/namelist) order; no sort
        cands = [nm for nm in files if re.search(rf"d0*{dd}[-_.]", nm)]
        km = re.search(r"_(\d+)$", field)
        idx = (int(km.group(1)) - 1) if km else 0
        if 0 <= idx < len(cands):
            return files[cands[idx]]
        return files[cands[0]] if cands else None
    # standalone day-2: route by the c_/cpp_ token
    if token in ("c", "cpp"):
        return route_file(token, field, files)
    # slot scheme sha256 (if ever asked)
    if (token or "").startswith("slot"):
        return route_file(token, field, files)
    sf = sorted(files.items())
    return sf[0][1] if sf else None


# --------------------------------------------------------------------------
# main loop
# --------------------------------------------------------------------------
def run_attempt(challenge, *, retry=False, run_for_time=False, dry_run=False,
                only=None, override=None, attempts=1, work=None, practice=False):
    """Open an attempt, solve it, and (unless dry_run) submit.

    Returns a summary dict: {result, mode, nq, solved, missing, elapsed, flag,
    work, sets}. Mastery (multi-set) uses the parallel incremental pipeline and
    honours ``attempts`` (retry the whole bundle until CORRECT); other modes do
    a single solve+submit. This is the reusable entry point used by the
    per-day orchestrator (solve_day.py).
    """
    override = override or []
    t0 = time.time()
    base_work = work or os.path.join("/tmp", f"as_{int(t0)}_{os.getpid()}")
    os.makedirs(base_work, exist_ok=True)

    def open_attempt():
        if practice:
            payload = {"op": "practice", "challenge": challenge}
        else:
            payload = {"op": "retry", "challenge": challenge} if retry else {"challenge": challenge}
        if run_for_time:
            payload["run_for_time"] = True
        resp = json.loads(gm._post(payload).decode())
        # Freshly-released challenges have no prior attempt, so `retry` fails with
        # start_required — open the first (fresh, scored) attempt with a plain start.
        if retry and resp.get("error") == "start_required":
            sp = {"challenge": challenge}
            if run_for_time:
                sp["run_for_time"] = True
            resp = json.loads(gm._post(sp).decode())
        return resp

    start = open_attempt()
    answer_ids = start.get("answer_ids") or [q["id"] for q in start.get("questions", [])]
    mode = start.get("mode")
    if not answer_ids:
        print(json.dumps({"stage": "start", "resp": start}, indent=2)[:2000])
        return {"result": start.get("result"), "mode": mode, "nq": 0}
    print(f"[+] {challenge.split('/')[-1]}: mode={mode} nq={len(answer_ids)} "
          f"deadline={start.get('deadline')} rem={start.get('unique_attempts_remaining')}")

    def set_ids_of(aids):
        return sorted({int(m.group(1)) - 1 for aid in aids
                       for m in [re.match(r"set(\d+)\.", aid)] if m})

    set_ids = set_ids_of(answer_ids)

    # --- mastery (multi-set, parallel, incremental, retry-until-CORRECT) -----
    if set_ids and not dry_run and not only and not override:
        for n in range(1, max(1, attempts) + 1):
            if n > 1:
                t0 = time.time()
                start = open_attempt()
                answer_ids = start.get("answer_ids") or []
                set_ids = set_ids_of(answer_ids)
                print(f"[+] attempt #{n} rem={start.get('unique_attempts_remaining')}")
            w = os.path.join(base_work, f"try{n}")
            os.makedirs(w, exist_ok=True)
            res = _run_incremental(challenge, start, answer_ids, set_ids, w, t0)
            if res in ("CORRECT", "already_solved"):
                print(f"[✓] solved on attempt #{n}")
                return {"result": res, "mode": mode, "nq": len(answer_ids),
                        "sets": len(set_ids), "elapsed": time.time() - t0, "work": w}
            if n < attempts:
                print(f"[!] attempt #{n} => {res}; retrying")
        return {"result": res, "mode": mode, "nq": len(answer_ids),
                "sets": len(set_ids), "elapsed": time.time() - t0, "work": base_work}

    # --- single delivery (single_solve / time_trial / cumulative) ------------
    if set_ids:
        files = _download_sets(challenge, set_ids, base_work)
        print(f"[+] {len(set_ids)} sets ({time.time()-t0:.2f}s)")
    else:
        files = extract(download_artifact(challenge, base_work), base_work)
        print(f"[+] files: {sorted(files)} ({time.time()-t0:.2f}s)")

    answers, notes = solve(answer_ids, files, start.get("questions"))
    overrides = dict(ov.partition("=")[::2] for ov in override)
    if overrides:
        for aid in list(answers):
            _, _, field = split_id(aid)
            if field in overrides:
                answers[aid] = overrides[field]
    if only:
        rx = re.compile(only)
        answers = {k: v for k, v in answers.items() if rx.search(k)}
    missing = [k for k, v in answers.items() if v is None]
    print(f"[+] solved {len(answers)-len(missing)}/{len(answers)} in {time.time()-t0:.2f}s")
    if missing:
        print(f"[!] NO ANSWER for: {missing[:20]}{' …' if len(missing) > 20 else ''}")
    if notes:
        print(f"[!] notes: {json.dumps(notes, indent=0)[:1000]}")
    with open(os.path.join(base_work, "answers.json"), "w") as fh:
        json.dump(answers, fh, indent=1)

    summary = {"mode": mode, "nq": len(answer_ids), "solved": len(answers) - len(missing),
               "missing": missing, "elapsed": time.time() - t0, "work": base_work}
    if dry_run:
        summary["result"] = "dry-run"
        return summary

    payload_ans = {k: v for k, v in answers.items() if v is not None}
    res = json.loads(gm._post({"challenge": challenge, "answers": payload_ans}).decode())
    summary["result"] = res.get("result")
    summary["flag"] = res.get("flag")
    summary["remaining"] = res.get("remaining")
    print(f"[=] result in {time.time()-t0:.2f}s: "
          f"{json.dumps({k: res.get(k) for k in ('result','remaining','flag') if k in res})}")
    with open(os.path.join(base_work, "result.json"), "w") as fh:
        json.dump(res, fh, indent=1)
    return summary


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("challenge")
    ap.add_argument("--retry", action="store_true", help="spend a fresh variant")
    ap.add_argument("--start", action="store_true", help="reconnect to current attempt")
    ap.add_argument("--run-for-time", action="store_true")
    ap.add_argument("--dry-run", action="store_true", help="don't submit")
    ap.add_argument("--work", default=None)
    ap.add_argument("--only", default=None, help="regex: submit only matching answer_ids")
    ap.add_argument("--override", action="append", default=[],
                    help="field=value: force a field's answer across all slots/days")
    ap.add_argument("--attempts", type=int, default=1,
                    help="for mastery: retry the whole bundle up to N times until CORRECT")
    ap.add_argument("--practice", action="store_true",
                    help="open an untimed practice attempt (after fresh variants are spent)")
    a = ap.parse_args()
    run_attempt(a.challenge, retry=a.retry, run_for_time=a.run_for_time,
                dry_run=a.dry_run, only=a.only, override=a.override,
                attempts=a.attempts, work=a.work, practice=a.practice)


if __name__ == "__main__":
    main()
