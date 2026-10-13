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


# --------------------------------------------------------------------------
# artifact download + extraction
# --------------------------------------------------------------------------
def download_artifact(challenge, work):
    raw = gm._get({"op": "artifact", "challenge": challenge})
    path = os.path.join(work, "artifact.zip")
    with open(path, "wb") as fh:
        fh.write(raw)
    return path


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

    def _kind(self):
        if self.data[:4] == b"\x7fELF":
            return "elf"
        if self.data[:2] == b"MZ":
            return "pe"
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
    def answer(self, field):
        e = self.elf
        c = self.cfg
        # --- container / arch ---
        if field in ("elf_class", "analysis_elf_class"):
            return e.elf_class()
        if field in ("endianness", "analysis_endianness"):
            return e.endianness()
        if field in ("machine", "analysis_machine"):
            return e.machine_short() if e else self._pe_machine()
        if field in ("architecture", "analysis_architecture"):
            return e.machine_short() if e else self._pe_machine()
        if field in ("elf_type", "analysis_elf_type"):
            return e.elf_type()
        if field in ("format", "analysis_format", "cpp_format"):
            return self._format()
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
            return json.dumps([s for s in e.section_names()])
        if field in ("symbols", "analysis_symbols"):
            return json.dumps(sorted({s["name"] for s in e.symbols() if s["name"]}))
        if field in ("disassembly", "analysis_disassembly"):
            return str(e.recover_constant())
        # --- C++ ---
        if field in ("has_cpp_vtable", "analysis_has_cpp_vtable"):
            return "true" if self.cpp["has_cpp_vtable"] else "false"
        if field in ("has_cpp_typeinfo", "analysis_has_cpp_typeinfo"):
            return "true" if self.cpp["has_cpp_typeinfo"] else "false"
        if field in ("vtable_symbol", "analysis_vtable_symbol"):
            return self.cpp["vtable_symbol"]
        if field in ("mangled_score_symbol", "analysis_mangled_score_symbol"):
            return self.cpp["score_symbol"]
        # --- config (HCFG) ---
        if field in ("campaign", "analysis_config_campaign"):
            return c.json.get("campaign") if c and c.json else None
        if field in ("domain", "analysis_config_domain"):
            return c.json.get("domain") if c and c.json else None
        if field in ("url", "analysis_config_url"):
            return c.json.get("url") if c and c.json else None
        if field in ("mutex", "analysis_config_mutex"):
            return c.json.get("mutex") if c and c.json else None
        if field in ("cpp_config_crc32", "config_crc32_hex", "analysis_config_crc32_hex",
                     "crc32_hex"):
            return f"{c.crc32:08x}" if c else None
        if field in ("cpp_xor_key", "xor_key_hex", "analysis_xor_key_hex"):
            return f"{c.xor_key:02x}" if c else None
        if field in ("hcfg_version", "analysis_hcfg_version", "metadata_version",
                     "analysis_metadata_version"):
            return str(c.version) if c else None
        if field in ("hcfg_offset", "analysis_hcfg_offset"):
            if not c:
                return None
            return str(c.file_offset if c.file_offset is not None else c.b64_offset)
        if field in ("has_hcfg_section", "analysis_has_hcfg_section"):
            if e:
                return "true" if any(s["name"] == ".hcfg" for s in e.sections) else "false"
            return "false"
        if field == "compression_methods" or field == "analysis_compression_methods":
            return json.dumps(jar_compression_methods(self.path))
        # --- hashes handled at a higher level (needs file selection) ---
        return None

    def _format(self):
        if self.kind == "elf":
            return self.elf.elf_class()           # ELF64 / ELF32
        if self.kind == "pe":
            return format_label(self.path)        # PE32 / PE32+
        if self.kind == "zip":
            return "JAR"
        return format_label(self.path)

    def _pe_machine(self):
        mz = struct.unpack_from("<I", self.data, 0x3c)[0]
        m = struct.unpack_from("<H", self.data, mz + 4)[0]
        return {0x8664: "x86-64", 0x14c: "i386", 0xaa64: "aarch64"}.get(m, f"0x{m:x}")


# --------------------------------------------------------------------------
# answer_id routing
# --------------------------------------------------------------------------
def pick_file(files, token):
    """Map a slot/day token to an artifact file path.
    token like 'slot0' / 'slot-0' / 'd03' / 'c' / 'cpp'."""
    names = list(files)
    m = re.match(r"slot[-_]?(\d+)", token)
    if m:
        n = m.group(1)
        for nm in names:
            if re.search(rf"slot[-_]?{n}\b|slot[-_]?{n}\.", nm):
                return files[nm]
    m = re.match(r"d(\d+)", token)
    if m:
        dd = int(m.group(1))
        cands = [nm for nm in names if re.search(rf"d0*{dd}[-_.]", nm)
                 and not nm.endswith(".runtimeconfig.json")]
        if cands:
            return files[sorted(cands)[0]]
    # day2 standalone: 'c' -> day01 elf, 'cpp' -> day02 elf
    if token == "c":
        for nm in sorted(names):
            if "day01" in nm or "d01" in nm:
                return files[nm]
    if token == "cpp":
        for nm in sorted(names):
            if "day02" in nm or "d02" in nm:
                return files[nm]
    return None


def split_id(aid):
    """Return (token, field). token groups slotN / dNN; field is the rest."""
    m = re.match(r"(slot\d+)_(.+)", aid)
    if m:
        return m.group(1), m.group(2)
    m = re.match(r"(d\d+)_(.+)", aid)
    if m:
        return m.group(1), m.group(2)
    m = re.match(r"(c|cpp)_(.+)", aid)
    if m:
        return m.group(1), m.group(2)
    return None, aid


def solve(answer_ids, files, questions=None):
    """Compute answers for every id. Returns (answers, notes)."""
    qmap = {q["id"]: q for q in (questions or [])}
    specimens = {}
    def spec(path):
        if path not in specimens:
            specimens[path] = Specimen(path)
        return specimens[path]

    # order files for day/standalone sha256 and 'artifact_sha256_K'
    sorted_files = sorted(files.items())
    answers, notes = {}, {}
    for aid in answer_ids:
        token, field = split_id(aid)
        try:
            # sha256 fields
            if field in ("sha256", "c_sha256", "cpp_sha256") or re.match(r"artifact_sha256_\d+", field) or field == "artifact_sha256":
                path = _sha_target(aid, token, field, files)
                answers[aid] = sha256_file(path) if path else None
                continue
            path = pick_file(files, token) if token else _standalone_file(field, files)
            if path is None:
                # single-file artifact fallback
                path = sorted_files[0][1] if sorted_files else None
            answers[aid] = spec(path).answer(field) if path else None
        except Exception as ex:  # noqa: BLE001
            answers[aid] = None
            notes[aid] = f"ERR {type(ex).__name__}: {ex}"
    return answers, notes


def _sha_target(aid, token, field, files):
    # dNN_artifact_sha256_K -> the K-th artifact file for day NN
    m = re.match(r"d(\d+)", token or "")
    if m:
        dd = int(m.group(1))
        cands = sorted(nm for nm in files if re.search(rf"d0*{dd}[-_.]", nm))
        km = re.search(r"_(\d+)$", field)
        idx = (int(km.group(1)) - 1) if km else 0
        if 0 <= idx < len(cands):
            return files[cands[idx]]
        return files[cands[0]] if cands else None
    if field == "c_sha256":
        return _standalone_file("c", files)
    if field == "cpp_sha256":
        return _standalone_file("cpp", files)
    # generic single file
    sf = sorted(files.items())
    return sf[0][1] if sf else None


def _standalone_file(token, files):
    return pick_file(files, token)


# --------------------------------------------------------------------------
# main loop
# --------------------------------------------------------------------------
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
    a = ap.parse_args()

    t0 = time.time()
    work = a.work or os.path.join("/tmp", f"as_{int(t0)}_{os.getpid()}")
    os.makedirs(work, exist_ok=True)

    # 1. open attempt
    payload = {"challenge": a.challenge}
    if a.retry:
        payload = {"op": "retry", "challenge": a.challenge}
    if a.run_for_time:
        payload["run_for_time"] = True
    start = json.loads(gm._post(payload).decode())
    answer_ids = start.get("answer_ids") or [q["id"] for q in start.get("questions", [])]
    deadline = start.get("deadline")
    if not answer_ids:
        print(json.dumps({"stage": "start", "resp": start}, indent=2)[:2000])
        return
    print(f"[+] attempt {start.get('attempt_id')} mode={start.get('mode')} "
          f"nq={len(answer_ids)} deadline={deadline} rem={start.get('unique_attempts_remaining')}")

    # 2+3 download & extract
    zp = download_artifact(a.challenge, work)
    files = extract(zp, work)
    print(f"[+] artifact files: {sorted(files)} ({time.time()-t0:.2f}s)")

    # 4. solve
    answers, notes = solve(answer_ids, files, start.get("questions"))
    # apply field overrides (force a given field's value across every slot/day)
    overrides = {}
    for ov in a.override:
        k, _, v = ov.partition("=")
        overrides[k] = v
    if overrides:
        for aid in list(answers):
            _, field = split_id(aid)
            if field in overrides:
                answers[aid] = overrides[field]
    # restrict submission set for probing
    if a.only:
        rx = re.compile(a.only)
        answers = {k: v for k, v in answers.items() if rx.search(k)}
    missing = [k for k, v in answers.items() if v is None]
    print(f"[+] solved {len(answers)-len(missing)}/{len(answers)} in {time.time()-t0:.2f}s")
    if missing:
        print(f"[!] NO ANSWER for: {missing}")
    if notes:
        print(f"[!] notes: {json.dumps(notes, indent=0)[:1000]}")

    with open(os.path.join(work, "answers.json"), "w") as fh:
        json.dump(answers, fh, indent=1)

    if a.dry_run:
        print(json.dumps(answers, indent=1))
        return

    # 5. submit
    res = json.loads(gm._post({"challenge": a.challenge, "answers": answers}).decode())
    elapsed = time.time() - t0
    summary = {k: res.get(k) for k in ("result", "remaining", "correct", "incorrect",
                                       "score", "message", "flag", "hall_of_fame_eligible")
               if k in res}
    print(f"[=] result in {elapsed:.2f}s: {json.dumps(summary)}")
    # persist full response for inspection
    with open(os.path.join(work, "result.json"), "w") as fh:
        json.dump(res, fh, indent=1)
    print(f"[i] work dir: {work}")


if __name__ == "__main__":
    main()
