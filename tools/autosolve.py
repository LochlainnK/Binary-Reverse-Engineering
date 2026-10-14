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
            return e.machine_short() if e else self._pe_machine()
        if field in ("architecture", "analysis_architecture"):
            return e.machine_short() if e else self._pe_machine()
        if field in ("elf_type", "analysis_elf_type"):
            return e.elf_type()
        if field in ("format", "analysis_format", "cpp_format"):
            # managed (.NET) specimens want a compound container+runtime token
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
            return _cjson([s["name"] for s in e.sections])
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

    qmap = {q["id"]: q.get("answer_format") for q in (questions or [])}
    answers, notes = {}, {}
    for aid in answer_ids:
        set_idx, token, field = split_id(aid)
        files = files_for(set_idx)
        try:
            if field in ("sha256", "c_sha256", "cpp_sha256") or \
               re.match(r"artifact_sha256(_\d+)?$", field):
                path = _sha_target(aid, token, field, files)
                answers[aid] = sha256_file(path) if path else None
                continue
            path = route_file(token, field, files)
            answers[aid] = spec(path).answer(field, qmap.get(aid)) if path else None
        except Exception as ex:  # noqa: BLE001
            answers[aid] = None
            notes[aid] = f"ERR {type(ex).__name__}: {ex}"
    return answers, notes


def _is_setmap(d):
    return isinstance(d, dict) and all(isinstance(k, int) for k in d) and d


def _sha_target(aid, token, field, files):
    # dNN_artifact_sha256_K -> the K-th artifact file for day NN (sorted by name)
    m = re.match(r"d(\d+)", token or "")
    if m:
        dd = int(m.group(1))
        cands = sorted(nm for nm in files if re.search(rf"d0*{dd}[-_.]", nm))
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
                only=None, override=None, attempts=1, work=None):
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
        payload = {"op": "retry", "challenge": challenge} if retry else {"challenge": challenge}
        if run_for_time:
            payload["run_for_time"] = True
        return json.loads(gm._post(payload).decode())

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
    a = ap.parse_args()
    run_attempt(a.challenge, retry=a.retry, run_for_time=a.run_for_time,
                dry_run=a.dry_run, only=a.only, override=a.override,
                attempts=a.attempts, work=a.work)


if __name__ == "__main__":
    main()
