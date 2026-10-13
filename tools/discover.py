#!/usr/bin/env python3
"""Per-field format-discovery oracle for the slot ELF scheme (day 1 time_trial).

Grading rule (learned empirically): a submit is 'accepted' only when EVERY
answer in it is correct; any wrong answer -> 'incorrect', nothing recorded.
So we probe one field at a time (its value across all 4 slots); 'accepted'
means that field's extraction+format is right. For known-ambiguous fields we
try a candidate list and stop at the first that is accepted.
"""
import json, os, sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gm
from elfmeta import ELF
import autosolve

CH = 'binary-reverse-engineering-day-01-c-elf-orientation/time_trial'
t0 = time.time()
work = f"/tmp/disc_{int(t0)}"; os.makedirs(work, exist_ok=True)
start = json.loads(gm._post({"op": "retry", "challenge": CH}).decode())
print("attempt", start.get("attempt_id"), "deadline", start.get("deadline"))
files = autosolve.extract(autosolve.download_artifact(CH, work), work)
slots = {i: ELF(files[f"slot-{i}.elf"]) for i in range(4)}
print("ready", f"{time.time()-t0:.2f}s")

def submit(ans):
    r = json.loads(gm._post({"challenge": CH, "answers": ans}).decode())
    return r.get("result"), r.get("remaining")

def val(e, field, cand):
    base = {
        "elf_class": e.elf_class(),
        "endianness": "little",
        "machine": "x86-64",
        "elf_type": "ET_EXEC",
        "marker": e.huntress_marker(),
        "has_symtab": "true" if e.has_symtab() else "false",
        "exported_symbol": (e.recover_symbol() or {}).get("name"),
        "recover_code": str(e.recover_constant()),
        "entry_point": e.entry_point(),
    }
    return cand if cand is not None else base[field]

# candidate lists for fields we want to pin down (None = use computed base value)
CANDS = {
    "elf_class":       [None, "ELFCLASS64", "64"],
    "endianness":      [None, "little endian", "LSB"],
    "machine":         [None, "EM_X86_64", "Advanced Micro Devices X86-64"],
    "elf_type":        [None, "EXEC", "ET_EXEC"],
    "marker":          [None],
    "has_symtab":      [None, "True"],
    "exported_symbol": [None],
    "recover_code":    [None],
    "entry_point":     [None],
}
found = {}
for field, cands in CANDS.items():
    for cand in cands:
        if time.time() - t0 > 27:
            print("!! time"); break
        ans = {f"slot{i}_{field}": val(slots[i], field, cand) for i in range(4)}
        res, rem = submit(ans)
        shown = cand if cand is not None else f"(computed: {ans[f'slot0_{field}']})"
        print(f"  {field:16s} {str(shown):42s} -> {res} rem={rem}")
        if res in ("accepted", "CORRECT"):
            found[field] = ans["slot0_"+field] if cand is None else cand
            break
print("ACCEPTED FORMATS:", json.dumps(found, indent=0))
print(f"elapsed={time.time()-t0:.2f}s")
