# CLAUDE.md — operating this repo

Automated solver for the **Huntress CTF 2026 Binary Reverse Engineering** lane.
Full design is in `WORKFLOW.md`; this file is the quick operational cheat-sheet
for resuming work in a fresh session.

## Prerequisite every session
The Game Master bearer token is **not** in the repo (it's a secret and the
container is ephemeral). Ask the user for it, write it to a `600` file, and
point the tools at it:
```bash
export HUNTRESS_GM_TOKEN_FILE=/path/to/token   # e.g. in the scratchpad dir
```
`tools/gm.py` feeds it to curl via `--config -` so it never hits argv.
Dependency: `pip install pyzipper` (AES-zip extraction). `infected` is the zip
password for every artifact.

## Run it
```bash
# Whole day, correct order (single_solve -> time_trial -> mastery):
python3 tools/solve_day.py 14 --tt-attempts 3 --mastery-attempts 3

# One mode directly:
python3 tools/autosolve.py '<challenge-id>/mastery'    --retry --attempts 3
python3 tools/autosolve.py '<challenge-id>/time_trial' --retry
python3 tools/autosolve.py '<challenge-id>'            --dry-run          # inspect
python3 tools/autosolve.py '<challenge-id>/time_trial' --practice         # untimed
python3 tools/gm.py list --all                                           # find ids
```

## How it works (one paragraph)
`autosolve.py` opens an attempt, downloads the artifact(s), answers every
field from the real bytes, and submits. Challenge id shapes auto-route to files:
`slotN_*` (day-1 time trial), `c_*/cpp_*` (day-2 time trial), `dNN_*`
(cumulative time trial), `setN.dNN_*` (mastery — one artifact **delivery per
set**, downloaded + submitted in parallel). Config comes from the embedded
`HCFG | ver | xor_key | len(u16) | crc32(u32) | XOR(json)` blob (`hcfg.py`,
CRC-validated), carried raw / Base64 (`SENG…`) / inside a JAR `.class`.
`elfmeta.py` reads ELF headers/symbols/`.huntress` marker/`recover_code`.

## Non-obvious facts (hard-won)
- **Grading is all-or-nothing per submit**; partial submits *accumulate*. Use
  that to calibrate: `discover.py` / probe single fields and watch `remaining`.
- **Answer format depends on each question's `answer_format.kind`**, which
  varies per day for the same field name. Already handled: `elf_class`
  `ELF64` (exact_text) vs `64` (integer); `endianness=little`; `elf_type=ET_EXEC`;
  `machine/architecture=x86-64`; `xor_key_hex`/`crc32_hex` = `0x…`;
  `format` = `elf`/`pe`/`jar` lowercase (exact_text) vs `ELF64`/`PE32+` (pattern)
  vs `PE32/.NET` (managed, pattern); `section_names`/`symbols`/`disassembly` =
  compact JSON; stripped ELF → `exported_symbol`/`recover_code` = `none`.
- **Progression gating:** `single_solve` CORRECT → unlocks `time_trial` →
  unlocks `mastery`. Fresh day: `retry` → `start_required` (use plain `start`);
  `start` → `prerequisite_required` until the earlier mode is CORRECT. When
  `unique_attempts_remaining` hits 0, `op=practice` is untimed and still
  completes the mode. `run_attempt`/`solve_day` handle all of this.
- **Mastery timer is tight (~28s) and `started_at` includes server bundle-gen
  time.** Keep the pipeline fast (parallel deliveries, `HCFG`/`SENG` byte
  locators, no full-file regex) and submit per-set so credit banks early.

## To solve a NEW day
`python3 tools/solve_day.py <N>`. The untimed single_solve stage flags any
field it can't answer (a genuinely new field type / container). Calibrate it on
the single_solve or time_trial (abundant/untimed), bake the rule into
`autosolve.py` `Specimen.answer()` (or `hcfg.py`/`elfmeta.py`), then rerun.

## Days 16-29 (added field types)
The cumulative schemes grew richer. `tools/dayextra.py` + `Specimen.answer`
now cover: wasm/neko containers; `format` enum (elf/pe/pe_cli/jar/wasm/
neko_bytecode) and integer `machine` (e_machine); PE fallbacks for
section_count/section_names/symbols (COFF); extra HCFG keys (host_model,
ipv4); runtime predicates (go/rust/nim/fpc/gnat/crystal/d/coroutine/decoy) and
symbol counts; **PE COFF symbol names keep the `.rdata$`/`.text$` prefix**
(day-2 typeinfo/vtable/mangled_score); conditional-branch opcode count
(vectorised); hcfg_storage classification; Java classfile parsing
(methods/access_flags/class_name/counts) + crash trace (d26); PK19/RS20
packed overlays (d19/d20); structural counts/hashes; question-text + verbatim
filename-tail sub-specimen routing; multi-member common-config (d21/d28).
Calibrate against the highest cumulative single_solve (untimed) — it reveals
every new field type at once; bisect by day then field.

## Day 30 `multi-binary-campaign` (SOLVED)
Three NEKO bytecode members (`loader.n`, `library.n`, `config.n`) each carry an
**HGRF** record — same 12-byte layout as HCFG, magic `HGRF`, scan backward for
the last CRC-valid one — whose JSON holds the campaign graph; answers come from
its `config` object (`dayextra.hgrf_graph_config`). `format` = `neko_bytecode`.
`solve_day.py` now picks the single_solve that owns the timed chain.

## Day 30 bonus `sha1-hulud` (standalone flag — UNSOLVED)
Standalone: one `flag` answer over `sha1-hulud.exe` (Rust PE32+). Not
scriptable. The `embre` crate obfuscates config strings in `.xsobf` with a
SplitMix-style per-index keystream (seed = a `mov eax,SEED` immediate; decoder
reversed — registry paths + anti-debug tool names, no flag). The flag is
revealed only when `is_unlocked(state)` holds (anti-analysis checks pass) and
is keyed by **SHA1** of the unlocked state (init constants present). Needs
either running the PE (no Wine in repo apt) or reversing the SHA1-state key.

## Git
Work on `main`; commit + push each milestone. Verified `CORRECT`: single_solve
+ time_trial + mastery for **days 1-30** (fully automated). Only the
standalone day-30 `sha1-hulud` flag is outstanding. Never commit the token or downloaded artifacts (`.gitignore`).
