# Huntress CTF 2026 — Binary Reverse Engineering automated workflow

An end-to-end, fully automated solver for the **Binary Reverse Engineering**
lane of the Huntress CTF 2026. It drives the Game Master API, downloads the
assigned artifacts, reverse-engineers them from the real bytes, and submits the
answers — fast enough to beat the server-enforced countdown on Time Trial and
Mastery attempts.

**Status:** Mastery modes for Days 8, 9, 10 and 15 solve `CORRECT` fully
automated (~15 s each); Day 1 Time Trial solves `CORRECT` in ~6 s. The
extractor covers every released day (1–15) and generalises to unseen days of
the same family. Day 15 adds a **paired stripped/symbolized specimen** per day
(`dNN--variant-*-stripped.elf` + `-symbolized.elf`); the solver routes each
`stripped_`/`symbolized_` field to its build and the two `artifact_sha256`
fields to symbolized (`_1`) then stripped (`_2`).

**Dependency:** `pip install -r requirements.txt` — `pyzipper` is required to
decrypt the WinZip-AES evidence archives (stdlib `zipfile` cannot).

---

## 1. The game loop

```
list  →  start/retry an attempt  →  download artifact  →  solve from bytes  →  submit
```

The Game Master lives at `https://2026.huntress.ctf.games/`. Every request
carries a personal bearer token. **The token is never stored in this repo** —
supply it at runtime via `HUNTRESS_GM_TOKEN` (raw) or `HUNTRESS_GM_TOKEN_FILE`
(a path to a file containing it, mode `600`). `tools/gm.py` feeds it to `curl`
through `--config -` (stdin) so it never appears in process arguments.

| Operation | Request |
|-----------|---------|
| List | `GET ?op=list` (`&day=`, `&lane=`, `&all=true`, `&search=`) |
| Start / reconnect | `POST {"challenge":"<id>"}` |
| **Retry** (fresh scored variant) | `POST {"op":"retry","challenge":"<id>"}` |
| Status | `GET ?op=status&challenge=<id>` |
| Artifact | `GET ?op=artifact&challenge=<id>[&delivery=N]` |
| Submit | `POST {"challenge":"<id>","answers":{...}}` |

Modes: **single_solve** (untimed; a correct solve earns the flag + points and,
for a newly released day, is the **prerequisite** that unlocks the day's
time_trial/mastery — until it is solved those return `prerequisite_required` /
`start_required`), **time_trial** (one specimen family), **mastery** (bundle of
many tasks). time_trial and mastery are scored but **untimed by default**
(`deadline: null`); pass `run_for_time: true` on start/retry only for a timed
Hall-of-Fame attempt. Open a fresh scored attempt with a plain start first;
`op:retry` only works once an attempt exists (it buys a fresh variant).

---

## 2. Challenge schemes

The `answer_ids` returned by `start`/`retry` come in four shapes. The solver
auto-detects which and routes each id to the right artifact file:

| Scheme | Example id | Artifact files | Seen in |
|--------|-----------|----------------|---------|
| **slot** | `slot0_elf_class` | `slot-0.elf … slot-3.elf` | Day 1 Time Trial |
| **standalone** | `cpp_xor_key`, `campaign` | `day01-c.elf`, `day02-cpp.{elf,exe}` | Day 2 Time Trial |
| **cumulative** | `d03_analysis_config_domain` | `dNN--variant-*.{elf,exe,dll,jar}` | Day ≥3 Time Trial |
| **mastery** | `set2.d07_analysis_config_url` | one **delivery per set** (`delivery=0,1,2,…`) | all Mastery |

Mastery bundles **N sets** (observed 3–5), each a *separate artifact delivery*
with its own fresh variants, all under one short timer. Specimens appear as
ELF **or** PE (`.exe`) across variants.

---

## 3. The HCFG configuration blob (the core mechanism)

Every specimen from Day 2 on embeds a malware-style config:

```
"HCFG" | version(u8) | xor_key(u8) | payload_len(u16 LE) | crc32(u32 LE) | XOR(payload, xor_key)
```

`payload` is a UTF-8 JSON object (`campaign`, `domain`, `ipv4`, `url`,
`mutex`, …) XOR-ed byte-wise with `xor_key`; `crc32` is CRC-32 of the *decoded*
payload (used to validate extraction and reject decoys).

It is carried three ways depending on the toolchain — all handled by
`tools/hcfg.py`, which validates by CRC so false positives (assertion strings,
decoys) are rejected automatically:

* **raw** in the file — C++, Go, Rust, Swift, Zig, Pascal, .NET → literal `HCFG`
* **Base64** string constant — Java/Kotlin, Nim, D, Crystal → decode first
  (a blob that starts `HCFG` base64-encodes to a token starting **`SENG`**,
  which gives a fast byte-search locator even in 60 MB+ binaries)
* **inside a JAR** — a Base64 constant within a `.class` entry

Archives are AES-encrypted ZIPs (WinZip AES, ZIP compression method 99); the
password is **`infected`** (the standard malware-sample convention). The
stdlib `zipfile` cannot decrypt these, so **`pyzipper`** is required (see
`requirements.txt`); the extractor falls back to stdlib only for plain ZIPs.

---

## 4. Calibrated answer formats

Grading is **all-or-nothing per submit** (a submit is `accepted` only if every
answer in it is correct; any wrong answer → `incorrect`, nothing recorded).
Partial submissions **accumulate** within an attempt, which is exploited by the
`discover.py` oracle to learn each field's exact expected string.

The required output of a field depends on the question's declared
`answer_format.kind`, which **varies per day for the same field name** — so the
solver is format-aware. Calibrated canonical values:

| Field | Value | Notes |
|-------|-------|-------|
| `elf_class` (exact_text) | `ELF64` / `ELF32` | |
| `elf_class` (integer) | `64` / `32` | e.g. `d08_analysis_elf_class` |
| `machine` / `architecture` (integer) | `62` (= `0x3e`, x86-64) | raw `e_machine` code; e.g. `d15_analysis_*_machine` |
| `endianness` | `little` / `big` | not "little endian" |
| `machine` / `architecture` | `x86-64` | pattern, lenient |
| `elf_type` | `ET_EXEC` (`ET_` prefix) | |
| `entry_point` | `0x401030` | lowercase hex, `0x` |
| `has_symtab` | `true` / `false` | |
| `marker` | exact `.huntress` string | |
| `exported_symbol` | symbol name, or `none` if stripped | |
| `recover_code` | returned constant (int), or `none` if stripped | keyed to the symbol |
| `section_names` | compact JSON array in SH-table order | leading `""` optional |
| `symbols` | compact JSON array of `.symtab` names | |
| `disassembly` | compact JSON array of `recover_code` instructions | `[]` if stripped |
| `xor_key_hex` / `config_crc32_hex` | `0x` + lowercase hex | both schemes |
| `format` (ELF) | `elf` | lowercase family token; the **only** value accepted from day 12 on (early days also took `ELF64`). Width lives in `elf_class`. |
| `format` (PE/JAR) | `PE32` / `PE32+` / `JAR` | |
| `format` (managed .NET, compound) | `PE32/.NET` | container **and** runtime |
| `metadata_version` (.NET) | `v4.0.30319` | from `BSJB` metadata root |
| `hcfg_version` | `1` | HCFG version byte |
| `hcfg_offset` | file offset of the HCFG blob (raw) or the base64 token (encoded) | |
| `has_hcfg_section` | `true`/`false` | checks **ELF and PE** section tables |
| `compression_methods` (JAR) | compact JSON array of ZIP method codes, e.g. `[0,8]` | |
| config `campaign`/`domain`/`url`/`mutex` | exact decoded strings | |
| `*_sha256*` | SHA-256 of the specific artifact file | `d03` `_1`=dll, `_2`=runtimeconfig |

**Stripped specimens** (Day 1 `BR01-STRIPPED-PROFILE`): `has_symtab=false`,
`exported_symbol=none`, `recover_code=none` (keyed to the absent symbol, even
though the `mov eax,imm; ret` stub is still in `.text`).

---

## 5. Tooling

| File | Role |
|------|------|
| `tools/gm.py` | Game Master HTTP client (token via stdin curl config) |
| `tools/hcfg.py` | universal HCFG config extractor (raw / base64 / jar, CRC-validated) |
| `tools/elfmeta.py` | pure-Python ELF parser (class, machine, type, entry, sections, symbols, `.huntress` marker, `recover_code` constant & disassembly) |
| `tools/autosolve.py` | end-to-end solver: open attempt → download (parallel per delivery) → solve (format-aware) → submit (incremental per set) |
| `tools/discover.py` | partial-credit format-discovery oracle |

---

## 6. Running it

```bash
export HUNTRESS_GM_TOKEN_FILE=/path/to/token.txt   # 600, never committed

# Recommended: orchestrate a whole day in the right order
#   single_solve (untimed coverage)  ->  time_trial (scored)  ->  mastery (parallel)
python3 tools/solve_day.py 10 --tt-attempts 3 --mastery-attempts 3
python3 tools/solve_day.py 14            # a future day, once released
python3 tools/solve_day.py 10 --from mastery   # skip straight to mastery
```

`solve_day.py` resolves the day's three challenge ids and runs the stages so
each informs the next:

1. **single_solve** — untimed. Dry-runs the solver over the day's artifact and
   reports any field with no answer. A new, unseen field type surfaces here,
   with no clock running.
2. **time_trial** — scored. Validates the answer formats for real. It *gates*
   mastery: a genuine `incorrect` stops the run (don't burn scarce mastery
   variants on a mis-calibrated solver), while a mere `expired` (big artifact
   vs short timer) is treated as a timing artifact and lets mastery proceed.
3. **mastery** — scored, multi-delivery, downloaded and submitted **in
   parallel**, retried up to `--mastery-attempts` until `CORRECT`.

The single-challenge tool underneath it:

```bash
# One mode directly:
python3 tools/autosolve.py '<id>/mastery'    --retry --attempts 3
python3 tools/autosolve.py '<id>/time_trial' --retry
python3 tools/autosolve.py '<id>'            --retry --dry-run   # inspect, no submit
```

`--retry` spends one `unique_attempts_remaining` for a fresh scored attempt;
omit it (or pass `--start`) to reconnect to the current attempt without
spending a variant. `--only <regex>` / `--override field=value` drive probes.

### Performance

Mastery is the tight case: **N deliveries × ~31 MB** (the Day 8 Swift binary
alone is 67 MB decompressed) under a ~28 s server timer whose clock starts when
the server *begins* generating the bundles. The solver copes by:

* downloading every delivery **in parallel** (one thread per set);
* locating configs with C-speed `HCFG`/`SENG` byte searches (no full-file
  regex), and parsing ELF/PE headers directly rather than shelling out;
* running each set's **download → solve → submit in its own thread**, so correct
  answers *bank immediately* (partial credit) and the attempt flips to `CORRECT`
  the moment the last set lands — surviving a tight or variable window.

---

## 7. Extending to unseen days

The generator is one consistent family: AES(`infected`) ZIP of
`dNN--variant-*` specimens, each with an HCFG config and the standard
ELF/PE/JAR metadata questions. `hcfg.py` finds the config regardless of
carrier, `elfmeta.py` reads any ELF, and `autosolve.py` answers by
field-name + declared format. New days of the same shape need no new code; a
genuinely new field type is calibrated in minutes with `discover.py` against a
Time-Trial variant (which has hundreds of spare attempts).
