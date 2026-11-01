# SHA1-Hulud — graduated hints

A standalone Day-30 bonus in the Huntress CTF 2026 Binary RE lane:
`sha1-hulud.exe`, one answer id `flag`. It is a **flag-checker crackme**, not a
flag-revealer. These hints go from gentle nudge to concrete technique — read
only as far as you need.

## What it is (verified facts)
- Rust, PE32+ x86-64 console app. Interactive: prints `What is the flag?`,
  reads one line from stdin, then exits **silently** on a wrong guess (no
  "correct/wrong" message anywhere in the binary).
- Built with a crate `embre` (`...\embre-...\crypt\src\xor.rs`) that hides
  strings in a custom `.xsobf` section.
- Inlined **SHA-1** (init constants `0x67452301 0xefcdab89 0x98badcfe
  0x10325476 0xc3d2e1f0` appear 7×). The name "SHA1-**Hulud**" (Shai-Hulud =
  a chain of segments) is the big tell: think *chained* SHA-1.

## Hint 1 — stop hunting for a plaintext flag
Scanning memory/strings for `flag{...}` will only ever find *your own input*.
The expected value is never materialised as text. It's a checker: it transforms
your input and compares. Re-aim at "what transform, compared to what?".

## Hint 2 — the obfuscated strings and anti-debug are a *gate*, not the puzzle
The `.xsobf` strings decode (per-index SplitMix keystream, see Hint 5) to
registry paths (`SOFTWARE`, `SYSTEM\CurrentControlSet\Services`, `\drivers`)
and analysis-tool names (`x64dbg.exe`, `x32dbg.exe`, `ollydbg.exe`,
`tcpview.exe`, `apimonitor`, `immunitydebugger.exe`, `rehex.exe`, `hxd.exe`).
Together with `IsDebuggerPresent` / `CheckRemoteDebuggerPresent` /
`NtQueryInformationProcess` / `NtQuerySystemInformation` / `GetThreadContext`
they feed an `is_unlocked(state)` assertion. All of this just decides *whether
the real logic runs* — it is not the flag check. Get past it by analysing in a
clean environment (or by stubbing those APIs in an emulator) and move on.

## Hint 3 — the check is constant-time over a SHA-1 chain
Two wrong inputs of the same length produce byte-identical execution traces:
there is no early-out comparison. The input is run through a SHA-1 computation
and the result compared in constant time against an embedded/derived target.
A single whole-flag SHA-1 would be a one-way wall — so look for the *chain*:
the input is split into pieces and hashed in stages ("Hulud"/worm = linked
segments), each stage's output feeding the next.

## Hint 4 — crack it stage by stage (the key idea)
A linked chain is only as strong as each link. If each segment's expected
intermediate is fixed by the construction, you can **peel** the flag one
segment at a time instead of brute-forcing the whole thing:
1. Recover the segmentation (how the input bytes are grouped per stage — look
   at the length handling and where each SHA-1 block consumes input).
2. For each stage in order, brute-force just that segment over the plausible
   flag alphabet until its stage output matches the next stage's expected
   input/constant, then lock it in and continue.
This turns an infeasible 2^k preimage into k small independent searches.

## Hint 5 — tooling that makes it tractable
- **Emulate** (no Wine needed): `speakeasy`/`unicorn` run the PE on Linux.
  Stub the anti-analysis APIs to report a clean host so `is_unlocked` holds,
  hook `ReadConsoleW` to feed input and `NtWriteFile` to read output.
- **Instrument the SHA-1 boundaries**: hook each inlined SHA-1 init/finalise to
  dump the exact message bytes and the 20-byte digest per stage. That reveals
  the segmentation and every stage's expected intermediate directly — then
  solve offline, no brute needed.
- **Or symbolic execution** (`angr`/`miasm`) on the checker function: constrain
  the output to "accepted" and let the solver recover the input preimage.
- **embre string decoder** (for reference): per byte `i` of an obfuscated
  string, with a 64-bit `seed` taken from the `mov eax,SEED` set up next to
  each string's pointer+length:
  `r8 = 0x5d2e9c47a1b386f0 ^ rol64(seed,17)`;
  `x = (i*0x065767ac2ba816c3) ^ r8`;
  `x = ((x>>29)^x) * 0x41169ddc6c156db1`;
  `x = ((x>>27)^x) * 0xa3d1f5bb9847a411` (all mod 2^64);
  keystream byte = `((x>>55) ^ ((x & 0xffffffff)>>24)) & 0xff`; plaintext =
  keystream ^ ciphertext.

## Honest status
This checker is deliberately hardened (constant-time compare, no plaintext
flag, obfuscated strings, anti-analysis gate). The remaining work is the
stage-by-stage preimage recovery in Hint 4, best driven by the SHA-1-boundary
instrumentation in Hint 5. Everything else in the lane (days 1–31, all three
modes) is already solved by this repo's tools.
