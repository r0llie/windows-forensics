# Prefetch (.pf) — Structure Card

Version 1.1 — based on libscca format documentation (J. Metz, rev 0.0.24), MS-XCA (Xpress Compression Algorithm specification), libfwnt source, and Microsoft documentation. Automated parser and decompressor regression tests use generated synthetic data.

## 1. What it is

The Prefetch engine (SuperFetch/SysMain lineage) watches process start-up file loads and caches a trace so future starts are faster. Every time an executable image is launched, the system updates a per-application trace file:

```
C:\Windows\Prefetch\<EXECUTABLE>-<HASH>.pf
```

A .pf file answers: **"this executable was run; it has run at least N times; the most recent runs were at these times (last 8); and it loaded these files."** It does **not** record command line, user, or arguments.

- Enabled by `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters\EnablePrefetcher` (0 off, 1 app, 2 boot, 3 both). Windows Server defaults to off. SSD-only systems may reduce/disable it (SysMain service).
- Files live in `C:\Windows\Prefetch\` (admin/ACL-restricted; a non-elevated listing can silently return empty — verify privilege before concluding "no prefetch").
- `ReadyBoot` boot traces (`NTOSBOOT-B00DFAAD.pf`) are boot-time traces, not user process runs.

## 2. Naming

`<EXECUTABLE>-<HASH>.pf` — executable basename truncated to 29 chars, upper-cased; HASH = 8 hex digits of the prefetch hash (see §7). Variations *(libscca)*:

- `/prefetch:N` processes get extra digits on the hash: `OP-EXPLORER.EXE-A80E4F97-000000F5.pf`. Per MS: `/prefetch:1..8` add the number to the hash; `9+` behaves like `0`.
- **NTFS ADS execution**: running `C:\...\notepad.exe:evil.exe` produces `NOTEPAD.EXE:EVIL.pf` — the ADS name appears in the .pf filename. (Hunt: .pf names containing `:`.)
- The same executable can have **multiple .pf files** (different full paths, different /prefetch values, or 32/64-bit variants) — do not merge them blindly.

## 3. Container: raw vs MAM

- **Version 17 / 23 / 26 (XP → 8.1):** the .pf file *is* the uncompressed structure — starts with `version` then `SCCA`.
- **Version 30 / 31 (Windows 10 / 11):** the .pf is a **MAM container**: `4D 41 4D 04` ("MAM\x04") + `uint32 uncompressed size` + **XPRESS Huffman** compressed data *(libscca)*. The decompressed data starts with the normal 84-byte file header.

### XPRESS Huffman decompression (MS-XCA, LZ77+Huffman)

- Compressed stream = sequence of **blocks**; each block = **256-byte Huffman table** + bit stream, and expands to **up to 65536 bytes** of output (last block = remainder). At a block boundary the residual bits in the register are **discarded** and the next table starts at the next unread byte. Matches may reference bytes produced in earlier blocks (window spans block boundaries).
- **There is NO end-of-stream symbol.** Symbol 256 is a legal match: length nibble 0, offset bits 0 → copy 3 bytes from offset 1 (repeat last byte 3×). Treating 256 as EOS corrupts multi-block files; the synthetic regression suite guards this behavior.
- Table: 512 symbols × 4 bits (low nibble = symbol 2i, high nibble = symbol 2i+1) = code bit lengths (0–15).
- Decoding table: canonical — sort by (bit length asc, symbol asc); symbol with length X occupies `2^(15−X)` consecutive entries of a 2^15-entry table. Table must exactly fill 2^15 entries or the stream is invalid.
- Bit stream: initialized with 32 bits (two 16-bit little-endian words), consumed MSB-first; after each symbol and after each match offset, if fewer than **16** bits remain, pull the next 16-bit little-endian word.
- Symbol < 256 → literal byte. Symbol ≥ 256: `L = symbol − 256`; `length_nibble = L & 0xF`, `offset_bits = L >> 4`; offset = `(1 << offset_bits) + next offset_bits bits`; if `length_nibble == 15`: read a **byte-aligned** byte `b`; if `b == 255` read a 16-bit LE value instead; length = base + extensions; final `length += 3`. Copy `length` bytes from `output − offset` **one byte at a time** (overlap allowed).
- Naive single-block implementations corrupt any .pf whose decompressed size > 64 KiB — handle blocks.

## 4. File header (84 bytes, decompressed)

| Offset | Size | Field |
|---|---|---|
| 0x00 | 4 | Format version: 17 XP/2003, 23 Vista/7, 26 8.0/8.1, 30 Win10, 31 Win11 |
| 0x04 | 4 | Signature `"SCCA"` |
| 0x08 | 4 | Unknown (seen 0x0F, 0x11) |
| 0x0C | 4 | File size (uncompressed) |
| 0x10 | 60 | Executable filename, UTF-16LE, null-terminated (max 29 chars; XP leaves remnants after the terminator — ignore) |
| 0x4C | 4 | Prefetch hash (should equal the hash in the filename) |
| 0x50 | 4 | Flags (0x01 = boot prefetch; else 0) |

## 5. File information section (right after the header)

Field names: metrics array offset/count, trace chains array offset/count, filename strings offset/size, volumes info offset/count/size — all file-relative offsets/counts.

- **v17 (68 bytes, @0x54):** …, last run time at rel 36 (8), 16 unknown, run count at rel 60, 4 unknown.
- **v23 (156 bytes):** 8 unknown at rel 36, last run time at rel 44 (still only ONE), 16 unknown, run count at rel 68, then unknown to 156.
- **v26 (220 bytes):** rel 44 = **8 × FILETIME last run times** (index 0 = most recent, 0 = unused); run count at rel 124 (rel 128/132 unknown; rel 136..219 unknown).
- **v30 variant 1 (220 bytes):** like v26 but rel 136 = string offset, rel 140 = string size.
- **v30 variant 2 (212 bytes) & v31 (212 bytes):** rel 108 = 8 unknown, run count at rel 116, string offset/size at rel 128/132.

Discriminator: the first u32 of the section is the mandatory metrics offset (v17: 0x98; v23: 0xF0; v26/v30v1: 0x130; v30v2/v31: 0x128) — sanity-check layout offsets instead of assuming a size. Run times are **UTC** FILETIME. The v30 string field (libscca calls it "hash string", doc carries `TODO: rename`) is **not the hash**: it can hold an executable path or UWP package family name. Do not compare it with the filename hash.

## 6. Sections

- **File metrics array** (one entry per file loaded; the executable itself is usually an entry): v17 entry 20 B (trace chain index, #trace entries, name string offset+len, flags); **v23+ entry 32 B** (adds blocks-to-prefetch (rel 8), file reference (rel 24) — 6-byte MFT record + 2-byte sequence). Metric flags: 0x1 do-not-prefetch, 0x2 load-as-resource, 0x200 load-as-executable.
- **Trace chains**: v17/26 entry 12 B (next index or 0xFFFFFFFF end, block load count (512 KiB units), flags, used bits, prefetched bits); **v30/31 entry 8 B** (block count, flags, used/prefetched bits — no next index).
- **Filename strings**: UTF-16LE blob; metrics reference into it by offset (relative to strings start) + char count.
- **Volumes information** (v17 entry 40 B; v23/26 104 B; v30/31 96 B): device path (offset+chars, relative to the volumes section), volume creation FILETIME, serial; file references array (v17: version u32 + count + refs; v23+: version=3, count, 8 unknown, refs) and directory strings (u16 char count + UTF-16 chars) — both relative to the volumes section.
- On Win10/11 in-file device paths look like `\VOLUME{GUID}\...` (or `\DEVICE\HARDDISKVOLUME#` on older). Large .pf files may be truncated by the system (>~1.8 MB cases exist) — parse what is present and report.

## 7. The prefetch hash

Computed over the **upper-cased Windows device path** with `\DEVICE\HARDDISKVOLUME#` prefix (even on Win10, where in-file paths use `\VOLUME{GUID}`) *(libscca)*. Three known functions *(libscca)*:

- **SCCA XP** (XP/2003) — 37-multiply roll, then `*314159269 % 1000000007`, sign-fold, `% 1000000007`:
  ```python
  h = 0
  for ch in path_upper_utf16_units: h = (h * 37 + ch) % 2**32
  h = (h * 314159269) % 2**32
  if h > 0x80000000: h = 2**32 - h
  return (abs(h) % 1000000007) % 2**32
  ```
  (Per-unit values for UTF-16 code units; libscca's snippet uses `ord()` of Python chars — for BMP that is the code unit.)
- **SCCA Vista** (Vista, Win10): `h = 314159; h = (h*37 + c) % 2**32` over the string.
- **SCCA 2008** (Server 2008, Win7, Win8/8.1 — and the practical default on Win7/8.x): 8-char blocking with `442596621` and `803794207` constants; tail loop `h = (37*h + c) % 2**32`. Pseudocode in libscca docs.
- The in-file hash (header 0x4C) is generated by the OS version that wrote the file; verify against the **filename** hash first (they must match), recompute from paths only as a cross-check (device path numbering is not visible inside the file on Win10). The v30 file-information string is not a hash (see §5).

## 8. Interpretation — what it proves (and what it does not)

- Existence of `X.EXE-*.pf` → X was run on this machine (image load observed). Run count = lifetime launches observed for that trace; 8 last run times = the most recent 8 (UTC). **v17/v23 files have only ONE last run time.**
- Absence proves **nothing** (never run vs cleaned vs prefetch disabled vs server edition vs SSD policy).
- It does **not** prove the process did anything, nor who ran it, nor with which arguments.
- A .pf file's own timestamps (MFT/USN) reflect *when the trace was written* (≈ last run or cleanup), not creation of the executable.
- Fields are user-mode writable (admin/SYSTEM): **tampering is possible**; treat content as evidence, cross-check with USN/BAM/Amcache. A hash field that does not match the filename, or an exe-name that does not match the filename prefix, is an *observation* worth reporting.

## 9. Cross-validation pointers

- `.pf` last-write time (MFT/USN) should ≈ last run time (index 0) for frequently used apps — gaps = cleanup/tampering.
- Windows **BAM/DAM** (registry) records last-run times per user SID — pairs with prefetch for "who".
- **Amcache** (registry) records first-run/install traces — pairs for "when first seen".
- Executable's MFT/USN records: creation + recent renames; prefetch ties the image to actual execution.
- Timeline fusion: each .pf contributes 1–8 run events (timestamped by the OS, UTC).

## 10. Agent Traps (LLM pitfalls)

1. **"Prefetch shows the command line / user / parent."** It shows none of those. It only ties an image path to run times.
2. **"Run count = runs in the last 8 entries."** No: run count is lifetime; the 8 times are only the most recent. `run_count` ≫ 8 is normal.
3. **Assuming 8 run times for all versions.** v17/v23 store a single last-run time. Reading 64 bytes there produces garbage.
4. **Local time.** Run times are FILETIME **UTC**. Do not apply local offset again.
5. **"No .pf = never ran."** False (disabled/cleaned/server/SSD). Report as "no prefetch evidence", never as proof of absence.
6. **"Prefetch hash = file hash."** It is an 32-bit path-derived ID (not integrity, not content). Two different files can collide; it is not cryptographic.
7. **Ignoring OS version when verifying the hash.** XP/Vista/2008 (Win7/8) functions differ; and the hash input is the `\DEVICE\HARDDISKVOLUME#` path, which is *not reconstructable* from the file on Win10 (in-file paths show `\VOLUME{GUID}`).
8. **Version 30 single layout.** There are two file-information variants (220 vs 212 bytes); check the metrics-offset field (0x130 vs 0x128) and validate section offsets before trusting counts.
9. **Single-Huffman-table decompressors.** Files whose decompressed size exceeds 64 KiB use one 256-byte table **per 64 KiB output block**. Single-table code "works" on small files and silently corrupts large ones (e.g. `NTOSBOOT`).
10. **Reading extended match lengths as bit-stream bits.** Length extension bytes are read **byte-aligned**; mixing them with the 16-bit register produces garbage on long matches.
11. **Multiple .pf per executable** (paths, /prefetch:N, bitness). Merging run counts across hashes fabricates history; treat each .pf as its own trace.
12. **Filename truncation at 29 chars** — compare prefixes, not full names, when matching .pf names to executables with long names.
13. **ADS traces**: `NOTEPAD.EXE:EVIL.pf` means someone executed an alternate data stream — the colon is a signal, not a typo.
14. **`NTOSBOOT-B00DFAAD.pf` is not an application** — it is the boot trace; do not timeline it as a user process.
15. **Trusting a .pf that was plausibly edited.** Hash/exe-name mismatches and impossible run-time sequences (future times) are observations of tampering, not proof of clean history elsewhere — cross-check USN creation times of the .pf itself.
16. **"Prefetch proves malware ran with persistence."** It proves image load; persistence and intent need Amcache/USN/registry/event log corroboration.
17. **Treating symbol 256 as end-of-stream.** It is a legal match (copy 3 bytes from offset 1). An EOS check "works" on files that never use it and breaks others mid-stream — class of bug that cost a full debugging session (see CHANGELOG 0.4.0). The stream ends when the declared output size is reached; that is the only terminator.
18. **Splitting fixed-size UTF-16 fields on `\x00\x00`.** In a 60-byte UTF-16 name field the last character's high byte plus the first terminator byte also form `00 00`; a naive byte split cuts mid-character (trailing replacement char). Decode the full field, then split at the first NUL **character**.
19. **Assuming the v30 file-information string is the hash.** It is the executable's device path (or UWP package family name) on Windows 11 — never compare it with the filename hash. libscca's own doc marks the name as TODO-rename.
20. **Verdicting corruption from non-descending run times.** Small forward steps can occur in valid records. Report the observation; do not call it tampering without corroboration.
21. **Assuming a .pf that is all `0x00` bytes is a parser bug.** Zero-filled .pf files can result from failed or incomplete writes. Report "zero-fill corruption", never invent fields from it.
22. **Expecting every flag bit to have a documented name.** A metric flag bit may be present without a documented name; empty `flags_names` with nonzero `flags` is possible.

## 11. Sources

- libscca — Windows Prefetch File (PF) format (J. Metz), rev 0.0.24 (2026): header/info/metrics/trace-chains/volumes layouts, MAM container, hash functions — https://github.com/libyal/libscca/blob/main/documentation/Windows%20Prefetch%20File%20(PF)%20format.asciidoc — retrieved 2026-10-15.
- [MS-XCA] Xpress Compression Algorithm — LZ77+Huffman decompression pseudocode (2.2.4), canonical table construction, 64 KiB blocks — https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-xca/26db8e62-bbd8-472c-a09e-623f6de10f0b — retrieved 2026-10-15.
- MS Learn / Ryanmy MSDN blog — `/prefetch:#` semantics — retrieved 2026-10-15 via libscca citation.
- Validation: synthetic round-trip and malformed-input tests cover container decoding, XPRESS-Huffman blocks, record layouts, and honest failure reporting. Any independent operating-system parity check is development validation, not a bundled fixture or a guarantee for every Windows build.

Do not edit layouts from memory; update only with a cited source.
