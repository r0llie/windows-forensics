# $MFT — Structure Card

**Artifact:** Master File Table (the index of every file and directory on an NTFS volume).
**Tool:** `tools/mft_parse.py` (offline `$MFT` captures; raw acquisition is handled separately by `tools/collect.py`).
**Verification legend:** *(flatcap)* = byte-level layout from the Linux-NTFS documentation; *(MS Learn)* = Microsoft documentation; *(research)* = peer-reviewed forensic studies; *(practical)* = community-consensus behavior, treat as strong hint, not proof.

This card covers the **on-disk structures**. For what MFT evidence can and cannot prove, read §9–§12 before writing any finding.

---

## 1. What it is

Every file and directory on an NTFS volume is described by one or more **FILE records** in the `$MFT` *(flatcap)*. Record 0 describes `$MFT` itself. The MFT is a regular NTFS file: it has its own record, its own `$DATA` attribute, and can be fragmented.

Key consequences:

- A FILE record **is not** the file's content — it is the metadata (attributes). Small file data can live inline (resident); larger data lives elsewhere and is described by data runs.
- **A FILE record remains after the file is deleted** (in-use flag cleared, sequence number incremented) — see §9, Trap 1.
- `$MFT` is the *only* per-file metadata store that survives "the directory listing is gone": names, parents, sizes, and up to 8 timestamps per file live here (4 in `$SI`, 4 in each `$FN`).

## 2. Locating the MFT — `$Boot`

Volume boot sector (`$Boot` file, first 512 bytes of the volume, *flatcap*):

| Offset | Size | Field |
|---|---|---|
| 0x03 | 8 | System id, `"NTFS    "` (magic) |
| 0x0B | 2 | Bytes per sector |
| 0x0D | 1 | Sectors per cluster |
| 0x28 | 8 | Total sectors in volume |
| 0x30 | 8 | LCN of VCN 0 of `$MFT` |
| 0x38 | 8 | LCN of VCN 0 of `$MFTMirr` |
| 0x40 | 4 | Clusters per MFT record (signed; negative = ¬size) |
| 0x44 | 4 | Clusters per index record (same encoding) |
| 0x48 | 8 | Volume serial number |

Record-size rule: if the value is **positive**, record size = value × cluster size. If **negative**, record size = 2^(−value) bytes. Typical: `0xF6` (= −10) → **1024 bytes** *(flatcap)*. Windows supports 1024 for decades; 4096 was introduced later (Win10 RS4-ish). Never assume 1024 — read it from `$Boot`, or try both and report which parsed.

`$MFTMirr` mirrors **only the first 4 records** and is not a backup of the whole MFT *(flatcap)*.

## 3. FILE record layout

Default 1024 bytes; header is 48 bytes *(flatcap)*:

| Offset | Size | Field |
|---|---|---|
| 0x00 | 4 | Magic `"FILE"` |
| 0x04 | 2 | Offset of the Update Sequence Number (USA offset) |
| 0x06 | 2 | Size of Update Sequence array in **words**, including the USN word itself (S) |
| 0x08 | 8 | `$LogFile` sequence number (LSN of last change) |
| 0x10 | 2 | **Sequence number** (record reuse counter) |
| 0x12 | 2 | Hard link count |
| 0x14 | 2 | Offset to first attribute (usually 0x30 on 1K records) |
| 0x16 | 2 | **Flags** (see below) |
| 0x18 | 4 | Real (used) size of the record, 8-byte padded |
| 0x1C | 4 | Allocated size of the record |
| 0x20 | 8 | Base record reference (0 = this is a base record) |
| 0x28 | 2 | Next attribute id |
| 0x2A | 2 | Align to 4 (XP+) |
| 0x2C | 4 | MFT record number (XP+) |
| USA | 2 | Update Sequence Number |
| USA+2 | 2S−2 | Update Sequence Array (orig bytes) |

Flags *(flatcap)*:

| Bit | Meaning |
|---|---|
| 0x01 | **In use** (0x00 = deleted) |
| 0x02 | Directory |
| 0x04 | × (flatcap: "extension"; observation on live systems: also set for some special metadata files — mark as *uncertain* rather than trusting this bit) |
| 0x08 | Special index present (`$Secure`, `$ObjID`, `$Quota`, `$Reparse`) |

Attributes follow the header, ordered by type/id, terminated by `0xFFFFFFFF` *(flatcap)*. Extra bytes after the end marker (or after real size) are **slack** — old data from previous occupants; useful for carving, never for attributing to the current file.

### 3.1 Update Sequence Array (fixup) — mandatory before parsing

The last two bytes of every 512-byte sector in the record are replaced by the 2-byte USN; the original bytes are saved in the USA *(flatcap)*. To parse:

1. Read the USN word at the USA offset.
2. For each sector end inside the record, verify the two bytes there equal the USN. If not → record is torn/corrupt → report, do not parse.
3. Restore each sector's last two bytes from USA entries `1..S-1`.

A 1 KB record has 2 sectors → 2 fixup positions (at 510 and 1022). If you skip the fixup, two 2-byte hunks of attribute data are silently wrong — the classic cause of "weird timestamps" in homemade parsers. **Trap 3.**

## 4. Attribute header

Every attribute starts with the same 16-byte header *(flatcap)*:

| Offset | Size | Field |
|---|---|---|
| 0x00 | 4 | Type (0x10, 0x30, 0x80, …) |
| 0x04 | 4 | Length of this attribute (including header) |
| 0x08 | 1 | Non-resident flag (0/1) |
| 0x09 | 1 | Name length (N) in UTF-16 chars |
| 0x0A | 2 | Offset to name (0 = unnamed) |
| 0x0C | 2 | Flags (0x0001 compressed, 0x4000 encrypted, 0x8000 sparse) |
| 0x0E | 2 | Attribute id (unique per record) |

**Resident** continues *(flatcap)*: 0x10 value length (4), 0x14 value offset (2, from attribute start), 0x16 indexed flag (1), 0x17 pad; value at 0x18 (+ name, padded to 4).

**Non-resident** continues *(flatcap)*: 0x10 first VCN (8, signed), 0x18 last VCN (8), 0x20 runs offset (2), 0x22 compression unit size (2; size = 2^value clusters, 0 = none), 0x24 padding (4), 0x28 allocated size (8), 0x30 real size (8), 0x38 initialized size (8), then the runlist.

`real size` < `allocated size` is normal (slack in last cluster). `initialized size` < `real size` indicates **sparse or compressed** data *(flatcap)*.

### Attribute types you will actually meet (flatcap, MS-FSCC numbering)

| Type | Name | Forensic value |
|---|---|---|
| 0x10 | `$STANDARD_INFORMATION` | The four user-visible timestamps + DOS flags + **last USN** (§5) |
| 0x20 | `$ATTRIBUTE_LIST` | Points to extension records (§8) |
| 0x30 | `$FILE_NAME` | Name(s), parent, second timestamp set, sizes (§6) |
| 0x40 | `$OBJECT_ID` | Volume-wide unique id ({GUID}); survives rename/move |
| 0x50 | `$SECURITY_DESCRIPTOR` | On-disk ACLs (legacy location; modern: `$Secure:$SDS` via security id) |
| 0x60 | `$VOLUME_NAME` | Volume label |
| 0x70 | `$VOLUME_INFORMATION` | NTFS version, dirtiness flags |
| 0x80 | `$DATA` | File content or **named streams** (`:Zone.Identifier` = MOTW) |
| 0x90/0xA0/0xB0 | `$INDEX_ROOT`/`$INDEX_ALLOCATION`/`$BITMAP` | Directory indexes (indx) — separate artifact |
| 0xC0 | `$REPARSE_POINT` | Symlinks/junctions, dedup, cloud placeholders |
| 0xD0/0xE0 | `$EA_INFORMATION`/`$EA` | Extended attributes (WSL metadata xattrs live here) |
| 0x100 | `$LOGGED_UTILITY_STREAM` | e.g. `$EFS` encryption metadata |

## 5. `$STANDARD_INFORMATION` (0x10) — the "user-visible" times

Resident; **48 bytes minimum, 72 bytes on volumes created/upgraded by Win2K+** (fields below 0x38 exist only if the value is long enough — check the resident value length, *flatcap*):

| Value offset | Size | Field |
|---|---|---|
| 0x00 | 8 | FILETIME: **Birth** (created) |
| 0x08 | 8 | FILETIME: **Modified** (last write) |
| 0x10 | 8 | FILETIME: **Changed** (MFT entry changed) |
| 0x18 | 8 | FILETIME: **Accessed** |
| 0x20 | 4 | DOS file attributes (same bit values as Win32 `FILE_ATTRIBUTE_*`; 0x10 = directory) |
| 0x24 | 4 | Max versions |
| 0x28 | 4 | Version |
| 0x2C | 4 | Class id |
| 0x30 | 4 | Owner id (quota) |
| 0x34 | 4 | Security id (key into `$Secure`) |
| 0x38 | 8 | Quota charged |
| 0x40 | 8 | **Last USN** of this file (`$UsnJrnl` offset; 0 = journal disabled) — see §11 |

**These four timestamps are what user-mode APIs see and set** (`GetFileTime`/`SetFileTime`; *MS Learn*). This is what makes them the timestomping surface.

## 6. `$FILE_NAME` (0x30) — name + parent + second time set

Resident, always. 66-byte fixed part + UTF-16 name, not null-terminated *(flatcap)*:

| Value offset | Size | Field |
|---|---|---|
| 0x00 | 8 | Parent directory file reference (MFT record + sequence) |
| 0x08 | 8 | FILETIME: Birth |
| 0x10 | 8 | FILETIME: Modified |
| 0x18 | 8 | FILETIME: Changed (MFT changed) |
| 0x20 | 8 | FILETIME: Accessed |
| 0x28 | 8 | Allocated size (multiple of cluster size; only meaningful when starting VCN = 0) |
| 0x30 | 8 | Real size (unnamed `$DATA` size — the number Explorer shows) |
| 0x38 | 4 | Flags (copy of DOS flags; 0x10000000 dir, 0x20000000 index view) |
| 0x3C | 4 | Reparse / EA size |
| 0x40 | 1 | Name length **in characters** (L, max 255) |
| 0x41 | 1 | Namespace |
| 0x42 | 2L | Name, UTF-16-LE |

Namespace *(flatcap)*: `0` POSIX, `1` Win32, `2` DOS (8.3), `3` Win32 & DOS (unified — most common). A file can have **up to 3 `$FN` attributes** (one per used namespace), each with its own name and its own timestamp set; all mirror the same times *(research)*. When reading "the file name", prefer namespace 1/3 (the long name); do not treat the `8.3` DOS name as a different file.

Hard links: each additional link adds another `$FN` attribute with a different parent *(flatcap)*. `Hard link count` in the record header should equal the `$FN` count for normal files.

**Update semantics (the crux for timestomping):**

- `$SI` times are **kept current by NTFS on every operation** (write updates Modified, metadata ops update Changed, etc.) *(flatcap)*.
- `$FN` times are **not updated by ordinary content writes** — they go stale; only when the `$FN` attribute itself changes (create, copy, move, rename; *research*) does the kernel overwrite `$FN` times with the **current `$SI` values** (with `SI.C` itself then set to the operation time).

So: a file that was written to yesterday but renamed today shows `FN.Modified` = yesterday's `SI.Modified`-at-rename-moment, then `SI.Modified` may advance further. `FN` times are a *snapshot of `$SI` at name-time*, not an independent witness.

**Size fields can go stale too:** `$FN` sizes are a snapshot from the last name-affecting operation and may not reflect later writes. Current size evidence is in `$DATA`; a stale `$FN` size by itself is not evidence of tampering.

Tool `size` field definition: directories → 0; else the **first `$DATA`** attribute in the merged attribute set (any name; resident → value length, non-resident → real size); if no `$DATA`, the parser uses the displayed (namespace-preferred) `$FN` real size as a fallback. Other tools may select a different `$FN` when multiple names exist.

## 7. Data runs (runlist)

Non-resident attribute values are stored as runs, encoded in the value at the runs offset *(flatcap)*:

- First byte (hex): high nibble **F** = size in bytes of the offset field, low nibble **L** = size in bytes of the length field.
- Then L bytes: run length in clusters (unsigned LE).
- Then F bytes: starting LCN as a **signed** LE offset **relative to the previous run's LCN** (first run relative to 0).
- Header `0x00` = end of runlist.
- F = 0 → sparse run (no location; length only).

Example: `21 18 34 56 00` → length `0x18` clusters at LCN `0x5634` *(flatcap)*. Signed offsets mean a later run can point *backwards* (example 3 in flatcap: LCN 0x160 → −0x20 → 0x140). Decode iteratively and keep the running LCN; a single misread byte scrambles everything after it.

Compression uses 16-cluster units with interleaved sparse runs — do not compute "size on disk" naively from runs for compressed files.

## 8. Extension records and `$ATTRIBUTE_LIST`

If attributes do not fit, the base record gains `$ATTRIBUTE_LIST` (0x20) and extra **extension FILE records** (base reference ≠ 0 at 0x20). The list entries — type (4), record length (2), name length (1), name offset (1), **starting VCN (8)**, **base file reference (8)**, attribute id (2), optional name — tell you which attributes live where *(flatcap)*.

To describe a file completely you must stitch: base record + every extension record. Reading extension records as standalone files is **Trap 13**.

Since mft_parse 0.2.0 the tool stitches, matching MFTECmd's semantics:

- **Linkage source is the extension record's BaseRecordReference** (entry + sequence at 0x20), not the `$ATTRIBUTE_LIST` content — this is exactly what MFTECmd does (it builds `MftRecordToBaseRecord` keys) and it still works when the base record's `$ATTRIBUTE_LIST` itself is non-resident (its content is *not* in the `$MFT` stream and cannot be read offline).
- All `$FILE_NAME` and `$DATA` attributes of every linked extension record are merged into the base; `file_names[]`/`data[]` entries from extension records carry `fragment_record` (and `$DATA` fragments carry `starting_vcn`).
- **Deleted bases are looked up under sequence − 1** (NTFS increments the base sequence when the record is freed, so extension records recorded against the previous incarnation still reference it — MFTECmd's `GetKey` does the same for free records).
- **`$ATTRIBUTE_LIST` entries are verified before being followed**: an entry's recorded sequence must equal the target record's current sequence. Stale entries (a freed incarnation's list still pointing at a record that has since been **reused by a different file**) are counted (`stale_attribute_list_entries`) and warned (`attribute_list_entry_stale`), never merged. The fallback is deliberately **stricter than the index path**: it follows a reference only on an exact sequence match (freed-since targets, recorded+1, are skipped too, since their last occupant cannot be proven from the record alone — the base-ref index covers those cases precisely, with the seq−1 rule).
- Unreadable/unreachable references warn (`attribute_list_extension_outside_capture`, `attribute_list_extension_not_a_file_record`) instead of guessing.
- Extension records are still emitted as their own JSONL rows (they are useful for churn analysis); some comparison tools omit them, so identity fields of an extension record must never be read as "a file".

The parser's output semantics were manually compared with MFTECmd during development. Differences in filename selection, file-size fallback, and timestomp flag definitions are described in the relevant sections; no host capture is distributed with this project.

## 9. Existence semantics — what a record proves

- **In use = 0x01:** file/directory exists (as far as the volume is concerned).
- **In use = 0x00:** the record is **deleted** but retains its last content: name, parent, sizes, timestamps. This is a *deleted-file trace*, not a live file. NTFS increments the sequence number on delete and increments again on reuse *(flatcap)*.
- **File reference = 48-bit record index + 16-bit sequence.** A reference with a stale sequence points at a **reused** record — that is a *different* file. When reporting FRNs, always keep both parts (our tool prints 64-bit index in hex like `0x001800000006ab9b`, as USN does).
- There is **no "file age" field**: age claims must be built from timestamps + other artifacts.

## 10. Timestomp analysis

### 10.1 Mechanics (all *research*-verified)

| Tool class | Writes | Precision | Notes |
|---|---|---|---|
| Basic (`SetFileTime`) | `$SI` M/A/B | whole seconds | Most malware; e.g. GPL timestomp.exe legacy |
| Intermediate (`NtSetInformationFile`) | all 4 `$SI` incl. Changed | 100 ns | `nTimestomp` |
| Advanced (raw disk / driver) | `$SI` **and** `$FN` | 100 ns | `SetMace`; needs admin + unmount/signed driver; blocked on live system disk by Windows protections |

`$FN` cannot be written by any user-mode API *(research)*. But it **can be poisoned indirectly**: timestomp `$SI`, then rename/move the file → kernel copies the (forged) `$SI` values into `$FN` *(research, practical)*.

NTFS also self-heals inconsistency: if `$FN`/directory-index copies disagree with `$SI`, the driver treats `$SI` as authoritative and fixes copies on access *(research)*.

### 10.2 What we may honestly claim

- A record where `$SI` timestamps are **earlier than `$FN`** timestamps is an **observation**, not a verdict: on live systems only ~3–23% of files satisfy "`FN` ≤ `SI`" *(research)*; the most common normal pattern is `SI.C < FN.C` caused by renames.
- Whole-second `$SI` timestamps (nanoseconds = 0) hint at `SetFileTime`-class tools — but also occur legitimately (FAT-sourced copies, installers, build systems, ZIP extraction).
- Strongest local evidence: a `$SI.C` **older than the parent directory's creation** — still needs cross-checks (clock skew, tunneled renames).
- The decisive cross-check is the **USN journal**: a RENAME record near `FN` time explains the `FN` snapshot; absence of any rename while `FN.C > SI.C` is suspicious. `$SI` also stores the file's **last USN** (offset 0x40) — a direct anchor into `$UsnJrnl` (§11).

Flag definitions (ours, deliberate, may differ from MFTECmd's CSV columns):

- `si_created_before_fn_created`: `SI.C < FN.C` **of the displayed (namespace-preferred) `$FN`** (we prefer `3 > 1 > 0 > 2`). Other tools may emit one row per `$FN` and compare against a different name attribute. When multiple `$FN` attributes disagree, flag definitions can therefore differ while each remains consistent with its stated rule.
- `si_whole_second_precision`: `SI.C` or `SI.M` falls exactly on a whole-second boundary (the 100 ns sub-second remainder is zero; flag is set if *either* timestamp qualifies). MFTECmd's `uSecZeros` fires when *either* timestamp's millisecond **component** is 0 (`.Millisecond == 0`), which is true even when sub-millisecond ticks remain (e.g. `x.000456s`) — theirs is therefore a strict superset of ours; all 1,147 disagreements in the reference comparison were `ours=False, ref=True` to that definition.

### 10.3 File tunneling (rare but real)

Renaming within the same directory within ~15 s of the original create/delete can preserve the old creation time on the new name (file tunneling). Do not call a "backdated-looking" delete+recreate pattern timestomping without USN confirmation.

## 11. Cross-validation pointers

- `$SI` last-USN (0x40) → find that USN record in `$UsnJrnl`: exact last change time for that file per the journal.
- `$FN` parent ref → walk parents up (records for `..`) to rebuild full paths; compare with USN `ParentFileReferenceNumber` for the same FRN.
- USN RENAME_OLD_NAME/RENAME_NEW_NAME pairs explain `$FN` time updates and names over time — MFT shows only the *latest* name; the journal shows the history.
- Execution claims need Prefetch/registry/event logs — MFT alone never proves "it ran" (only that it existed; and if deleted, that it existed until its MFT record was reused).
- `$MFT` times vs `$SI` times vs `$LogFile` (§backlog) — three independent sources; disagreements are findings.

## 12. Reading methods

- **Offline (this tool):** parse a captured `$MFT` file (raw bytes of the MFT data stream). Captures can be acquired with `tools/collect.py` or another acquisition tool. The parser detects record size when possible; it can also be provided explicitly (§2).
- **Live (not implemented in this parser):** direct raw-volume parsing is not available. `tools/collect.py` can acquire a raw `$MFT` capture for offline parsing; raw volume access requires administrator privileges.
- `$MFTMirr` is only useful for the first 4 records; never parse it as "the backup MFT" *(flatcap)*.

## 13. Agent Traps (LLM pitfalls)

1. **"There is a record, so the file exists."** Wrong: deleted records persist with in-use flag 0x00. Check flags **and** whether sequence refers to current occupancy.
2. **Timestamps quoted without the attribute name.** `$SI` and `$FN` disagree by design; "the file's creation time" is ambiguous. Always say which attribute (and which offset) produced a time.
3. **Skipping USA/fixup** → two 2-byte corruptions per 512-byte sector; timestamps read 2 bytes wrong. Always fix up first.
4. **Treating `$FN` as a tamper-proof witness.** `$FN` can be *indirectly* timestomped via rename/move after `$SI` forgery.
5. **"SI times older than FN times = timestomp."** This comparison has many false positives; renames produce it routinely. Report as an observation and require a USN cross-check.
6. **Assuming 1024-byte records.** Read `$Boot` 0x40 (negative = 2^−v).
7. **Attributing slack bytes / bytes after the end marker to the current file.** They may be from a previous occupant of the reused record.
8. **Ignoring record reuse** (sequence number): old bookmarks/USN entries with the same record index may refer to a different file.
9. **One `$FN` per file.** Up to 3 (namespaces), plus one per hard link. "The name" = the Win32 one; the DOS 8.3 name is not a second file.
10. **Reading extension records as files.** They share the base record's identity; nothing is complete until stitched via `$ATTRIBUTE_LIST`.
11. **`$FN` Modified = file last written.** No: it is a snapshot from the last name-affecting operation; ordinary writes don't touch it.
12. **Trusting Accessed time.** NTFS delays access-time updates up to 1 h *(MS Learn)* and modern Windows disables them by default — an untouched-looking `A` time proves nothing (Trap for "was it opened?").
13. **Using `$FN` size fields blindly.** They can remain stale after writes. Meaningful only when starting VCN = 0, and even then a historical snapshot; current truth is the `$DATA` size.
14. **Comparing directory-index (indx) `$FN` copies with MFT `$FN` as if identical.** Index copies track `$SI` values and get "fixed" on access *(research)* — discrepancies are usually self-healing artifacts, not tampering.
15. **Calling exact-to-the-second timestamps "forged".** Legit sources abound (installers, archives, FAT lineage). Whole-second precision is a *hint*, and `SetFileTime` succumbing tools writing 0 nanoseconds is a *hint* — never alone a finding.
16. **MFT proves execution.** It does not. Existence ≠ execution ≠ provenance. Execution needs Prefetch/Amcache/event logs; cross-check required.
17. **Following `$ATTRIBUTE_LIST` entries without verifying sequences.** A freed record's list can reference an entry that has since been **reused by a different file**; merging by record number alone can graft another file's `$DATA`/`$FN` onto the deleted file. Entry record number + recorded sequence must both match the target's *current* header. Extension-record *linkage* (base-ref based) has the mirror-image quirk: **deleted bases must be matched at sequence − 1** (NTFS bumps the base sequence on free).

## 14. Sources

- Linux-NTFS documentation (flatcap/R. Russon), v0.6 — FILE record, fixup, attribute header, `$SI`/`$FN`, data runs, `$Boot`: https://flatcap.github.io/linux-ntfs/ntfs/ (pages: concepts/file_record.html, concepts/fixup.html, concepts/attribute_header.html, concepts/data_runs.html, concepts/filename_namespace.html, attributes/standard_information.html, attributes/file_name.html, attributes/attribute_list.html, files/boot.html) — retrieved 2026-10-15.
- Microsoft Learn, `SetFileTime` (user-mode C/A/M timestamp semantics; access-time delay note) — retrieved 2026-10-15.
- "Time for Truth: Forensic Analysis of NTFS Timestamps" (ARES/ACM 2021) — tool taxonomy (basic/intermediate/advanced), `$FN` update-on-rename mechanics, precision limits of `SetFileTime` tools.
- "Timestomping NTFS" (W. Minnaard, os3.nl 2014) — `FN ≤ SI` invariant fails on real systems (23%/3%), NTFS self-healing of `$FN` copies from `$SI`, IXFN semantics.
- artefacts.help / qazeer DFIR notes — community formulation of the `$SI`-vs-`$FN` comparison and its false-positive caveats.
- Regression coverage uses synthetic records, including extension linkage, stale references, and timestamp interpretation cases. Live acquisition data is not distributed.

Structure card version 1.2 — do not edit layouts from memory; update only with a cited source.
