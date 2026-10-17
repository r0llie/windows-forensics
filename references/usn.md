# USN Journal ($UsnJrnl) — Structure Card

Scope: the NTFS per-volume change journal (`$Extend\$UsnJrnl`). NTFS and ReFS support USN operations; this card covers the NTFS artifact as encountered in Windows forensics.
Status: reference and parser available. Automated regression tests generate synthetic USN records; live acquisition must be evaluated against the target system and Windows version.
Related: `mft.md` (FRN -> MFT record), `timeline-methodology.md` (fusion rules).

All offsets are byte offsets, little-endian. Statements marked **(verified)** are taken from Microsoft Win32 documentation (see Sources). Statements marked **(practical)** are derived from the binary layout and field behavior; consult parser diagnostics and source coverage for a specific case.

## 0. If you remember nothing else

- Per-volume artifact; it records **change events**, not file contents.
- **No USN record version contains actor information** (process, user, program). Never attribute a change to something from USN alone.
- A rename/move = **two records** (`RENAME_OLD_NAME`, `RENAME_NEW_NAME`).
- Reasons **accumulate** per open-session; repeats of the same kind of change do **not** write new records; the final record carries `CLOSE` and is a **summary without order**.
- Timestamps are **UTC FILETIME**; ordering is by **USN**, never by timestamp.

## 1. What it is

- NTFS maintains a change journal per volume. Changes to files/directories append records to the journal stream: the fact of a change, the reason, and the affected file (verified).
- Storage: hidden NTFS metadata file `$Extend\$UsnJrnl` with two streams:
  - `$Max` — journal metadata (a `USN_JOURNAL_DATA` structure; see §3). **(practical: standard forensic reading; docs describe the same layout as the `FSCTL_QUERY_USN_JOURNAL` output buffer)**
  - `$J` — the record stream, a sparse file used as a ring buffer.
- "The change journal logs only the fact of a change to a file and the reason for the change ... It does not record enough information to allow reversing the change." (verified)
- **USN** ("update sequence number") is defined as "the offset from the beginning of the stream for a particular record" (verified). It doubles as the per-volume ordering key.

## 2. Questions it answers — and does not

Answers:
- Was a file created / deleted / renamed / written to? When (record time), under which name at that moment, under which parent directory (parent FRN)?
- Order of changes: per file (filter records by FRN) and volume-wide (sort by USN).
- Recent activity windows: which files were touched between T1 and T2.

Does not answer:
- **WHO.** No USN record version has a process/thread/image/user field. `SecurityId` is the file's security identifier, not an actor.
- **WHAT content.** Reason flags only (overwrite/extend/truncate); no bytes, sizes, or hashes.
- **WHY.** A delete by a program, the user, or Windows looks identical.
- **Complete history.** Ring buffer: old records are trimmed; journals can be deleted and re-created at will (verified, §3).

## 3. `$Max` metadata — USN_JOURNAL_DATA_V0 field layout

| off | size | field | meaning (verified) |
|---|---|---|---|
| 0 | 8 | `UsnJournalID` | journal identifier; assigned on creation; can be re-stamped during lifetime |
| 8 | 8 | `FirstUsn` | number of the first record that can be read |
| 16 | 8 | `NextUsn` | number of the next record to be written |
| 24 | 8 | `LowestValidUsn` | first record written in this journal instance; if `FirstUsn` < `LowestValidUsn`, the journal was re-stamped and a discontinuity exists (changes may be missing) |
| 32 | 8 | `MaxUsn` | largest USN the journal supports; near it, the journal must be deleted/re-created |
| 40 | 8 | `MaximumSize` | target maximum size (bytes); journal may grow beyond, then is trimmed at NTFS checkpoints when size exceeds `MaximumSize + AllocationDelta` |
| 48 | 8 | `AllocationDelta` | alloc/dealloc unit in bytes |

- Newer `USN_JOURNAL_DATA` revisions append fields after the V0 prefix. Read the 56-byte V0 prefix; parse extended fields only if a schema for them exists **(practical)**.
- Retention: "The NTFS file system may delete old records to conserve space." (verified) Trim happens at checkpoints in `AllocationDelta` units.
- Deletion: `FSCTL_DELETE_USN_JOURNAL` walks all files, resets USNs, deletes the journal; deletion persists across restarts; during it, read/create/modify fail with `ERROR_JOURNAL_DELETE_IN_PROGRESS` (verified).
- "Change journals are not necessarily created at startup. To create a change journal, an administrator may do so explicitly or start another service that requires a change journal." (verified) => **Absence of a journal or records is never evidence that nothing happened.**

## 4. USN_RECORD_V2 — layout

Records in `DeviceIoControl` output buffers are "aligned on 64-bit boundaries from the start of the buffer" (verified). Walk by `RecordLength`.

| off | size | field | notes |
|---|---|---|---|
| 0 | 4 | `RecordLength` | total record bytes incl. padding + name; use it to walk |
| 4 | 2 | `MajorVersion` | 2 = this layout; 3/4 select other layouts (verified table) |
| 6 | 2 | `MinorVersion` | 0 for 2.0. A minor bump means new fields may be inserted before the variable-length tail — never use compile-time offsets for the tail (verified) |
| 8 | 8 | `FileReferenceNumber` | file's NTFS file reference number (FRN) |
| 16 | 8 | `ParentFileReferenceNumber` | parent directory FRN at record time |
| 24 | 8 | `Usn` | this record's USN |
| 32 | 8 | `TimeStamp` | "standard UTC time stamp (FILETIME)" (verified) |
| 40 | 4 | `Reason` | bitmask, §7 |
| 44 | 4 | `SourceInfo` | bitmask, §8 |
| 48 | 4 | `SecurityId` | the file's security identifier |
| 52 | 4 | `FileAttributes` | GetFileAttributes-style (0x10 = directory, etc.) |
| 56 | 2 | `FileNameLength` | name length in **bytes** (UTF-16LE). Do not rely on a trailing `\0` (verified) |
| 58 | 2 | `FileNameOffset` | offset of name from record start; typically 60 for V2 |
| 60 | .. | `FileName` | UTF-16LE, `FileNameLength` bytes |

Parse rules **(practical, derived)**:
- Header is 60 bytes. Accept `RecordLength >= 60`, `RecordLength % 8 == 0` (alignment), `FileNameOffset >= 60`, `FileNameOffset + FileNameLength <= RecordLength`.
- Max record size: `(MaxComponentLength - 1) * sizeof(WCHAR) + header` (verified formula; ~570 bytes typical for NTFS `MaxComponentLength` 255).
- Decode name with `errors='replace'` and strip trailing NULs defensively.

## 5. USN_RECORD_V3 — differences

Same layout as V2 except the two file reference numbers are 128-bit (`FILE_ID_128`). Minimum: Windows 8 / Server 2012 (verified).

| off | size | field |
|---|---|---|
| 0 | 4 | `RecordLength` |
| 4 | 2 | `MajorVersion` (3) |
| 6 | 2 | `MinorVersion` |
| 8 | 16 | `FileReferenceNumber` |
| 24 | 16 | `ParentFileReferenceNumber` |
| 40 | 8 | `Usn` |
| 48 | 8 | `TimeStamp` |
| 56 | 4 | `Reason` |
| 60 | 4 | `SourceInfo` |
| 64 | 4 | `SecurityId` |
| 68 | 4 | `FileAttributes` |
| 72 | 2 | `FileNameLength` |
| 74 | 2 | `FileNameOffset` (76 for V3) |
| 76 | .. | `FileName` |

- "When range tracking is turned on, NTFS switches to producing only USN_RECORD_V3 records as output." (verified)

## 6. USN_RECORD_V4 — extent records

- Only produced when range tracking is on AND the file size is `>= RangeTrackFileSizeThreshold` (verified).
- No `TimeStamp` and no `FileName` fields exist in V4 (structural fact from the layout below).
- A run of V4 records for a file "is always followed by a USN_RECORD_V3 record with at least the USN_REASON_CLOSE flag set" (verified).

| off | size | field |
|---|---|---|
| 0 | 8 | `USN_RECORD_COMMON_HEADER` = `RecordLength`(4) + `MajorVersion`(2, =4) + `MinorVersion`(2) |
| 8 | 16 | `FileReferenceNumber` |
| 24 | 16 | `ParentFileReferenceNumber` |
| 40 | 8 | `Usn` |
| 48 | 4 | `Reason` |
| 52 | 4 | `SourceInfo` |
| 56 | 4 | `RemainingExtents` (0 = last V4 for this file) |
| 60 | 2 | `NumberOfExtents` |
| 62 | 2 | `ExtentSize` (size of one extent entry, bytes) |
| 64 | .. | `Extents[]` — each is a `USN_RECORD_EXTENT`: `Offset` (i64), `Length` (i64); 16 bytes each |

## 7. Reason flags (verified values)

| value | flag | meaning |
|---|---|---|
| 0x00000001 | `DATA_OVERWRITE` | data overwritten |
| 0x00000002 | `DATA_EXTEND` | data extended (appended) |
| 0x00000004 | `DATA_TRUNCATION` | data truncated |
| 0x00000010 | `NAMED_DATA_OVERWRITE` | named data stream overwritten |
| 0x00000020 | `NAMED_DATA_EXTEND` | named data stream extended |
| 0x00000040 | `NAMED_DATA_TRUNCATION` | named data stream truncated |
| 0x00000100 | `FILE_CREATE` | file/directory created for the first time |
| 0x00000200 | `FILE_DELETE` | file/directory deleted |
| 0x00000400 | `EA_CHANGE` | extended attributes (NTFS internal) changed |
| 0x00000800 | `SECURITY_CHANGE` | access rights changed |
| 0x00001000 | `RENAME_OLD_NAME` | renamed; record's name is the **previous** name |
| 0x00002000 | `RENAME_NEW_NAME` | renamed; record's name is the **new** name |
| 0x00004000 | `INDEXABLE_CHANGE` | `FILE_ATTRIBUTE_NOT_CONTENT_INDEXED` toggled |
| 0x00008000 | `BASIC_INFO_CHANGE` | attributes and/or **timestamps** changed |
| 0x00010000 | `HARD_LINK_CHANGE` | hard link added/removed |
| 0x00020000 | `COMPRESSION_CHANGE` | compression state changed |
| 0x00040000 | `ENCRYPTION_CHANGE` | encrypted/decrypted |
| 0x00080000 | `OBJECT_ID_CHANGE` | object identifier changed |
| 0x00100000 | `REPARSE_POINT_CHANGE` | reparse point changed/added/removed |
| 0x00200000 | `STREAM_CHANGE` | named stream added/removed/renamed |
| 0x00400000 | `TRANSACTED_CHANGE` | modified through a TxF transaction |
| 0x00800000 | `INTEGRITY_CHANGE` | integrity stream state changed (ReFS checksums) |
| 0x80000000 | `CLOSE` | file/directory closed |

Unused bits are reserved (verified).

## 8. SourceInfo flags (verified values)

| value | flag | meaning |
|---|---|---|
| 0x1 | `DATA_MANAGEMENT` | OS-initiated change (e.g. Remote Storage); data may not have changed from the user's point of view |
| 0x2 | `AUXILIARY_DATA` | private data stream operation (e.g. AV checksum); application data unchanged |
| 0x4 | `REPLICATION_MANAGEMENT` | change made to match another replica member |
| 0x8 | `CLIENT_REPLICATION_MANAGEMENT` | change made to match cloud content |

- "When a thread writes a new USN record, the source information flags in the prior record continue to be present only if the thread also sets those flags." (verified) — read SourceInfo per record; do not assume inheritance.

## 9. Change accumulation semantics — read this twice (verified)

- Reasons are "flags that identify reasons for changes that have **accumulated** ... since the file or directory **opened**."
- Same kind of change repeated => **no new record**: "If the same kind of change occurs more than once, the NTFS file system does not write a new record for the changes after the first."
- Worked example from the docs (one open session): write -> record `[DATA_OVERWRITE]`; set timestamp -> record `[DATA_OVERWRITE | BASIC_INFO_CHANGE]`; write again -> nothing; truncate -> `[DATA_OVERWRITE | BASIC_INFO_CHANGE | DATA_TRUNCATION]`; write -> nothing; close -> `[...| CLOSE]`.
- The final CLOSE record "represents a summary of changes to the file, but ... gives no indication of the order of the changes."
- After the session: "The next user to access and change the file generates a new USN record with a single reason flag."

Consequences:
- To ask "did change-kind K ever happen in this session": any record whose mask contains K.
- To ask "when did it first happen": the lowest USN whose mask contains K.
- **Never count occurrences** of a repeated action from record counts.
- Ordering is meaningful only **across** records (by USN), never within one record's mask.

## 10. Reading the journal

Live (administrator required):
- `fsutil usn queryjournal C:` — quick metadata (IDs and sizes).
- `fsutil usn readjournal C:` — dump; triage only. Do not treat its formatting as authoritative field semantics; parser output is the authority.
- Programmatic (volume handle `\\.\C:`, admin):
  - `FSCTL_QUERY_USN_JOURNAL` — journal metadata (§3 layout).
  - `FSCTL_ENUM_USN_DATA` — enumerates records "between two USNs"; in practice used to inventory current files (one record per allocated file) **(practical)**.
  - `FSCTL_READ_USN_JOURNAL` — selective read (reason mask, only-on-close, resume by returned USN).
  - Numeric control codes are defined in `tools/usn_parse.py`; live access requires validation on the target Windows version.
- FSCTL output buffers begin with **one 8-byte continuation value** (the USN of the next record to retrieve) before the first record (verified). It is not a record.

Offline (case folder with a captured `$J`):
- The raw `$J` stream is concatenated records with **no 8-byte continuation preamble** (deduction: the preamble exists only in FSCTL output buffers).
- Walk: `offset = 0`; read `RecordLength`/`MajorVersion`/`MinorVersion`; validate per-version bounds; emit; advance by `RecordLength`. On invalid data, **resync**: advance 8 bytes at a time until a plausible header (`Major` in {2,3,4}, `Minor == 0`, `RecordLength` >= minimum for version, `% 8 == 0`, within sane bound, name bounds valid). Report skipped/failed byte ranges honestly.
- Zero runs are sparse/trimmed space, **never records**.
- A capture may end mid-record (journal being written during capture): emit an `incomplete_tail` diagnostic; never guess fields.
- Sanity check: USN values are stream byte offsets (verified), so in a capture starting at stream position 0 a record's USN should equal its byte offset. Flag mismatches as anomalies **(practical)**.

## 11. Fact -> interpretation map

| Record says (fact) | Common interpretation (needs cross-check) |
|---|---|
| `FILE_CREATE` + name | object created; record time = shortly after creation completed |
| `FILE_DELETE` | an unlink happened; the record outlives the file; exact last-access/modification of the file is unknown |
| `RENAME_OLD_NAME` then `RENAME_NEW_NAME` pair | rename or move; equal parent FRNs => rename in place; different parents => moved between directories |
| `DATA_OVERWRITE/EXTEND/TRUNCATION` | at least one write happened in that session; window = first such record .. closing record |
| `BASIC_INFO_CHANGE` | attributes and/or timestamps changed — **possible timestomp; never proof alone**; cross-check `$SI`/`$FN` (see `mft.md`) |
| `CLOSE` | session boundary; record is a summary; internal order unknown |
| `SourceInfo = DATA_MANAGEMENT/AUXILIARY_DATA` | change may not reflect user-visible data modification |

## 12. Cross-validation hooks (implemented in `tools/validate.py`)

- FRN -> `$MFT` entry: existence, in-use flag, names, `$SI`/`$FN` timestamps. V2 FRN encodes MFT entry index + sequence number **(see `mft.md`)**; always compare the **full** FRN.
- Timestomp story: USN shows writes at T1..T2 while `$SI`/`$FN` claim older times => contradiction.
- Execution artifacts (Prefetch / Amcache / BAM): USN records for the image path inside the same window.
- Registry side effects (PendingFileRenameOperations, etc.) as an independent witness of file operations.

## 13. Agent Traps — never do these

1. **Never attribute** a change to a process, user, or program from USN data. No such field exists; doing so is fabrication.
2. Never treat each Reason flag as one event. Flags accumulate; repeats do not write records (§9).
3. Never read a `CLOSE` record as "only a close happened" — it summarizes the session.
4. Never order records by `TimeStamp`. Order by USN. Equal timestamps are normal.
5. Never assume the record's name is "the" file name — it is the name at that moment (old name on `RENAME_OLD_NAME`).
6. Never match files by MFT entry index alone; compare the full FRN (sequence included).
7. Never decode zero runs (sparse/trimmed) as records; never treat absence after `FirstUsn` as proof of no activity.
8. Absence of a journal/records is **absence of evidence, not evidence of absence** (§3).
9. Never claim V4 has a timestamp or a filename — it has neither.
10. USNs are per-volume and restart when a journal is re-created; never compare USNs across volumes or journal instances.
11. `SecurityId` is not an actor.
12. A record about a deleted file describes an event, not a present file. An unchanged in-use file may have no recent records at all.
13. `NAMED_DATA_*` flags refer to **named streams** (ADS), not the main data stream. No flag implies a size or content.
14. Never cite `fsutil` dump text as field semantics; schema'd parser output (`schemas/usn.schema.json`) is the authority.

## 14. Sources (fetched 2026-10-15)

- USN_RECORD_V2 / USN_RECORD_V3 / USN_RECORD_V4 — learn.microsoft.com (winioctl reference)
- USN_JOURNAL_DATA_V0 — learn.microsoft.com (winioctl reference)
- Change Journals / Change Journal Records / Walking a Buffer of Change Journal Records / Creating, Modifying, and Deleting a Change Journal — learn.microsoft.com (fileio)
