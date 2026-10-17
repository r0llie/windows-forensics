# Windows Registry Artifacts — Structure Card

Version 1.0 — based on libregf format documentation (J. Metz, rev 0.0.31), libyal winreg-kb artifact documentation (AppCompatCache, BAM, UserAssist, MRU, MUI cache, Typed paths), libyal dtformats AMCache format (rev 0.0.3), RegRipper `appcompatflags` plugin, Vortex Forensic Repository, and Microsoft documentation. Automated parser tests generate synthetic hives.

## 1. What it is

The Registry is Windows' hierarchical configuration database. Forensically it is a set of **hive files**, each a self-contained binary tree of keys and values:

| Hive file | Mounted as (live) | Typical forensic content |
|---|---|---|
| `%SystemRoot%\System32\config\SYSTEM` | `HKLM\SYSTEM` | Services, AppCompatCache (shimcache), BAM/DAM, PendingFileRenameOperations, mounted devices |
| `...\config\SOFTWARE` | `HKLM\SOFTWARE` | Installed software, Run keys, AppCompatFlags\Layers (machine-wide) |
| `...\config\SAM` | `HKLM\SAM` | Local accounts, group membership |
| `...\config\SECURITY` | `HKLM\SECURITY` | Cached credentials, policy secrets |
| `%UserProfile%\NTUSER.DAT` | `HKCU` | Per-user: UserAssist, MUICache, RunMRU, TypedPaths, AppCompatFlags\Layers |
| `%UserProfile%\AppData\Local\Microsoft\Windows\UsrClass.dat` | `HKCU\Software\Classes` | Shellbags, per-user file associations |
| `C:\Windows\AppCompat\Programs\Amcache.hve` | (standalone) | Amcache: executables/drivers metadata + SHA-1 |

Key forensic fact: **in an offline hive there is no `CurrentControlSet`** — that is a runtime link. To find the control set that was active, read `SYSTEM\Select\Current` (1 → `ControlSet001`). Parse all `ControlSet00N` keys present and say which one `Select\Current` points to.

## 2. regf container format (libregf doc)

- **File header** (512 bytes inside a 4096-byte header block): `"regf"` magic at 0; primary/secondary sequence number at 4/8 (mismatch = dirty hive, transaction logs not fully applied); last-written FILETIME at 12 (the hive's own "last change" time, UTC); major/minor format version at 20/24 (1.3 NT4+; 1.5 XP+; 1.6 Win10 docker); file type at 28 (0 = hive, 1/2/6 = transaction log variants); root key cell offset at 36; hbins data size at 40. Checksum at 508 = XOR-32 of previous 508 bytes.
- **Hive bins** start at file offset 4096. Each hbin: `"hbin"` magic, offset, size, 32-byte header.
- **Cells**: 4-byte signed size + data; negative = allocated, positive = free; 8-byte aligned. **All offsets inside the hive are relative to the start of the hive bin data area** (= file offset − 4096). File offset = `(bin_number + 1) * 4096`.
- **Cell types**: `nk` named key, `vk` value, `sk` security, `lf`/`lh`/`li`/`ri` sub key lists, `db` data block.
- **nk (v1.2+)** `CM_KEY_NODE`: flags u16 @2 (0x20 = KEY_COMP_NAME → name is ASCII/Latin-1, else UTF-16LE; 0x0004 = root key); last-written FILETIME @4; parent offset @16; subkey count @20; subkey list offset @28; values count @36; values list offset @40; class name offset @48; max sizes @52..64; name size @72; name @76 (not NUL-terminated). **Key LWT is the time the key (or any of its values) last changed — not the time the recorded event happened.**
- **vk (v1.2+)** `CM_KEY_VALUE`: name size u16 @2 (0 = "(Default)"); data size u32 @4; data offset @8; type @12; flags @16 (0x1 = name is ASCII). Name @20.
  - **Inline data**: if MSB (0x80000000) of data size is set, the real size is `size & 0x7FFFFFFF` and the data lives in the 4-byte data offset field (sizes 1–4 use the low bytes). Size 0 = value not set.
  - **Big data**: values larger than 16344 bytes in format 1.5+ are split into `db` segments — the data offset points to a `db` cell (`"db"`, segment count u16 @2, segment list offset u32 @4), whose entries are cell offsets of the segment data. A naive reader returns garbage or misses data on the AppCompatCache value (multi-MB on real systems).
- **Sub key lists**: `lf`/`lh` = 8-byte elements (nk offset + name hash); `li` = 4-byte nk offset; `ri` = 4-byte offset of *another* list cell (indirection — resolve recursively). Mixed nesting is legal.
- **Values list**: array of 4-byte vk offsets, count from nk.
- **Value types**: 1 REG_SZ, 2 REG_EXPAND_SZ, 3 REG_BINARY, 4 REG_DWORD (LE), 5 REG_DWORD_BE, 6 REG_LINK, 7 REG_MULTI_SZ, 11 REG_QWORD. REG_MULTI_SZ = UTF-16LE strings NUL-separated, double-NUL terminated — **the trailing terminator is not always present**.
- Prefer hives obtained via `reg save` (clean, logs applied) over raw file copies of in-use hives (may be dirty; our parser detects sequence-number mismatch and warns instead of guessing).

## 3. AppCompatCache (Shimcache) — execution-ish cache

- **SYSTEM hive**, value `AppCompatCache` under `ControlSet00N\Control\Session Manager\AppCompatCache`. Value data is a versioned blob; **first u32 selects the format**:

| Signature (u32 @0) | Format | Parsed by this skill |
|---|---|---|
| 0xDEADBEEF | XP / 2003 64-bit | no (honest error) |
| 0xBADC0FFE | 2003 / Vista / 2008 | no (honest error) |
| 0xBADC0FEE | 7 / 2008 R2 | no (honest error) |
| 0x00000080 (header) + `"00ts"` entries at 0x80 | 8.0 | yes |
| 0x00000030 (header size) + `"10ts"` | 10 | yes |
| 0x00000034 (header size 52) + `"10ts"` | 10 Creator+/11 | yes ("Win10c-11" variant) |

- **Windows 10/11**: u32 @0 = 48 (or 52 on Creator+) = offset of first entry; number of entries u32 @36 (48-byte) / @40 (52-byte). Entry ("10ts"): signature @0; unknown u32 @4; cache entry data size u32 @8 (bytes after the 12-byte header); path size u16 @12; path @14 (UTF-16LE, no terminator); last modification FILETIME; data size u32; data. **No insertion flags in the Win10 entry** (flags exist only in 2003/Vista/7/8 formats). **Caution:** on Windows 10/11 the count field may be a lifetime counter rather than the current entry count. Walk entries to the end of the value; never trust the count as an upper bound or a truncation target.
- **Windows 8.x** entries (`"00ts"`/`"10ts"`): 12-byte header, path, insertion flags u32, shim flags u32, unknown u16 (8.1), last modification FILETIME, data size, data.
- The Windows 7 header is 128 bytes (`0xBADC0FEE`, size field 120 @8); XP/2003/Vista have their own headers/LRU arrays (see sources).
- Entry LWT semantics: **the cache records files the compatibility engine saw; on Win8+ mere presence does NOT prove execution** — entries can be populated by `CreateProcess` attempts and pushed by other activity. Treat as "file was touched/seen by apphelp"; cross-check execution claims with Prefetch/BAM/USN.
- The value can be megabytes → can be stored as big data (`db` segments). Implement segment assembly.
- The cache persists across reboots (until flushed); `ShimFlushCache` (rundll32 apphelp.dll) can clear it — like all registry evidence, deletion/absence proves nothing.

## 4. Amcache — executable/driver metadata + hashes

- Standalone hive `C:\Windows\AppCompat\Programs\Amcache.hve` (Win8+; Win7 used `RecentFileCache.bcf`). Root key name: `{11517B7C-E79D-4e20-961B-75A811715ADD}`, sub key `Root`.
- **Modern (Win10 1709+): `Root\InventoryApplicationFile`** — one subkey per executables seen by the inventory: name = `%NAME%|%IDENTIFIER%`. Values (all REG_SZ unless noted):

| Value | Meaning |
|---|---|
| `FileId` | `"0000"` + SHA-1 (40 hex) of **first 31,457,280 bytes (30 MiB)** — prefix hash, not full-file for big files |
| `ProgramId` | links to `InventoryApplication` program entry (may not exist there = unassociated) |
| `LowerCaseLongPath` | full path (lower-cased) |
| `Name` | file name (original case) |
| `LongPathHash` | `name|hash_fragment` (key-name style, unrelated to content hash) |
| `Publisher`, `ProductName`, `ProductVersion`, `BinFileVersion`, `BinProductVersion`, `Version` | PE metadata |
| `BinaryType` | e.g. `pe32_i386`, `pe32_amd64` |
| `LinkDate` | PE link timestamp, string e.g. `"07/11/2021 06:58:40"` |
| `Size` (REG_QWORD), `Language` (REG_DWORD, LCID), `Usn` (REG_QWORD) | size / language / USN journal id |

- **`Root\InventoryApplication`** — one subkey per ProgramId: `Name`, `Publisher`, `Version`, `RootDirPath`, `InstallDate` (string), `Source` (AddRemoveProgram / Msi / AppxPackage / File), `UninstallString`, `RegistryKeyPath`, `MsiPackageCode`, `MsiProductCode`; key-value `LastScanTime` (FILETIME), `ProviderSyncId`.
- **Legacy (Win8–10 pre-1709): `Root\File\<volume GUID>\<identifier>`** — identifier = `%SEQ%0000%MFT-entry-hex%` (e.g. `100001605a` = NTFS MFT entry 90202, sequence 1). Values are named with hex numbers: 0 product name, 1 company, 2/5 versions, 3 language, 6 file size, 7 PE image size, 9 checksum, c description, d image version, f link date (POSIX u32), 11 modification FILETIME, 12 creation FILETIME, 15 path, 100 ProgramId, 101 SHA-1 (`0000` + 40 hex).
- **`Root\Programs\<id>`** (old format): 0 name, 1 version, 2 publisher, 6 source, 7 uninstall paths, a install (POSIX), b uninstall (POSIX), d install dirs, `Files` = `%VOLUME_GUID%@%FILE_REFERENCE%` references.
- **Timestamp semantics (critical)**: on the **legacy `File` key**, the subkey LWT ≈ execution or install time. On **`InventoryApplicationFile`**, the subkey LWT = **the last run of the Microsoft Compatibility Appraiser task**, NOT execution. Do not date execution from it; use LinkDate (compile time) or other artifacts.
- **`LinkDate` format trap**: `InventoryApplicationFile` LinkDate is a REG_SZ string in CRT format `MM/DD/YYYY HH:MM:SS` (always US-style — the appraiser writes it, not the user locale; do not parse with locale rules). `reg_parse.py` normalizes it to `link_date_ts` (ISO 8601 UTC) and keeps the raw string in `link_date`. Values outside `1990 .. 2038-01-19T03:14:07Z` (the signed 32-bit PE-stamp ceiling) get a warning and `link_date_ts: null`; malformed or hash-derived PE timestamps can fall outside this range. They are not host-event times and must not enter a timeline. The legacy `File` key's value `f` is a POSIX u32 instead (also exposed as `link_date_ts`).
- FileId prefix hash limits: files >30 MiB yield a prefix hash; VirusTotal/NSRL matching still works for ≤30 MiB (most binaries). Strip the `0000` before lookups.

## 5. BAM / DAM — per-user last execution

- **SYSTEM hive**: `ControlSet00N\Services\bam\State\UserSettings\<SID>` (Win10 1809+, Win11) and `...\bam\UserSettings\<SID>` (Win10 1709–1803, may retain stale entries on upgraded systems). DAM mirrors under `Services\dam[\State]\UserSettings\<SID>` (populated mainly on Modern Standby devices).
- Each SID key holds one value per executable: **value name = kernel device path** (`\Device\HarddiskVolume3\...exe`) or UWP package family name; **value data**: FILETIME execution time @0 (8B), 8B empty @8, "Windows app" flag @16 (u32), constant 0x00000002 @20. Value data is 24 bytes.
- Per-SID metadata values `Version` and `SequenceNumber` (REG_DWORD) are bookkeeping — **not executables** (skip; do not report as runs).
- Retention ≈ **7 days** (boot-time cleanup; BAM writes on process start and active-time updates). Absence ≠ never ran (older than ~7 days, cleanup on boot, network/removable shares frequently not recorded — though device paths for removable media *can* appear).
- BAM/DAM give user attribution (SID) — one of the few execution artifacts that do.

## 6. UserAssist — Explorer-launched programs

- **NTUSER.DAT**: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`. Per-GUID `Version` (REG_DWORD): 3 = 2000/XP/2003/Vista; 5 = 2008/7/8/. Likely-still-5 on 10/11.
- Value names are **ROT13-obfuscated** (ASCII `[A-Za-z]` only; digits/others untouched): e.g. `HRZR_EHACNGU:P:\...` → `UEME_RUNPATH:C:\...`. Known value-name prefixes: `UEME_RUNPATH` executed programs, `UEME_RUNPIDL` shortcut-launched, `UEME_RUNCPL` control-panel applets, `UEME_RUNWMCMD` Run-command, `UEME_UI*` shell (quick launch/desktop/toolbar). `UEME_CTLSESSION` = session metadata (not a program) — skip and note. **Modern Win10/11 `{CEBFF5CD}` keys also hold non-`UEME_` names**: plain executable paths (`C:\...\tool.exe`), CLSID-prefixed paths (`{GUID}\mspaint.exe`), UWP AppUserModelIDs (`Microsoft.WindowsCalculator_8wekyb3d8bbwe!App`), URI launches (`steam://...`) — treat these as opaque strings; only `UEME_xxx:` names carry a kind/target split.
- Entry data (48–72 bytes): **v3** = session id u32 @0, run count u32 @4, last run FILETIME @8 (16B total). **v5** (72B) = unknown u32 @0 (0/-1/1), run count u32 @4, focus count u32 @8, focus time u32 @12 (**milliseconds**; can be -1), 10 floats @16..56 (last 10 focus times, ~0.0/-1.0 unset), unknown u32 @56, **last run FILETIME @60**, 4B zero @68.
- Interpretation: only proves programs launched **via Explorer** (Start menu, Run dialog, double-click). Count is per-user; last run is the strongest field. Deleted/corrupted entries tell no story by themselves.
- UserAssist GUID → activity mapping is only partly documented (winreg-kb lists known GUIDs and Windows versions); `{CEBFF5CD-...}` ≈ executable/file execution, `{F4E57C4B-...}` ≈ shortcut execution (both "assumed").

## 7. MUICache — friendly names from Explorer

- **NTUSER**: Vista+ `HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache`; XP/2003 `HKCU\Software\Microsoft\Windows\ShellNoRoam\MUICache`. In `UsrClass.dat` the hive root **is** `HKCU\Software\Classes`, so the hive-relative path is `Local Settings\Software\Microsoft\Windows\Shell\MuiCache`.
-**Value names**: full path to executable (Vista+ often with `.FriendlyAppName` suffix). **Data**: friendly display name (a string, frequently `"@file,-id"` form or `"Application"`). Records that Explorer has seen the file (open/launch); **no timestamps** in the modern key. Rebuilt by Explorer — long-lived but fragile.

## 8. RunMRU — Run dialog history

- **NTUSER**: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`.
- `MRUList` value = UTF-16LE letters (e.g. `"bca"`) in most-recent-first order; the rest are letter-named values whose data is the typed command string (UTF-16LE). `a` = first entry ever, letters cycle. Records what was **typed into the Run dialog** (a re-type of an existing command appears once, moved to front of MRUList).
- RunMRU was notably abused: `cmd /k ...` entries are programmatic (from RunMRU abuse) vs interactively typed commands. Treat as user-attributed (HKCU).

## 9. TypedPaths — Explorer address bar history

- **NTUSER**: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths`; values `url1..urlN` (REG_SZ), most recent first in practice. Paths typed into the Explorer address bar.

## 10. AppCompatFlags\Layers — compatibility shims applied

- **NTUSER**: `HKCU\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers`; also machine-wide `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers` (+ `Wow6432Node` variants for 32-bit views).
- **Value name = full path to the executable; data = shim string**, e.g. `~ WIN7RTM`, `~ RUNASADMIN`, `~ WINXPSP3 RUNASADMIN` (`~` = user-set flag). `RUNASADMIN` = explicit run-as-administrator marker (privilege-interest signal). Key LWT ≈ when shims were last set.
- Related (backlog): `...\AppCompatFlags\Compatibility Assistant\Persisted` (programs the PCA interacted with; per-value binary contains a FILETIME at offset 0x2C per RegRipper) and `...\Store` (PCA lookup table, opaque).

## 11. PendingFileRenameOperations — scheduled rename/delete at next boot

- **SYSTEM hive**: `ControlSet00N\Control\Session Manager\PendingFileRenameOperations`, REG_MULTI_SZ. Every two strings form one operation (MoveFileEx with `MOVEFILE_DELAY_UNTIL_REBOOT`):
  - `szSrc \0 szDst` → rename/move `src` → `dst` at next boot
  - `szSrc \0 ""` (empty second string) → **delete `src`** at next boot
- Paths are typically prefixed `\??\` (NT object namespace) and refer to the `\Device\HarddiskVolumeN` form. Boolean evaluation trap: an empty destination string is what distinguishes **delete** from rename; an odd-length list (missing second element) must be reported as malformed, not guessed.
- This is a **future-tense intent**, not evidence of past activity: writers include installers (patch/AV replacement of locked files) and malware (self-delete on reboot). Operations execute early in the boot process, before programs can lock files. After the next boot the value is usually consumed — a **non-empty value at acquisition time implies "these operations were pending at capture"** (great for correlating "file was replaced around reboot" with USN/MFT).

## 12. Cross-validation pointers

- Execution story: Prefetch (image load, count, ≥8 last runs) + **BAM/DAM** (last run, per-SID) + **UserAssist** (Explorer launches, count) + **Amcache** (existence, SHA-1, compile date) + **AppCompatCache** (touched) + USN (file events). Disagreements are findings, not tool failures.
- File replacement at reboot: PendingFileRenameOperations ↔ USN/MFT events just after boot; `SET*.tmp`/`_*.tmp` companions.
- Device paths (`\Device\HarddiskVolumeN` in BAM, AppCompatCache) can be resolved via SYSTEM `MountedDevices` (backlog).
- Amcache SHA-1 ↔ file hashes from disk images / VirusTotal (strip `0000`; remember 30 MiB prefix limit).
- Key LWT values are supporting timestamps; the artifact-specific timestamp fields (FILETIMEs inside value data) are the primary ones.

## 13. Agent Traps (LLM pitfalls)

1. **"CurrentControlSet exists in the hive."** It does not — offline you must read `SYSTEM\Select\Current` and use/name `ControlSet00N` explicitly.
2. **Dating executions from `InventoryApplicationFile` key LWT.** That's the Compatibility Appraiser run time. (Legacy `Root\File` LWT is closer to install/execution.)
3. **Comparing Amcache `FileId` directly to a full-file SHA-1 for files >30 MiB.** It's a prefix hash of the first 30 MiB; and keep the `0000` type tag out of external lookups.
4. **Reporting BAM `Version`/`SequenceNumber` values as executed programs.** They are metadata under each SID key.
5. **BAM presence after deletion.** Entries survive executable deletion until a later boot cleanup; equally, absence may just mean >7 days old. Never "BAM proves it ran recently" without retention awareness.
6. **Treating Shimcache presence as proof of execution (Win8+).** It's "seen by apphelp"; Windows 7-era semantics ("present = executed") do NOT carry over. No insertion flags in Win10 entries either.
7. **Reading UserAssist names raw.** Names are ROT13; `UEME_RUNPATH:` etc. appear only after de-obfuscation, and `UEME_CTLSESSION` is not a program.
8. **UserAssist run count = process executions.** It counts Explorer-initiated launches (and per user), not every process start; focus time is milliseconds (u32, can be -1).
9. **MRU letter order.** In `MRUList`, the first character is the MOST recent; values are letter-named. For `MRUListEx` keys the entries are 4-byte ints terminated by 0xffffffff — different scheme; don't mix them up.
10. **PendingFileRenameOperations off-by-one.** Even indices are sources, odd are destinations; empty destination = delete. A missing trailing NUL terminator (common) must not produce a phantom operation — validate pair alignment and report odd tails.
11. **Assuming the value data is always in a cell.** Small values (≤4 bytes) are inline in the vk record; >16344-byte values (AppCompatCache!) are `db` segment chains. Reading the first 16344 bytes of a big value "works" and silently truncates.
12. **Offsets relative to file start.** Cell offsets are relative to the **hive bin data area** (file offset − 4096). Forgetting the 4096 shift misreads everything by one page.
13. **`lf` vs `lh` vs `li` vs `ri`.** All are subkey lists; `ri` contains offsets of *other lists* (an indirection layer). A parser that assumes "list elements are keys" misses half the keyspace on large keys.
14. **Hive dirty state.** Mismatched primary/secondary sequence numbers = transaction logs not applied; `reg save` output is clean. Parsing a dirty hive can silently lose recent changes (e.g. last-run values).
15. **Trusting hive timestamps as event times.** Key LWT = last key write; it changes when *any* value under it changes and is not the event time. Use artifact-internal FILETIMEs.
16. **"The user did not run it, UserAssist says so."** UserAssist/MUICache/RunMRU/TypedPaths are per-user (NTUSER); processes not launched via Explorer (services, console-spawned) never appear. Conversely these hives are user-writable — tampering is possible (cross-check USN of NTUSER.DAT).
17. **MUICache as timeline evidence.** It has no timestamps; use it for existence/friendly-name, not time.
18. **Registry-wide deletion.** An attacker with SYSTEM/admin can delete keys (e.g. clear BAM SID key). Absence in one artifact is never a conclusion — compare multiple artifacts (golden rule).
19. **Case-sensitivity and backslash assumptions.** Registry key names are case-insensitive; values may be ASCII or UTF-16 (nk/vk flag 0x20/0x1); paths in values mix `\Device\HarddiskVolumeN`, `\??\`, `\VOLUME{GUID}` forms. Normalize before comparing across artifacts, and quote verbatim in findings.

## 14. Sources

- libregf — Windows NT Registry File (REGF) format (J. Metz), rev 0.0.31 (May 2026): header/hbin/cells/nk/vk/data blocks/corruption — https://github.com/libyal/libregf/blob/main/documentation/Windows%20NT%20Registry%20File%20(REGF)%20format.asciidoc — retrieved 2026-10-15.
- libyal winreg-kb: Application compatibility cache (`docs/sources/system-keys/Application-compatibility-cache.md`), Background activity moderator, User assist, Most recently used, MUI cache, Typed paths — https://github.com/libyal/winreg-kb — retrieved 2026-10-15.
- libyal dtformats — AMCache file (AMCache.hve) format (J. Metz), rev 0.0.3 (2022) — https://github.com/libyal/dtformats — retrieved 2026-10-15.
- Mandiant / Eric Zimmerman's AmcacheParser / Psmths Windows Forensic Handbook / DFIR Handbook — FileId and InventoryApplicationFile semantics (30 MiB prefix SHA-1, `0000` tag, appraiser-run LWT) — retrieved 2026-10-15.
- RegRipper `appcompatflags` plugin (H. Carvey, 2013) + Vortex Forensic Repository `AppCompatFlags` — Layers key paths incl. Wow6432Node and Compatibility Assistant Persisted/Store — retrieved 2026-10-15.
- Microsoft Learn: MoveFileEx / PendingFileRenameOperations (Win2000 technet archive) + Sysinternals PendMoves — pair semantics, empty destination = delete at boot — retrieved 2026-10-15.
- Belkasoft BAM/DAM analysis + windowsforensics.app cheat sheet + SecurityRonin bam-forensic — BAM/DAM key paths per Windows build, 7-day retention, Version/SequenceNumber metadata, FILETIME@0 — retrieved 2026-10-15.
- Didier Stevens UserAssist research (via winreg-kb citations) — ROT13, UEME_ prefixes — retrieved 2026-10-15.

Do not edit layouts from memory; update only with a cited source.
