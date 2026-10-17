# Windows Event Logs (EVTX) — Structure Card

Version 1.0 — based on libevtx format documentation (J. Metz, rev 0.0.37), Microsoft documentation for `wevtutil`, event schemas and audit policy, and published event-ID references. Automated tests use generated XML examples.

## 1. What it is

Windows records security-relevant and operational events into channel-based logs stored as `.evtx` files under `C:\Windows\System32\winevt\Logs\`. One file per channel (rotated content may land in `<name>.evtx.old`). Typical files:

| .evtx file | Channel | Content and forensic value |
|---|---|---|
| `Security.evtx` | `Security` | Logons (4624/4625), process creation (4688, if audited), account/group changes, log-clear (1102), service installs (4697), explicit credentials (4648). **Admin rights required to read (live or offline file needs ACL bypass).** |
| `System.evtx` | `System` | Service lifecycle (7045/7036/7040), shutdown/boot (1074/6005/6006/6008/6013), Kernel-Power 41, BugCheck 1001, PnP driver installs. |
| `Application.evtx` | `Application` | App crashes (1000/1001 WER), some installers. |
| `Microsoft-Windows-Windows Defender%4Operational.evtx` | `Microsoft-Windows-Windows Defender/Operational` | Defender detections (1116/1117), protection tampering (5001/5007). **%4 in filenames = "/"** escaped. |
| `Microsoft-Windows-TaskScheduler%4Operational.evtx` | `.../Operational` | Task registered (106), updated (140), deleted (141), action start/complete (200/201). **Off by default** (must be enabled). |
| `Microsoft-Windows-PowerShell%4Operational.evtx` | `.../Operational` | Script block logging (4104), module logging (4103) — **must be enabled** (registry/policy). |
| `Windows PowerShell.evtx` | `Windows PowerShell` | Classic engine log: 400/403 engine life, 500/501 command life, 600 provider load. On by default but minimal without transcription. |
| `Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx` | `.../Operational` | RDP session 21/22/23/24/25. |
| `Microsoft-Windows-WMI-Activity%4Operational.evtx` | `.../Operational` | WMI activity (5857–5861), useful for lateral movement. |
| `Microsoft-Windows-CodeIntegrity%4Operational.evtx` | `.../Operational` | Driver/image load violations 3004/3033. |

Key forensic facts:
- **Presence in these logs proves the logged action happened** (the OS wrote it). Absence proves **nothing**: logs wrap (circular overwrite), can be cleared, can be disabled, and many events require audit policy to exist at all.
- Log retention is set per channel (`wevtutil gl Security`): default Security = 20 MB (Win10/11 client), "Overwrite events as needed" — oldest records die silently, **no event marks that**. Full free space? When a log cannot overwrite and cannot grow, the whole log is disabled.
- Record timestamps are UTC (100-ns resolution); GUIs render local time.

## 2. EVTX binary format (v1 uses OS export; binary parse is backlog)

Brief structure so you can honestly reject/triage `.evtx` files without misreading them:

- File header 4096 bytes: magic `"ElfFile\x00"` @0; first/last chunk numbers; next record ID @24; header size @32; minor/major version @36/40; header block size @44; chunk count @48; flags @120; CRC32 @124.
- Chunks of 64 KiB (0x10000), magic `"ElfChnk\x00"`; first/last record numbers; first/last record IDs; header size 512; last record data offset; CRC32s; final chunk size @48; strings table at record-data end; chunk ends with 128-byte `0x83..` template.
- Records: 4-byte magic `0x00002a2a` (bytes `2a 2a 00 00`), size @4, record ID @8, FILETIME-ish written time @16, then BinXML token stream.
- **A file that starts with `ElfFile` is binary EVTX.** `wevtutil` must convert it (`wevtutil qe <file.evtx> /f:xml /lf:true`) — the v1 parser handles the XML form only and must say so.

## 3. Collecting (wevtutil recipes)

```bat
wevtutil el                                   :: list all channels
wevtutil gl  Security                         :: get config (enabled, retention, maxSize)
wevtutil gli Security                         :: get info: file size, record count, oldest record number
wevtutil qe  Security /f:xml /rd:false /c:0   :: dump ALL events as XML (oldest first; /c:0 = all... use /c:N to cap)

:: targeted query (XPath), newest first:
wevtutil qe System /f:xml /rd:true /c:100 /q:"*[System[(EventID=7045)]]"

:: export channel (binary) and query it offline later:
wevtutil epl System C:\case\System.evtx
wevtutil qe  C:\case\System.evtx /f:xml /lf:true /rd:false
```

- Security (and querying live Security) requires an **admin/privileged** session; System/Application are readable by users.
- **Caution — two different counters:** `gli` shows both `numberOfLogRecords` and `oldestRecordNumber`; the latter does **not** necessarily equal the `EventRecordID` of the oldest exported event. `oldestRecordNumber` is a per-file sequence counter, `EventRecordID` the channel-level record ID. Never compare them against each other; validate `EventRecordID` continuity within one export instead.
- `epl` output is binary EVTX; `qe /f:xml` output is a sequence of standalone `<Event>` elements (often no shared root or XML declaration). Both are useful — collect with `qe /f:xml` for direct parsing, `epl` for evidence-grade copies. **Encoding:** `qe` writes in the console codepage (raw-redirect it with `>`; UTF-8 decode fails on non-ASCII content and falls back to cp1254/cp857 — the parser does this automatically and says which encoding it used).
- Offline parsing of a copied `Security.evtx` requires bypassing the restrictive file ACL (administrators) — even as admin the ACL applies; `takeown`/`icacls` or reading via a tool as admin usually suffices on the copy.

## 4. XML record anatomy

```xml
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-...}"/>
    <EventID>4624</EventID>                      <!-- may carry Qualifiers attr on classic providers -->
    <Version>2</Version>
    <Level>0</Level>                             <!-- 0 LogAlways 1 Critical 2 Error 3 Warning 4 Information 5 Verbose -->
    <Task>12544</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8020000000000000</Keywords>      <!-- 0x8020... = Audit Success, 0x8010... = Audit Failure -->
    <TimeCreated SystemTime="2024-01-15T09:00:00.1234567Z"/>   <!-- UTC, 100-ns digits -->
    <EventRecordID>184467</EventRecordID>        <!-- per-channel monotonic; restarts after clear -->
    <Correlation ActivityID="{...}" [RelatedActivityID="{...}"]/>
    <Execution ProcessID="1234" ThreadID="5678"/> <!-- IDs of the thread that logged, NOT the subject process -->
    <Channel>Security</Channel>
    <Computer>DESKTOP-XXXX</Computer>
    <Security UserID="S-1-5-18"/>                <!-- account context that emitted the event -->
  </System>
  <EventData>
    <Data Name="SubjectUserSid">S-1-5-21-...</Data>
    <Data Name="TargetUserName">sample-user</Data>
    ...
  </EventData>
  <!-- OR, for some providers: -->
  <UserData>
    <EventXML xmlns="...provider-specific..."> <Param1>...</Param1> ... </EventXML>
  </UserData>
</Event>
```

- **EventData vs UserData**: Security-Auditing and most modern providers use `<EventData>`; a minority (older/manifestless, e.g. some WER/Update events) use `<UserData>` with a provider-specific nested schema. Inside `EventData`, children are usually named `<Data Name=...>`, but `<Binary>` children carrying raw hex payloads also occur; entries with no `Name` attribute must be preserved positionally.
- `Execution\ProcessID` is the logging thread's PID, in **hex** in the XML — not the process an event is about.
- `EventRecordID` is per channel. For fusion/timeline use `(channel, EventRecordID)` as identity; after `wevtutil cl` or a detected clear, IDs restart low.

## 5. Critical event ID map

### 5.1 Log integrity / anti-forensics

| ID | Channel | Meaning |
|---|---|---|
| 1102 | Security | **Audit log was cleared** — typically includes who (`SubjectUserName`/Sid) and when. Written INTO the fresh log; usually near the first record. |
| 104 | System | System log was cleared (source `EventLog`, provider Microsoft-Windows-Eventlog). |
| 1100 / 1101 | Security | Event logging service shut down / audit events dropped (buffer full or transport failure). |
| 6005 / 6006 | System | Event Log service started / stopped (6006 = clean shutdown). |
| 6008 | System | Unexpected shutdown (did not reach clean 6006). |
| 41 | System (Kernel-Power 0x8000000000000020) | Kernel power loss / hard reset (can be bugcheck without crashdump). |
| 1001 | System (BugCheck) | BSOD, with bugcheck code + dump presence. |
| 6013 | System | System uptime interval (daily), seconds. |

### 5.2 Authentication (Security channel)

| ID | Meaning |
|---|---|
| 4624 | Successful logon. **`LogonType`**: 0 System, 2 Interactive (console), 3 Network (SMB/RPC — very noisy), 4 Batch (scheduled task), 5 Service (SYSTEM services), 7 Unlock, 8 NetworkCleartext (IIS basic auth), 9 NewCredentials (runas /netonly), 10 RemoteInteractive (RDP), 11 CachedInteractive (cached creds, no DC contact). Fields: TargetUserSid/Name, IpAddress, WorkstationName, LogonProcessName, AuthenticationPackage, LmPackageName, ImpersonationLevel. |
| 4625 | Failed logon. Reason in **`SubStatus`** (Status is generic 0xC000006D): 0xC000006A bad password, 0xC0000064 no such user, 0xC0000234 account locked, 0xC0000072 disabled, 0xC0000193 expired, 0xC000015B logon-type not granted. |
| 4634 / 4647 | Logoff (logon ended / user-initiated). |
| 4648 | Logon attempted **with explicit credentials** (runas, scheduled task credentials, PsExec-like). Subject = caller in logs, Target = account used. |
| 4672 | Special privileges assigned to new logon — administrative login indicator (noisy for SYSTEM/service logons). |
| 4776 | NTLM credential validation (Workstation: local SAM; DC: cached). Many failures = password guessing against NTLM. |
| 4771 | Kerberos pre-auth failed (domain). |
| 4719 | Audit policy changed (which subcategory, by whom). |

### 5.3 Accounts & groups (Security channel)

| ID | Meaning |
|---|---|
| 4720 / 4722 / 4724 / 4725 / 4726 | User account created / enabled / password reset attempted / disabled / deleted. |
| 4728 / 4732 / 4756 | Member added to global / local / universal security group (4756 Universal). |
| 4738 | User account changed (flags etc.). |
| 4740 | Account locked out. |

### 5.4 Process & execution

| ID | Channel | Meaning |
|---|---|---|
| 4688 | Security | Process created. **Requires "Audit Process Creation"**. `NewProcessId`/`ProcessId` are **hex** in XML; inspect the actual EventData key for command-line data (often `CommandLine`). It may be empty unless policy **"Include command line in process creation events"** is enabled. |
| 4689 | Security | Process exited (same audit). |
| 4657 | Security | Registry value modified (requires "Audit Registry" on the key; rarely on). |
| 4697 | Security | A service was installed — also requires its audit subcategory; 7045 (System) is the more reliable twin. |

### 5.5 Services & system lifecycle (System channel)

| ID | Meaning |
|---|---|
| 7045 | Service installed (SCM): ServiceName, ImagePath, ServiceType (user-mode/kernel driver), StartType (2 auto-start, 3 demand, 0 boot, 1 system). **Always on.** Prime persistence evidence. |
| 7040 | Service start type changed (e.g. disabled by attacker, or by defender). |
| 7036 | Service running/stopped (very chatty — use for timeline windows, not per se). |
| 7034 | Service crashed unexpectedly. |
| 1074 | Shutdown/restart initiated — includes **initiating process image and user** (User32). |
| 1000 | Application Error: faulting app + module + path (Application channel). |
| 1001 | WER report (Application) — different 1001 from System BugCheck. Context matters: provider + channel disambiguate. |

### 5.6 Scheduled tasks

| ID | Channel | Meaning |
|---|---|---|
| 106 / 140 / 141 | TaskScheduler/Operational | Task registered / updated / deleted — includes task name and often the author (`UserContext`). **Operational log off by default.** |
| 200 / 201 | TaskScheduler/Operational | Action started / completed (execution evidence while enabled). |
| 4698 / 4699 / 4700 / 4701 / 4702 | Security | Task created / deleted / enabled / disabled / updated — require "Audit Other Object Access Events". |

### 5.7 PowerShell

| ID | Channel | Meaning |
|---|---|---|
| 400 / 403 | Windows PowerShell | Engine started / stopped (with HostApplication — full command line of powershell.exe!). |
| 500 / 501 | Windows PowerShell | Command invocation started / stopped (InvocationInfo; 500 may carry the command text in older versions). |
| 4103 | PowerShell/Operational | Module logging: pipeline execution details (needs enablement). |
| 4104 | PowerShell/Operational | **Script block logging** — full deobfuscated script text (needs enablement; highly valuable). |
| 4105 / 4106 | PowerShell/Operational | Script run start / stop. |

### 5.8 Defender, RDP, WMI

| ID | Channel | Meaning |
|---|---|---|
| 1116 | Defender/Operational | Malware/possibly unwanted software detected (severity, threat name, path, action). |
| 1117 | Defender/Operational | Action taken on threat (quarantine/remove...). |
| 5001 | Defender/Operational | Real-time protection disabled (tampering!). |
| 5007 | Defender/Operational | Defender configuration changed (who/what key). |
| 21 / 22 / 23 / 24 / 25 | TS-LocalSessionManager/Operational | RDP session logon success / shell start / logoff / disconnected / reconnect. |
| 1149 | TS-RemoteConnectionManager/Operational | RDP network authentication succeeded (user + source IP). |
| 5857 / 5858 / 5859 / 5860 / 5861 | WMI-Activity/Operational | Provider load / operation / error / temporary error / permanent error — WMI abuse (remote execution via Win32_Process.Create etc.). |

## 6. Interpretation rules

- **Audit policy dependency must be stated** for every event class: 4688/4689/4648/4697/4698–4702 + 4624's detail level depend on advanced audit policy (default on client for Logon: yes; Process Creation: **off** by default). Defender/RDP operational logs: on by default. TaskScheduler/Operational: off. PowerShell/Operational: off.
- A 4624 with `LogonType=3` and `LogonProcessName=NtLmSsp`/`Kerberos` is normal background noise; humans are usually 2/7/10/11.
- 7045 `StartType=2` (auto) + ImagePath outside `System32`/`Program Files` = classic persistence; pair with MFT creation time and (for file drop) USN.
- 4688 `ProcessId`/`NewProcessId` hex; `ParentProcessId` likewise — matching parent to a dead process requires pairing with earlier 4688/4689 records (record PID reuse! PIDs are recycled).
- Record written time ≈ activity time, but large log streams can batch-write; sub-second precision is 100 ns but actual write latency varies (ms scale) — do not build 100-ns-precision stories.

## 7. Cross-validation notes

- 4688 (if enabled) ↔ Prefetch/BAM/Amcache/UserAssist: different coverage (4688 needs audit; Prefetch needs SysMain; BAM = 7 days; UserAssist = Explorer launches only).
- 7045 service install ↔ SOFTWARE hive service keys + USN/MFT of the ImagePath file.
- 4624 type 10 / LSM 21 / RCM 1149 ↔ RDP client IPs in bam? no — use network logs / `Security` source IP fields; LSM 21 has no IP (RCM 1149 does).
- 1102/104 clearance times ↔ USN/MFT activity of `winevt\Logs\*.evtx` (file recreation) and jump in EventRecordID.
- 6008/41 unexpected shutdown ↔ last System 6006 absence; BugCheck 1001 pairing; dump file in `C:\Windows\MEMORY.DMP` ($MFT size/time).
- Defender 1116/1117 ↔ quarantined file paths + USN deletion patterns.

## 8. Agent Traps

1. **1102 is written INTO the log it reports being cleared.** Its presence proves a clear; its absence after a suspicious gap does not prove there was no clear (attacker can kill the service, delete the file, or the log can simply wrap). 1102 usually carries the subject — quote it or say "bedrock fields were empty/denied".
2. **Auto-overwrite leaves no trace.** Circular wrap silently deletes oldest records; absence of early events ≠ machine was clean. Check `wevtutil gli <log>` oldest record number/ID vs the expected window.
3. **EventRecordID is per-channel and restarts low after a clear.** Never fuse using record ID alone; always (channel, record ID). A sudden "reset" to small IDs in a high-ID channel indicates recreation. Also: `wevtutil gli`'s `oldestRecordNumber` is a different counter from `EventRecordID`; do not treat them as the same number space.
4. **TimeCreated is UTC with 100-ns fraction** (`...T09:00:00.1234567Z`). GUI shows local time. Parse as UTC; comparisons with FILETIME-derived UTC timestamps need no conversion.
5. **`Execution ProcessID` ≠ subject process.** For 4688 it's the logging thread; the subject is `NewProcessId` in EventData, in hex.
6. **Command-line fields may be empty on 4688.** Inspect the actual EventData key (often `CommandLine`; some documentation uses `ProcessCommandLine`). Empty may indicate that "Include command line in process creation events" is off; it is a policy state, not evidence of a bare spawn.
7. **No 4688 at all is normal on client Windows by default** (Process Creation auditing off unless a policy enables it). Don't call it "anti-forensics" — cross-check the audit policy (Security 4719 changes, `auditpol /get`).
8. **4625: the reason is `SubStatus`, not `Status`.** Status 0xC000006D ("bad user name or password") is generic; SubStatus carries 0xC000006A/0xC0000064/0xC0000234/0xC0000072. PIN wrong / password wrong shows 0xC000006A (bad password) even when the account exists and is locked — lockout lives in 4740.
9. **4624 LogonType=3/5 noise.** SMB, RPC, service logons flood the log; presence of 4624s is not human activity. Filter and interpret by LogonType.
10. **Level values:** 0=LogAlways, 1=Critical, 2=Error, 3=Warning, 4=Information, 5=Verbose — not "higher = worse". Keywords `0x8020...` = Audit Success bit pattern (not a severity).
11. **Two different "1001"s** (BugCheck in System vs WER in Application) and many same-ID collisions across providers/channels (e.g. 1000 in Application vs elsewhere). Always qualify by (channel, provider, ID).
12. **Classic providers put a `Qualifiers` attribute on EventID** (e.g. old 1000/1001 in XP-era providers); modern XML still allows it. Don't drop the qualifier when present.
13. **UserData vs EventData vs Binary:** providers choose EventData or provider-specific `<UserData>` (WER/Update/older events); EventData itself can contain `<Binary>` hex payloads alongside `<Data>` entries. A parser that silently drops either returns partial maps — dropping must be visible (warned), and `<Binary>` should be captured as data.
14. **Security log needs admin even offline.** A copied `Security.evtx` keeps its restrictive ACL (SYSTEM-only read). "Access denied" on a copy is ACL, not corruption — bypass via running elevated or `icacls` on the copy.
15. **`epl` export is binary; `qe /f:xml` dump is text.** Renamed/miscollected files are common. Magic `ElfFile` = binary EVTX (needs wevtutil or a real binary parser — backlog); `<Event` = XML.
16. **One logical event can span multiple records** (e.g. 4688 without 4689 = process still running or audit lost; 4624/4634 pairing per LogonId). LogonId is the correlation key, not PID.
17. **Service events are Chatty Cathy:** 7036 (state change) fires constantly; using it as "evidence of execution" is a classic over-claim. 7045 (install) is the persistence one; 7040 = config change (often defender disabling a service).
18. **TaskScheduler 106 is the task itself, `EventData` uses provider-specific names** (`TaskName`, `UserContext`), and its Operational log is OFF by default — absence of 106 says nothing about task creation; TaskCache registry + Security 4698 are alternates.
19. **Broken/rotated filenames:** channel-to-file mapping escapes `/` as `%4` (`...TaskScheduler%4Operational.evtx`) and long-named channels get hashed short forms; do not reverse-map by string manipulation — use `wevtutil el` + `wevtutil gl`.
20. **Event ID meanings drift across Windows versions** (e.g. Kernel-Power 41 details, WER variants, or reused IDs like 1000/1001 by new providers). Card entries here are versioned for NT6+ client/server families — when precision matters, quote the provider + channel + XML fields, not just the number.
