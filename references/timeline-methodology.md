# Timeline Methodology — fusion, normalization, cross-validation

Version 1.0 — defines how `tools/timeline.py` fuses parser JSONL into one super-timeline, how `tools/report.py` summarizes it, and how `tools/validate.py` cross-checks available artifacts. Grounded in the per-artifact Structure Cards; this card explains the shared analysis rules.

## 1. Why fusion is non-trivial

Every artifact timestamps different things, with different reliability:

- **USN journal**: records file-system operations as they happen (create/write/rename/delete). High fidelity, but a ring buffer (oldest events die silently) and contains no process/user info.
- **$MFT**: stores per-file `$SI`/`$FN` timestamps. A *state*, not a log — a timestamp is "what the file says about itself", not an event record. Created/modified/accessed are update-in-place values; only creation is append-only-ish.
- **Prefetch**: per-executable last-8 run times. Proves execution (SysMain enabled), no user/args.
- **Event logs**: rich (user, process, IP), but audit-policy and retention dependent; logs wrap.
- **Registry artifacts**: mostly *state pointers* (UserAssist "last run", BAM "last execution" in a 7-day window, Amcache "observed at link time"), not full histories. One timestamp per record is common.
- **Trace-file/cache existence** (Application Compatibility cache): "apphelp saw the file before this FILETIME" — an upper bound, not an event.

Fusion must therefore: normalize timestamps, attach provenance, keep semantics per artifact, and never silently upgrade a weak timestamp into a strong claim.

## 2. Super-timeline record schema (timeline.py output)

One JSON object per line (JSONL), sorted ascending by `ts`:

```json
{
  "ts": "2024-01-01T13:36:55.022253Z",
  "source": "evtx",                 // one of: usn, mft, pf, evtx, reg
  "artifact": "eventlog",           // the producing artifact name (same as parser output)
  "action": "event:6005",           // short machine code, see mapping table
  "target": "EventLog",             // primary object (file name, executable, provider...)
  "details": { ... },               // artifact-specific, ALWAYS includes "record_ref"
  "record_ref": "System.xml#184467" // file (and record identifier) the fact came from
}
```

Rules:

- `ts` is the artifact's own timestamp, normalized to ISO 8601 UTC. Microseconds when available; never synthesized, never interpolated.
- Entries with no usable timestamp are **skipped** and counted in the report (`skipped_no_timestamp`), never given a fake time (no "file-system-observed" placeholders).
- `details` carries the discriminating fields (FRN, reason flags, PID, run counts...). `record_ref` keeps a pointer to the source parser output so any timeline entry can be traced back to raw evidence.
- The fusion does not deduplicate across artifacts. A file created (USN) and seen by the shim cache (AppCompatCache) is legitimately two entries — that redundancy is what cross-validation exploits.

## 3. Timestamp → action mapping (v1, per artifact)

| artifact | timestamp field | action code | target | interpretation strength |
|---|---|---|---|---|
| usn | `timestamp` | `usn:<REASON_FLAGS>` (e.g. `usn:FILE_CREATE`) | file name | **event** (append-only until wrap) |
| mft | `si_created` | `mft:file_created` | file name | state claim ("$SI says created") |
| mft | `si_modified` | `mft:file_modified` | file name | state claim (update-in-place) |
| pf | each of `run_times` (≤8) | `pf:executed` | executable | **event** (per-run records) |
| pf | `last_run_time` | `pf:last_run` | executable | event (usually == newest of run_times) |
| evtx | `time_created` | `evtx:<EventID>` | provider (data in details) | **event** (OS log) |
| reg bam | `execution_time` | `reg:bam_executed` | path | event, ≤7-day window |
| reg userassist | `last_run_time` | `reg:userassist_last_run` | decoded name | event (Explorer-mediated only) |
| reg amcache (file/iaf) | `link_date_ts` | `reg:amcache_observed` | path | event of Appraiser inventory pass |
| reg appcompatcache | entry `last_modified` | `reg:shimcache_seen` | path | **upper bound "seen by"** — not execution |
| others (typedpaths, muicache, runmru, pending, layers) | — | skipped | — | no trustworthy timestamps |

Deliberate omissions: Application Compatibility cache entries are flagged as cache observers; UserAssist counts/focus times are details, not timeline entries (one entry per record, the last run); MFT `si_accessed` and `fn_*` variants are suppressed in v1 to avoid tripling every file (their values remain in the parser output for targeted use). Amcache `link_date_ts` is null when the PE link date is unparseable or outside 1990..2038-01-19T03:14:07Z (hash-derived/forged stamps are common): those records are recounted as `skipped_no_timestamp`, the raw string stays in the parser output.

## 4. Ordering, windows, and honesty

- Sort strictly by `ts` ascending; ties keep input file order (stable sort) — deterministic output for tests.
- `--since/--until` filter on `ts` after normalization. Boundaries inclusive.
- Timestamp granularity differences are real: USN ≈ 100 ns, EVTX 100 ns (printed to 100 ns), registry FILETIME 100 ns, but actual write latency varies (ms scale) — never interpret ordering inside a <1 ms cluster as causal.
- Coverage windows differ per source (USN ring, BAM 7 days, Prefetch caps, log max size). The report must print each source's observed time range so gaps are visible as *coverage*, not as *absence of activity*.

## 5. Cross-validation rules (implemented by `tools/validate.py`)

The reason fusion exists. Each rule consumes the super-timeline (or raw parser outputs) and emits a finding: severity + rationale + source refs.

| # | Rule | Rationale |
|---|---|---|
| 1 | Execution claim (Prefetch/BAM/Amcache/UserAssist/4688) for executable X without any USN/MFT evidence of X's file ever existing | file was deleted+journal wrapped, or evidence mismatch — flag as unresolved |
| 2 | `$SI` created > `$FN` created by more than clock skew (≥ 1 s) or `$SI` timestamps all equal with sub-second zeros | timestomp (mft.md §10); USN/MFT cross-check |
| 3 | 7045 service install resolves to ImagePath; no USN `FILE_CREATE` of that path around install time | service installed from existing file, or USN wrapped — needs pair |
| 4 | 1102 (Security) / 104 (System, Application, other channels) log clear + jump in EventRecordID continuity | clear or recreation; corroborate with file timestamps of .evtx |
| 5 | BAM execution without Prefetch run (SysMain on) and without UserAssist (Explorer app) | execution via another mechanism (scheduled task/service), or artifact loss |
| 6 | Amcache `link_date_ts` older than file's `$SI` created | inventory of a temp/staged file lineage — investigate |
| 7 | PendingFileRenameOperations entry referencing a path with no recent USN activity | pending op set long ago; move happened in another session or log wrapped |
| 8 | Event 6008/41 (unexpected shutdown) without preceding 6006 or 1074 | corroborate crash; check dirty hive sequences (registry `dirty` warnings) |
| 9 | 4688 exists but no corresponding Prefetch run and no BAM | audit on but execution artifacts absent — deletion/cleanup suspicion |
| 10 | UserAssist `last_run_time` after BAM window (7 days) start yet BAM absent | maybe non-BAM-tracked launch (UWP/URI), or BAM tampering |

Rules are versioned here as a contract; `tools/validate.py` implements them and its report carries the honest boundaries:

- Rules run only when their required inputs are present; otherwise they land in `skipped_rules[]` with a reason — never as a zero-finding.
- Rule 1's evidence base is USN names + full `$MFT` names; unmatched claims are unresolved leads (severity info), not verdicts.
- Rule 3 is coverage-gated: install events older than the USN ring's oldest record are counted as coverage-limited, not flagged (the ring cannot see their creates).
- Rule 4 implements IDs 1102 (Security) and 104 (System/Application/other); boundary effects from exports are excluded — only internal gaps and record-id resets count.
- Rule 8 clusters 41/6008 markers within 300 s and looks up to 24 h back for 1074/6006 intent; a 1074 with "Other (Unplanned)" is reported but does not contradict a crash.
- Rule 10's BAM window starts at the earliest BAM `execution_time` observed; URI/UWP launches legitimately in UserAssist-only form.
- Example lists are capped (`--examples`, default 10) while counts are exact; every finding cites source refs.

## 6. Agent Traps (timeline edition)

1. **A state timestamp is not an event.** `$SI modified` = "the file's current story about its last modification", not "something modified it at T". USN and EVTX are events; MFT/registry cache fields are claims.
2. **`shimcache_seen` is an upper bound.** AppCompatCache records when apphelp handled the file; execution cannot be inferred (Win8+). Cross-check with Prefetch/BAM.
3. **Prefetch `run_times` are a rolling set** (last ≤8), not a complete history; absence of a run time ≠ never ran then.
4. **BAM window is ~7 days.** Anything older is invisible there; a "BAM/UserAssist gap" proves nothing without the window noted.
5. **Record IDs collide across channels/artifacts.** `record_ref` always includes file + artifact-specific id (channel+EventRecordID for evtx, FRN for usn/mft).
6. **Ties at identical timestamps** (same second, many events) must not be causally ordered by the tool; equal-as-ordering is a presentation artifact.
7. **Different clocks**: all Windows artifacts store UTC (FILETIME); timestamps in EventData *text* fields (e.g. embedded strings) may be local — normalize only known-UTC fields listed in the mapping table.
8. **Large MFT and event-log inputs can produce very large timelines** — window with `--since/--until` and source filters before drawing conclusions; a monster timeline tool is not a substitute for targeted queries.

## 7. Pipeline tools

- `tools/timeline.py` — implements the mapping table; `--source` filters, `--since/--until`, `--limit`, `--jsonl`, `--report`, `--quiet`; honest per-file/per-line errors (malformed JSONL counted, never silently dropped).
- `tools/report.py` — reads a timeline JSONL (or a directory of parser outputs) and writes the markdown "machine story": coverage, headline observations with per-finding sources, timeline excerpt, caveats.
- Automated tests use synthetic records and verify deterministic ordering.
