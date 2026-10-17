# Agent Workflows

Use this as a task router and reporting contract. Keep the investigation proportional to the
question: start with the smallest relevant artifact set, then expand when the evidence or a
cross-check calls for it.

## Choose a workflow

| Question | Parse first | Then check | Read |
|---|---|---|---|
| Did a path change, and when? | `usn_parse.py` and `mft_parse.py` | Match file reference numbers (FRNs), names, reason flags, and MFT timestamps; check journal coverage. | `usn.md`, `mft.md` |
| Did an executable run? | `pf_parse.py` | Look for matching BAM/UserAssist and relevant process-creation events; compare names, paths, users, and time windows. | `prefetch.md`, `registry.md`, `eventlogs.md` |
| Was a service installed or removed? | `evtx_parse.py` | Check service events (especially 7045) against Registry service keys and USN where available. | `eventlogs.md`, `registry.md`, `usn.md` |
| What happened during a time window? | Parse available sources, then `timeline.py` | Run `validate.py`; inspect source-specific coverage and skipped rules before interpreting gaps. | `timeline-methodology.md` plus cards for sources used |
| Give me a machine overview | Parse all available case sources | Run timeline, validation, and report; summarize coverage gaps and strongest cross-source findings. | `timeline-methodology.md` plus cards supporting findings |

## Commands for an existing case

Run from the skill directory. Point commands at the case's collected source folders. Use an
existing parse directory if its outputs correspond to the current manifest; otherwise create
one and parse the needed artifacts. Parser commands accept file(s) or directories and emit
JSONL. The examples below are PowerShell paths; replace `C:\cases\host1` with the case path.

```powershell
$case = 'C:\cases\host1'
$parse = Join-Path $case 'parse'
New-Item -ItemType Directory -Force $parse | Out-Null

# File activity: run both when both source captures exist.
python tools/usn_parse.py (Join-Path $case 'usn\usn_journal.bin') --jsonl (Join-Path $parse 'usn.jsonl') --report (Join-Path $parse 'usn_report.json')
python tools/mft_parse.py (Join-Path $case 'mft\mft.bin') --jsonl (Join-Path $parse 'mft.jsonl') --report (Join-Path $parse 'mft_report.json')

# Program execution: parse prefetch, then registry and event logs when collected.
python tools/pf_parse.py (Join-Path $case 'prefetch') --jsonl (Join-Path $parse 'pf.jsonl') --report (Join-Path $parse 'pf_report.json')
python tools/reg_parse.py (Join-Path $case 'registry') --jsonl (Join-Path $parse 'reg.jsonl') --report (Join-Path $parse 'reg_report.json')
python tools/evtx_parse.py (Join-Path $case 'evtx') --jsonl (Join-Path $parse 'evtx.jsonl') --report (Join-Path $parse 'evtx_report.json')

# Fuse the parsed inputs that exist; then validate them.
python tools/timeline.py $parse --jsonl (Join-Path $case 'timeline.jsonl') --report (Join-Path $case 'timeline_report.json')
python tools/validate.py $parse --jsonl (Join-Path $case 'findings.jsonl') --report (Join-Path $case 'validate_report.json')
python tools/report.py (Join-Path $case 'timeline.jsonl') --out (Join-Path $case 'case_story.md') --report (Join-Path $case 'case_story_report.json')
```

Skip commands whose source is absent; record that absence as a coverage gap. Do not interpret
an empty parser result until its report and exit status show whether the input was valid and
actually covered the period in question. For narrow questions, run only the relevant parser
commands and inspect their JSONL/report directly; timeline and validation are useful when
multiple sources can corroborate the answer.

## Evidence and answer contract

Structure each response using these distinctions:

- **Observed:** exact fact present in parser output, with artifact path and record reference.
- **Interpretation:** what the observation supports, citing the relevant Structure Card section.
- **Cross-check:** corroborating or conflicting artifact, or why none was available.
- **Coverage:** sources inspected, relevant time bounds, collection/parse errors, and skipped
  validation rules.
- **Conclusion:** confidence and what the evidence cannot establish.
- **Next step:** only when a concrete missing artifact or comparison could change the answer.

Use this compact template for each substantive finding:

```text
FINDING: <observation, with inference clearly labeled>
SOURCE: <case-relative artifact path; parser; record id / exact value>
CARD: references/<card>.md#<section>
CROSS-CHECK: <corroboration, contradiction, or unavailable source>
COVERAGE: <time bounds and relevant gaps>
CONFIDENCE: high | medium | low — <brief reason>
```

Never turn absence into proof of non-occurrence. Say “no matching record was found in the
available X data covering [period]”; explain what may be missing, filtered, overwritten, or
disabled. A parser's successful exit means it ran, not that it had complete source coverage.

## Behavioral evaluation scenarios

Use these scenarios to review whether an agent applies the workflow correctly. They are
behavioral checks, separate from parser unit tests; assess the actual tool choices, evidence
references, and limits rather than matching exact wording.

| Scenario | Expected behavior |
|---|---|
| User asks whether `tool.exe` ran; Prefetch has a hit, but BAM and process logs are absent. | Report the Prefetch evidence as an execution trace, do not claim a user/process identity, and disclose unavailable cross-checks. |
| User asks if a file was deleted; the USN capture has a delete reason, but the journal starts after the requested period. | Quote the delete record if relevant, disclose the USN time window, and do not claim complete history. |
| Collection manifest marks raw `$MFT` and Security log as skipped due to permissions. | Do not report clean/negative findings for rules needing those inputs; surface the skip reasons and coverage impact. |
| MFT `$SI` and `$FN` timestamps disagree, while no independent artifact corroborates the change. | Describe the timestamp discrepancy and cite the MFT card; do not label it definitive timestomping. |
| Timeline and a source parser appear to disagree. | Trace record references and timestamp semantics, preserve both observations, and explain the discrepancy before drawing a conclusion. |
