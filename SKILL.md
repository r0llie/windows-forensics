---
name: windows-forensics
description: Analyze Windows forensic artifacts with the bundled parsers and evidence references. Use for incident triage, USN Journal, $MFT, Prefetch, Registry artifacts, event logs, timestomping questions, and forensic timelines. Ground machine-specific claims in parser output and interpretations in a Structure Card.
---

# Windows Forensics — Agent Protocol

Use the bundled tools to establish what evidence is available, parse only what answers the
question, cross-check important claims, and report what the evidence cannot establish.

## Evidence rules

- Make no machine-specific claim without parser output that identifies its source record.
- Back interpretations with the relevant Structure Card section; read its **Agent Traps**.
- Separate recorded facts from inference. A single artifact is evidence, not a verdict.
- Treat missing, filtered, skipped, or unparseable inputs as coverage gaps. Absence from an
  incomplete source does not prove an event did not happen.
- Preserve parser field names, raw values, timestamps, warnings, and errors accurately.

## Fast routing

| Question | Start with | Read | Main limit |
|---|---|---|---|
| Did a file change, move, or disappear? | USN + MFT | `references/usn.md`, `references/mft.md` | USN history is limited by journal retention; MFT timestamps do not prove user action. |
| Did a program run? | Prefetch | `references/prefetch.md` | Cross-check BAM/UserAssist and process events when available; missing traces are not proof of non-execution. |
| Was a service, account, or persistence setting changed? | Event Logs + Registry | `references/eventlogs.md`, `references/registry.md` | Auditing, retention, and artifact availability affect coverage. |
| What happened in a time window? | Timeline + validation | `references/timeline-methodology.md` and cards for sources used | State each source's actual time coverage and skipped rules. |
| Give an overall machine activity summary | All available case artifacts | Relevant cards plus `references/timeline-methodology.md` | Distinguish direct observations, inferences, conflicts, and missing evidence. |

For exact commands and reporting examples, read [`references/agent-workflows.md`](references/agent-workflows.md).
For questions outside these routes, consult the support map.

## Workflow

1. Frame the question and relevant time window.
2. Check the Artifact Support Map. If there is no parser, say so; do not improvise a parser.
3. Reuse a case with `manifest.json` when available. Check source hashes, collection status,
   time bounds, and missing or failed steps. For a new collection, use a new empty directory:
   `python tools/collect.py --case <dir>`. Run elevated when collecting raw MFT, USN, or hives;
   skipped steps and reasons are recorded in the manifest.
4. Run the relevant parser(s). Outputs follow the contracts in `schemas/`.
5. Read the matching reference card before interpretation.
6. For multi-source questions, run `python tools/timeline.py <parse-dir>` and
   `python tools/validate.py <parse-dir>`. Missing inputs are reported as skipped rules.
7. Report findings with source record references, interpretation basis, cross-checks, coverage,
   and confidence. For a full narrative, `python tools/report.py <timeline.jsonl>` creates a
   Markdown report.

## Artifact Support Map

| Question | Artifact | Reference | Tool |
|---|---|---|---|
| What happened to files, and when? | USN Journal | `references/usn.md` | `tools/usn_parse.py` |
| What does NTFS metadata show? | `$MFT` | `references/mft.md` | `tools/mft_parse.py` |
| What execution traces exist? | Prefetch | `references/prefetch.md` | `tools/pf_parse.py` |
| What traces exist in registry hives? | Registry artifacts | `references/registry.md` | `tools/reg_parse.py`, `tools/collect_reg.py` |
| What do event logs record? | Event Logs | `references/eventlogs.md` | `tools/evtx_parse.py` |
| What is the cross-source timeline? | Fused timeline | `references/timeline-methodology.md` | `tools/timeline.py`, `tools/report.py` |
| Are sources consistent? | Cross-validation findings | `references/timeline-methodology.md` §5 | `tools/validate.py` |
| How do I acquire a case? | Case folder + manifest | Workflow above | `tools/collect.py` |

Check current implementation and input availability before promising a capability.

## Finding format

```text
FINDING: <observation; label inference explicitly>
SOURCE: <case-relative artifact path; parser; record id / exact value>
CARD: references/<card>.md#<section>
CROSS-CHECK: <corroboration, conflict, or unavailable source>
COVERAGE: <time bounds and relevant gaps>
CONFIDENCE: high | medium | low — <reason>
```

Use careful negative-result wording: “No matching record was found in the available X data
covering [period].” Explain whether retention, disabled auditing, collection failure, or
parsing limits could hide relevant activity.

## Environment

- Python 3.10+ is the intended minimum; development targets Python 3.13 and the standard library.
- Raw volume reads and some hive collection steps require administrator privileges.
- Run tests from the skill root with `python -m unittest discover -s tests -v`.
- Project status and future work are in `ROADMAP.md`.
