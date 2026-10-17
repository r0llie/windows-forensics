# Windows Forensics — Roadmap

This file describes the public project state and planned work. It intentionally excludes
host-specific collection notes and forensic case details.

## Project goal

Provide an agent-oriented Windows forensics toolkit that separates artifact facts from
interpretation. Parsers emit structured records; reference cards document format semantics
and common interpretation traps; cross-validation highlights agreements, contradictions,
and coverage gaps.

## Implemented capabilities

| Area | Capability | Current boundary |
|---|---|---|
| Collection | Case folders, SHA-256 manifest, machine metadata, Prefetch, event logs, raw MFT and USN collection | Elevated rights are required for some sources; skipped or failed steps are recorded. |
| NTFS | USN Journal and MFT parsing, including extension record stitching and timestamp observations | USN history is bounded by journal retention; observations do not by themselves prove tampering. |
| Execution traces | Prefetch parsing, including MAM/XPRESS-Huffman and classic formats | Prefetch may be disabled, absent, or incomplete. |
| Registry | Offline hive parsing and common execution, compatibility, and persistence artifacts | Live Amcache acquisition can be blocked by the OS. |
| Event logs | `wevtutil` XML export parsing | Binary EVTX parsing is not implemented. |
| Analysis | Timeline fusion, ten cross-validation rules, and Markdown report generation | Results depend on available artifacts and their retention/configuration. |
| Agent guidance | Question routing, evidence reporting contract, Structure Cards, and behavioral evaluation scenarios | The scenarios are guidance; they are not an automated agent benchmark. |

## Planned work

- Add an optional binary EVTX parser.
- Add parsers for SRUM, Shellbags, Jump Lists/LNK, `$LogFile`, `$I30`, WER, and browser artifacts.
- Explore VSS-aware acquisition and historical artifact analysis.
- Add optional timeline visualization, multi-host baseline comparison, and localized reports.
- Build an automated behavioral evaluation harness for agent tool selection, evidence citations,
  and coverage reporting.

## Development conventions

- Runtime target: Python 3.13 with the standard library; documented minimum is Python 3.10.
- Output schemas live in `schemas/`; parser regression tests live in `tests/`.
- Test command: `python -m unittest discover -s tests -v`.
- Real machine captures are not committed. Tests generate synthetic data at runtime.
- Every user-facing capability claim should match the implementation and its known limits.
