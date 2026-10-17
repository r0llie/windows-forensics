# Changelog

Project changes are recorded here. Version numbers describe the toolkit, parsers, and output
schemas as a release; they do not identify a forensic case.

## Unreleased

- Added question-first agent routing, task-specific command recipes, an evidence/coverage
  reporting contract, and behavioral evaluation scenarios.
- Clarified runtime documentation: Python 3.10+ is the intended minimum; Python 3.13 is the
  current development target.
- Replaced real machine-derived regression fixtures with synthetic records generated in tests.
- Added MIT licensing, repository ignore rules, Windows CI, contribution guidance, and a
  vulnerability reporting policy.
- Removed machine-specific details from public documentation and clarified artifact limits.
- Closed EVTX parser and test file handles that emitted `ResourceWarning` during the suite.

## 1.0.1

- Hardened case collection so populated case directories are not overwritten or mixed.
- Improved manifest reporting for partially completed collection steps.

## 1.0.0

- Documented the collection, parsing, timeline, validation, and reporting workflow.
- Added end-to-end analysis support and reference cards for the implemented artifact families.
- Added JSON schemas and regression tests for parser outputs.
