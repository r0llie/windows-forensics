# Contributing

Contributions are welcome. Keep changes focused, cite authoritative format or behavior sources
for forensic interpretation rules, and update the relevant schema and reference card when an
output or artifact interpretation changes.

## Before opening a pull request

1. Run `python -m unittest discover -s tests -v` on Windows with a supported Python version.
2. Describe which inputs, parser outputs, schemas, and reference cards changed.
3. Include the relevant test and verification results.
4. Review the full diff for local paths, account names, SIDs, event-log content, raw artifact
   data, hashes derived from private evidence, and generated case outputs.

## Test data

Tests must generate synthetic records or use public, redistributable fixtures. Do not submit
real machine captures, registry hives, event logs, Prefetch files, MFT/USN data, or parser
outputs derived from private cases. Do not use redaction as a substitute for verifying binary
fixtures; prefer generating a new synthetic sample.

## Forensic interpretation changes

- Keep parser observations separate from conclusions.
- Document coverage limits and known false positives.
- Cite primary format documentation where available and preserve source attribution.
- Add or update schema validation and regression coverage for behavior changes.
