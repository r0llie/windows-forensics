# windows-forensics

Windows leaves traces in places that are easy to misread in isolation. This project brings
common artifacts, lightweight parsers, and practical reference notes into one small Python
toolbox.

```text
 raw artifacts          parsed records          useful output
┌──────────────┐        ┌───────────────┐        ┌───────────────────┐
│ USN · MFT    │───────▶│ parse to JSONL│───────▶│ timeline + checks │
│ Prefetch     │        └───────────────┘        └─────────┬─────────┘
│ Registry     │                                           │
│ Event logs   │                                           ▼
└──────────────┘                                ┌───────────────────┐
                                                │ Markdown report   │
                                                └───────────────────┘
```

The tools help answer questions such as *what changed?*, *what evidence suggests a program
ran?*, and *what can the available logs say about this time window?* They do not turn an
artifact into a verdict. Each source has gaps, and the references explain where interpretation
can go wrong.

## What’s here

- Collectors for selected Windows artifacts, including `$MFT`, the USN Journal, Prefetch,
  event logs, and registry data.
- Parsers that emit JSONL records and a per-source report.
- A timeline builder, cross-artifact checks, and a Markdown case summary.
- Reference cards covering artifact formats, useful fields, limitations, and common traps.
- An agent skill that routes a question to relevant artifacts and sets rules for evidence-based
  reporting.

Supported sources include USN Journal, `$MFT` (with `$ATTRIBUTE_LIST` extension stitching),
Prefetch, selected Registry artifacts, and Event Logs exported as XML with `wevtutil`.

## Run it

Requires Python 3.10 or newer. The tools use only the standard library; there is nothing to
install with pip. Run collection from an elevated PowerShell when you need protected sources
such as `$MFT` or the USN Journal. The collector records steps it cannot perform.

```powershell
git clone https://github.com/r0llie/windows-forensics.git
cd windows-forensics
python --version
python tools/collect.py --case C:\cases\host1
```

Use a new, empty case directory each time. Collection will not overwrite a populated one.
After collection, parse the sources that are present. For example:

```powershell
New-Item -ItemType Directory -Force C:\cases\host1\parse | Out-Null

python tools/usn_parse.py C:\cases\host1\usn\usn_journal.bin `
  --jsonl C:\cases\host1\parse\usn.jsonl `
  --report C:\cases\host1\parse\usn_report.json

python tools/mft_parse.py C:\cases\host1\mft\mft.bin `
  --jsonl C:\cases\host1\parse\mft.jsonl `
  --report C:\cases\host1\parse\mft_report.json

python tools/timeline.py C:\cases\host1\parse `
  --jsonl C:\cases\host1\timeline.jsonl `
  --report C:\cases\host1\timeline_report.json

python tools/validate.py C:\cases\host1\parse `
  --jsonl C:\cases\host1\findings.jsonl `
  --report C:\cases\host1\validation_report.json

python tools/report.py C:\cases\host1\timeline.jsonl `
  --out C:\cases\host1\case_story.md
```

The same pattern applies to Prefetch, Registry, and event log exports. Each parser’s `--help`
shows its accepted input and options. Skip a parser when its source is unavailable; the
timeline and validation reports include coverage information. A missing artifact is not proof
that an event did not happen.

For agent instructions and complete workflows, start with [`SKILL.md`](SKILL.md) and
[`references/agent-workflows.md`](references/agent-workflows.md).

## Development

The tests build synthetic artifacts in memory or temporary directories; the repository does
not include captures from real machines.

```powershell
python -m unittest discover -s tests -v
```

CI runs the suite on Windows with Python 3.10 and 3.13. See
[`CONTRIBUTING.md`](CONTRIBUTING.md) before submitting changes.

## Limits

- USN history only reaches as far back as the journal retains it.
- Event logs are read from `wevtutil` XML exports; binary EVTX parsing is not included.
- Parsing a full-volume `$MFT` can use several GiB of memory.
- A live Amcache hive may be locked by Windows; VSS acquisition is not implemented.
- Results depend on what was collected, retained, and successfully parsed. Check warnings,
  skipped sources, and coverage before drawing conclusions.

## License

MIT. See [`LICENSE`](LICENSE).
