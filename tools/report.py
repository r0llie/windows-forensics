#!/usr/bin/env python3
"""Narrate a super-timeline as the markdown "machine story" (Phase 6).

Input: timeline JSONL entries (tools/timeline.py output) and/or raw parser
JSONL records (any tool in tools/) — parser records are fused on the fly with
the same emitters timeline.py uses, so a directory of parser outputs works
directly. Output: deterministic markdown story (coverage, headline
observations, timeline excerpt, caveats) — every claim carries counts and
source ranges, never speculation. Methodology: references/timeline-methodology.md.

Exit codes: 0 = tool ran (per-file/per-line errors inside the report),
1 = fatal (inputs unreadable / output not writable), 2 = usage error.
"""

import argparse
import json
import os
import sys
from collections import Counter
from datetime import datetime, timezone

TOOLS_DIR = os.path.dirname(os.path.abspath(__file__))
if TOOLS_DIR not in sys.path:
    sys.path.insert(0, TOOLS_DIR)

import timeline as tl  # noqa: E402

TOOL_VERSION = "0.1.0"
SCHEMA_VERSION = 1

EXECUTION_ACTIONS = {
    "pf:executed",
    "pf:last_run",
    "reg:bam_executed",
    "reg:userassist_last_run",
    "reg:amcache_observed",
}

CAVEAT_LINES = [
    "Coverage windows differ per source (USN ring buffer, BAM 7-day window, Prefetch run-count cap, log rotation). "
    "A quiet window in one source is not proof that nothing happened - compare the per-source ranges above.",
    "Timestamps are artifact-authored. Registry FILETIME and EVTX values have ~1 s write latency; never treat "
    "sub-millisecond ordering within a cluster of records as causal.",
    "The fusion does not deduplicate across artifacts: one real-world action can legitimately appear as several "
    "entries (e.g. USN create + Prefetch run). That redundancy is what cross-validation exploits.",
    "No entry in this story is inferred. Every line traces back to a record_ref in the source JSONL.",
]

FENCE = "```"


class ReportError(RuntimeError):
    pass


def _is_entry(rec):
    return isinstance(rec, dict) and "ts" in rec and "source" in rec and "action" in rec


def _entry_from_record(rec, source_file):
    artifact = rec.get("artifact")
    emitter = tl.EMITTERS.get(artifact)
    if emitter is None:
        if artifact in tl.NO_TIMESTAMP_ARTIFACTS:
            return "no_timestamp", artifact
        return "unknown_artifact", str(artifact)
    rec = dict(rec)
    rec["_source_file"] = source_file
    entries = []
    skipped = 0
    for entry in emitter(rec):
        if not entry.get("ts") or tl.parse_iso(entry["ts"]) is None:
            skipped += 1
            continue
        entries.append(entry)
    if skipped and not entries:
        return "no_timestamp", artifact
    if skipped:
        return "partial", (artifact, entries, skipped)
    return "ok", entries


class Stats:
    def __init__(self):
        self.files_total = 0
        self.files_failed = 0
        self.records_in = 0
        self.entries = []
        self.emitted = 0
        self.malformed = 0
        self.skipped_no_timestamp = Counter()
        self.skipped_unknown_artifact = Counter()
        self.by_source = Counter()
        self.by_action = Counter()
        self.source_ts_min = {}
        self.source_ts_max = {}
        self.inputs_meta = []
        self.errors = []
        self.notes = []
        self.warnings = set()


def expand_inputs(inputs):
    paths = []
    for item in inputs:
        if os.path.isdir(item):
            names = [n for n in sorted(os.listdir(item)) if n.lower().endswith(".jsonl") and os.path.isfile(os.path.join(item, n))]
            if not names:
                raise ReportError("no *.jsonl files in directory: %s" % item)
            paths.extend(os.path.join(item, n) for n in names)
        else:
            paths.append(item)
    return paths


def collect(paths):
    stats = Stats()
    for path in paths:
        stats.files_total += 1
        try:
            with open(path, "rb") as fh:
                raw = fh.read()
        except OSError as exc:
            stats.files_failed += 1
            stats.errors.append({"path": os.path.basename(path), "line": None, "error": "cannot_read: %s" % exc})
            continue
        source_file = os.path.basename(path)
        line_no = 0
        file_entries = 0
        file_records = 0
        for line in raw.decode("utf-8", errors="replace").splitlines():
            line_no += 1
            if not line.strip():
                continue
            try:
                rec = json.loads(line)
            except ValueError as exc:
                stats.malformed += 1
                stats.errors.append({"path": source_file, "line": line_no, "error": "bad JSON: %s" % exc})
                continue
            if _is_entry(rec):
                ts = tl.parse_iso(rec["ts"])
                if ts is None:
                    stats.skipped_no_timestamp[rec.get("artifact", "?")] += 1
                    continue
                stats.records_in += 1
                stats.entries.append(rec)
                file_entries += 1
                continue
            if isinstance(rec, dict) and "artifact" in rec:
                stats.records_in += 1
                file_records += 1
                kind, payload = _entry_from_record(rec, source_file)
                if kind == "ok":
                    stats.entries.extend(payload)
                    file_entries += len(payload)
                elif kind == "partial":
                    artifact, entries, skipped = payload
                    stats.entries.extend(entries)
                    file_entries += len(entries)
                    stats.skipped_no_timestamp[artifact] += skipped
                elif kind == "no_timestamp":
                    stats.skipped_no_timestamp[payload] += 1
                else:
                    stats.skipped_unknown_artifact[payload] += 1
                continue
            stats.skipped_unknown_artifact["<no artifact field>"] += 1
        stats.inputs_meta.append({"path": source_file, "size": len(raw), "entries": file_entries, "records": file_records})
    return stats


def apply_filters(stats, filters):
    kept = []
    for entry in stats.entries:
        source = entry.get("source")
        if filters["sources"] is not None and source not in filters["sources"]:
            continue
        ts = tl.parse_iso(entry.get("ts"))
        if ts is None:
            stats.skipped_no_timestamp[entry.get("artifact", "?")] += 1
            continue
        if filters["since"] is not None and ts < filters["since"]:
            continue
        if filters["until"] is not None and ts > filters["until"]:
            continue
        kept.append(entry)
    kept.sort(key=lambda e: e["ts"])
    stats.entries = kept
    for entry in kept:
        source = entry.get("source", "?")
        stats.emitted += 1
        stats.by_source[source] += 1
        stats.by_action[entry.get("action", "?")] += 1
        ts = entry["ts"]
        if source not in stats.source_ts_min or ts < stats.source_ts_min[source]:
            stats.source_ts_min[source] = ts
        if source not in stats.source_ts_max or ts > stats.source_ts_max[source]:
            stats.source_ts_max[source] = ts


def execution_summary(entries):
    counter = Counter()
    latest = {}
    for entry in entries:
        if entry.get("action") in EXECUTION_ACTIONS:
            target = entry.get("target") or "?"
            counter[target] += 1
            if target not in latest or entry["ts"] > latest[target]:
                latest[target] = entry["ts"]
    return [
        {"target": target, "count": count, "last_ts": latest[target]}
        for target, count in sorted(counter.items(), key=lambda kv: (-kv[1], kv[0]))
    ]


def busiest_days(entries):
    counter = Counter()
    for entry in entries:
        counter[entry["ts"][:10]] += 1
    return [{"date": day, "count": count} for day, count in sorted(counter.items(), key=lambda kv: (-kv[1], kv[0]))]


def extreme_timestamps(entries):
    """Count entries outside a sane host-activity window (fixed thresholds, so
    deterministic): pre-1995 and post-2035 values are FAT-epoch placeholders or
    hash-derived PE stamps, not host events. They stay in the timeline - this
    only tags them for the reader."""
    count = 0
    examples = []
    for entry in entries:
        year = int(entry["ts"][:4])
        if year < 1995 or year > 2035:
            count += 1
            if len(examples) < 3:
                examples.append("%s %s -> %s" % (entry["ts"][:10], entry.get("action"), entry.get("target")))
    return count, examples


def render(stats, title, excerpt, args):
    lines = []
    total = len(stats.entries)
    if total:
        first, last = stats.entries[0]["ts"], stats.entries[-1]["ts"]
        span = "%s -> %s" % (first, last)
    else:
        span = "n/a (no entries)"
    lines.append("# Machine story - %s" % title)
    lines.append("")
    lines.append(
        "_Generated at %s by report.py %s from %d input file(s); %d parser record(s) fused; %d timeline entry(ies) narrated._"
        % (datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), TOOL_VERSION, stats.files_total, stats.records_in, total)
    )
    lines.append("")

    lines.append("## Inputs")
    lines.append("")
    lines.append("| file | size (bytes) | parser records | timeline entries |")
    lines.append("|---|---|---|---|")
    for meta in stats.inputs_meta:
        lines.append("| %s | %d | %d | %d |" % (meta["path"], meta["size"], meta["records"], meta["entries"]))
    if stats.files_failed:
        for error in stats.errors:
            if error.get("line") is None:
                lines.append("| %s | - | FAILED: %s | - |" % (error["path"], error["error"]))
    lines.append("")

    lines.append("## Coverage")
    lines.append("")
    lines.append("| source | entries | earliest | latest |")
    lines.append("|---|---|---|---|")
    for source in sorted(stats.by_source):
        lines.append(
            "| %s | %d | %s | %s |" % (source, stats.by_source[source], stats.source_ts_min[source], stats.source_ts_max[source])
        )
    lines.append("")
    if stats.skipped_no_timestamp:
        parts = ["%s: %d" % (artifact, count) for artifact, count in sorted(stats.skipped_no_timestamp.items())]
        lines.append("State-only records without timeline timestamps (skipped, counted): %s." % "; ".join(parts))
    if stats.skipped_unknown_artifact:
        parts = ["%s: %d" % (artifact, count) for artifact, count in sorted(stats.skipped_unknown_artifact.items())]
        lines.append("Unrecognized records (skipped): %s." % "; ".join(parts))
    lines.append("")

    lines.append("## Headline observations")
    lines.append("")
    lines.append("- **%d timeline entries** across %d source(s), spanning %s." % (total, len(stats.by_source), span))
    if stats.by_action:
        top = "; ".join("%s (%d)" % (action, count) for action, count in stats.by_action.most_common(10))
        lines.append("- Most frequent actions: %s." % top)
    executions = execution_summary(stats.entries)
    if executions:
        head = "; ".join("%s x%d (last %s)" % (e["target"], e["count"], e["last_ts"]) for e in executions[:10])
        lines.append("- Execution evidence for %d target(s): %s." % (len(executions), head))
    days = busiest_days(stats.entries)
    if days:
        head = "; ".join("%s (%d)" % (d["date"], d["count"]) for d in days[:10])
        lines.append("- Busiest days (UTC): %s." % head)
    quality = []
    if stats.malformed:
        quality.append("%d malformed JSONL line(s) skipped (see report)" % stats.malformed)
    if stats.files_failed:
        quality.append("%d file(s) failed to read" % stats.files_failed)
    extreme_count, extreme_examples = extreme_timestamps(stats.entries)
    if extreme_count:
        quality.append(
            "%d entry(ies) carry extreme timestamps (pre-1995/post-2035) - placeholders or hash-derived PE stamps, "
            "not host activity (e.g. %s)" % (extreme_count, "; ".join(extreme_examples))
        )
    if quality:
        lines.append("- Data quality: %s." % "; ".join(quality))
    lines.append("")

    lines.append("## Timeline excerpt")
    lines.append("")
    if total == 0:
        lines.append("_No entries._")
    elif total <= excerpt * 2:
        lines.append("All %d entries:" % total)
        lines.append(FENCE)
        for entry in stats.entries:
            lines.append(format_entry(entry))
        lines.append(FENCE)
    else:
        lines.append("First %d of %d entries:" % (excerpt, total))
        lines.append(FENCE)
        for entry in stats.entries[:excerpt]:
            lines.append(format_entry(entry))
        lines.append(FENCE)
        lines.append("Last %d of %d entries:" % (excerpt, total))
        lines.append(FENCE)
        for entry in stats.entries[-excerpt:]:
            lines.append(format_entry(entry))
        lines.append(FENCE)
    lines.append("")

    lines.append("## Caveats")
    lines.append("")
    for caveat in CAVEAT_LINES:
        lines.append("- %s" % caveat)
    if stats.malformed:
        lines.append("- %d malformed line(s) were skipped; totals above undercount by that much." % stats.malformed)
    if stats.skipped_no_timestamp:
        lines.append(
            "- %d timestampless record(s) exist as state evidence but do not appear in the timeline."
            % sum(stats.skipped_no_timestamp.values())
        )
    if total == 0:
        lines.append("- **No entries were narrated** - check input paths, filters and parser outputs.")
    lines.append("")
    return "\n".join(lines)


def format_entry(entry):
    target = entry.get("target")
    target_part = " -> %s" % target if target else ""
    return "%s  %-4s %s%s" % (entry.get("ts"), entry.get("source", "?"), entry.get("action", "?"), target_part)


def build_report(stats, filters, args):
    warnings = set(stats.warnings)
    if stats.files_failed:
        warnings.add("files_failed_to_parse")
    if stats.malformed:
        warnings.add("malformed_lines_present")
    if stats.emitted == 0:
        warnings.add("no_records_emitted")
    return {
        "tool": "report",
        "tool_version": TOOL_VERSION,
        "schema_version": SCHEMA_VERSION,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "inputs": stats.inputs_meta,
        "counts": {
            "files": stats.files_total,
            "failed": stats.files_failed,
            "records_in": stats.records_in,
            "entries": stats.emitted,
            "malformed_lines": stats.malformed,
            "by_source": dict(sorted(stats.by_source.items())),
            "top_actions": [{"action": a, "count": c} for a, c in stats.by_action.most_common(20)],
            "source_ranges": {
                s: {"min": stats.source_ts_min.get(s), "max": stats.source_ts_max.get(s)}
                for s in sorted(set(stats.source_ts_min) | set(stats.source_ts_max))
            },
            "execution_targets": execution_summary(stats.entries)[:20],
            "busiest_days": busiest_days(stats.entries)[:10],
            "extreme_timestamps": {
                "count": extreme_timestamps(stats.entries)[0],
                "examples": extreme_timestamps(stats.entries)[1],
            },
            "skipped_no_timestamp": dict(sorted(stats.skipped_no_timestamp.items())),
            "skipped_unknown_artifact": dict(sorted(stats.skipped_unknown_artifact.items())),
        },
        "filters": {
            "sources": sorted(filters["sources"]) if filters["sources"] else None,
            "since": args.since,
            "until": args.until,
            "excerpt": args.excerpt,
        },
        "notes": stats.notes,
        "errors": stats.errors,
        "warnings": sorted(warnings),
    }


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="report.py",
        description="Write the markdown 'machine story' from timeline entries and/or raw parser JSONL records.",
    )
    ap.add_argument("inputs", nargs="+", help="timeline JSONL and/or parser JSONL file(s) and/or directory(ies)")
    ap.add_argument("--out", default="-", help="write markdown story to this path ('-' = stdout, default)")
    ap.add_argument("--title", default="host activity", help="story title (default: 'host activity')")
    ap.add_argument("--excerpt", type=int, default=50, help="entries to show from each end of the timeline (default 50)")
    ap.add_argument("--source", action="append", default=None, help="filter: source(s) (repeatable/comma): usn, mft, pf, evtx, reg")
    ap.add_argument("--since", default=None, help="filter: entries at/after this ISO 8601 time (UTC)")
    ap.add_argument("--until", default=None, help="filter: entries at/before this ISO 8601 time (UTC)")
    ap.add_argument("--report", default=None, help="write machine-readable JSON report to this path")
    ap.add_argument("--quiet", action="store_true", help="suppress the stderr summary")
    args = ap.parse_args(argv)

    if args.excerpt < 1:
        ap.error("--excerpt must be positive")

    try:
        filters = tl.make_filters(args)
    except tl.TimelineToolError as exc:
        sys.stderr.write("[report] usage error: %s\n" % exc)
        return 2
    try:
        paths = expand_inputs(args.inputs)
    except ReportError as exc:
        sys.stderr.write("[report] fatal: %s\n" % exc)
        return 1

    stats = collect(paths)
    apply_filters(stats, filters)
    story = render(stats, args.title, args.excerpt, args)

    if args.out == "-":
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(newline="\n")
        sys.stdout.write(story)
    else:
        try:
            with open(args.out, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(story)
        except OSError as exc:
            sys.stderr.write("[report] fatal: cannot write story: %s\n" % exc)
            return 1

    report = build_report(stats, filters, args)
    if args.report:
        try:
            with open(args.report, "w", encoding="utf-8", newline="\n") as fh:
                json.dump(report, fh, indent=2, ensure_ascii=False)
                fh.write("\n")
        except OSError as exc:
            sys.stderr.write("[report] fatal: cannot write report: %s\n" % exc)
            return 1

    if not args.quiet:
        counts = report["counts"]
        sys.stderr.write(
            "[report] files=%d failed=%d records_in=%d entries=%d by_source=%s warnings=%s\n"
            % (counts["files"], counts["failed"], counts["records_in"], counts["entries"], counts["by_source"], report["warnings"])
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
