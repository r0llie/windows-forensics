#!/usr/bin/env python3
"""Fuse forensic parser JSONL outputs into one super-timeline (Phase 6).

Methodology: references/timeline-methodology.md (mapping table, honesty rules).
Every entry is an artifact-authored timestamp normalized to ISO 8601 UTC with
provenance (source, artifact, record_ref) so any fact can be traced back to the
producing parser output. Records without usable timestamps are skipped and
counted — never invented.

Usage:
  python timeline.py INPUT [INPUT ...] [--source usn,evtx ...] [--since ISO]

Exit codes: 0 = tool ran (per-file/per-line errors inside the report),
1 = fatal (inputs unreadable / output not writable), 2 = usage error.
"""

import argparse
import hashlib
import json
import os
import sys
from collections import Counter
from datetime import datetime, timezone

TOOL_VERSION = "0.1.0"
SCHEMA_VERSION = 1

SOURCE_OF_ARTIFACT = {
    "usn": "usn",
    "mft": "mft",
    "pf": "pf",
    "eventlog": "evtx",
    "bam": "reg",
    "userassist": "reg",
    "amcache_inventory_application_file": "reg",
    "amcache_file": "reg",
    "appcompatcache": "reg",
}

# Artifacts that legitimately carry no timeline timestamp (state-only evidence).
NO_TIMESTAMP_ARTIFACTS = {
    "muicache",
    "runmru",
    "typedpaths",
    "pending_file_rename_operations",
    "appcompatflags_layers",
    "amcache_inventory_application",
    "amcache_programs",
}

VALID_SOURCES = ("usn", "mft", "pf", "evtx", "reg")


class TimelineToolError(RuntimeError):
    pass


def parse_iso(value):
    if not value:
        return None
    text = value.strip()
    if text.endswith("Z") or text.endswith("z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _entry(ts, source, artifact, action, target, details, record_ref):
    return {
        "ts": ts,
        "source": source,
        "artifact": artifact,
        "action": action,
        "target": target,
        "details": details,
        "record_ref": record_ref,
    }


def usn_entries(rec):
    source_file = rec.get("_source_file", "?")
    ref = "%s#usn=%s" % (source_file, rec.get("usn"))
    flags = rec.get("reason_flags") or []
    action = "usn:" + "+".join(flags) if flags else "usn:UNKNOWN"
    details = {
        "usn": rec.get("usn"),
        "file_reference": rec.get("file_reference"),
        "reason_flags": flags,
        "file_attributes": rec.get("file_attributes"),
    }
    yield _entry(rec.get("timestamp"), "usn", "usn", action, rec.get("name"), details, ref)


def mft_entries(rec):
    source_file = rec.get("_source_file", "?")
    ref = "%s#record=%s" % (source_file, rec.get("record_number"))
    si = rec.get("standard_information") or {}
    details = {
        "record_number": rec.get("record_number"),
        "file_reference": rec.get("file_reference"),
        "size": rec.get("size"),
        "is_directory": rec.get("is_directory"),
        "timestomp_flags": rec.get("timestomp_flags") or [],
    }
    if si.get("created"):
        yield _entry(si["created"], "mft", "mft", "mft:file_created", rec.get("primary_name"), details, ref)
    if si.get("modified"):
        yield _entry(si["modified"], "mft", "mft", "mft:file_modified", rec.get("primary_name"), details, ref)


def pf_entries(rec):
    source_file = rec.get("_source_file", "?")
    executable = rec.get("executable")
    run_count = rec.get("run_count")
    base = {"run_count": run_count, "prefetch_hash": rec.get("prefetch_hash")}
    for index, ts in enumerate(rec.get("run_times") or []):
        details = dict(base)
        details["run_index"] = index
        yield _entry(ts, "pf", "pf", "pf:executed", executable, details, "%s#run=%d" % (source_file, index))
    if rec.get("last_run_time"):
        yield _entry(rec["last_run_time"], "pf", "pf", "pf:last_run", executable, base, "%s#last_run" % source_file)


def evtx_entries(rec):
    source_file = rec.get("source_file") or rec.get("_source_file", "?")
    details = {
        "event_id": rec.get("event_id"),
        "channel": rec.get("channel"),
        "provider": rec.get("provider"),
        "computer": rec.get("computer"),
        "security_user_id": rec.get("security_user_id"),
        "event_data": rec.get("event_data") or {},
    }
    if rec.get("user_data") is not None:
        details["user_data"] = rec["user_data"]
    ref = "%s#record=%s" % (source_file, rec.get("record_id"))
    action = "evtx:%s" % rec.get("event_id") if rec.get("event_id") is not None else "evtx:UNKNOWN"
    yield _entry(rec.get("time_created"), "evtx", "eventlog", action, rec.get("provider"), details, ref)


def bam_entries(rec):
    ref = "%s#%s" % (rec.get("hive", "?"), rec.get("path"))
    details = {"user_sid": rec.get("user_sid"), "windows_app_flag": rec.get("windows_app_flag")}
    yield _entry(rec.get("execution_time"), "reg", "bam", "reg:bam_executed", rec.get("path"), details, ref)


def userassist_entries(rec):
    ref = "%s#%s\\%s" % (rec.get("hive", "?"), rec.get("guid"), rec.get("name"))
    details = {
        "guid": rec.get("guid"),
        "run_count": rec.get("run_count"),
        "kind": rec.get("kind"),
        "version": rec.get("version"),
    }
    yield _entry(rec.get("last_run_time"), "reg", "userassist", "reg:userassist_last_run", rec.get("name"), details, ref)


def amcache_iaf_entries(rec):
    ref = "%s#%s" % (rec.get("hive", "?"), rec.get("key_name") or rec.get("path"))
    details = {
        "sha1": rec.get("sha1"),
        "size": rec.get("size"),
        "name": rec.get("name"),
        "key_name": rec.get("key_name"),
        "link_date": rec.get("link_date"),
    }
    yield _entry(rec.get("link_date_ts"), "reg", "amcache_inventory_application_file", "reg:amcache_observed", rec.get("path"), details, ref)


def amcache_file_entries(rec):
    ref = "%s#%s" % (rec.get("hive", "?"), rec.get("path") or rec.get("name"))
    details = {
        "sha1": rec.get("sha1") or rec.get("sha1_raw"),
        "file_size": rec.get("file_size"),
        "modification_time": rec.get("modification_time"),
        "creation_time": rec.get("creation_time"),
    }
    yield _entry(rec.get("link_date_ts"), "reg", "amcache_file", "reg:amcache_observed", rec.get("path"), details, ref)


def appcompatcache_entries(rec):
    ref = "%s#%s" % (rec.get("hive", "?"), rec.get("path"))
    details = {
        "control_set": rec.get("control_set"),
        "entry_signature": rec.get("entry_signature"),
        "data_size": rec.get("data_size"),
    }
    yield _entry(rec.get("last_modification_time"), "reg", "appcompatcache", "reg:shimcache_seen", rec.get("path"), details, ref)


EMITTERS = {
    "usn": usn_entries,
    "mft": mft_entries,
    "pf": pf_entries,
    "eventlog": evtx_entries,
    "bam": bam_entries,
    "userassist": userassist_entries,
    "amcache_inventory_application_file": amcache_iaf_entries,
    "amcache_file": amcache_file_entries,
    "appcompatcache": appcompatcache_entries,
}


class Stats:
    def __init__(self):
        self.files_total = 0
        self.files_parsed = 0
        self.files_failed = 0
        self.records_in = 0
        self.emitted = 0
        self.skipped_no_timestamp = Counter()
        self.skipped_unknown_artifact = Counter()
        self.by_source = Counter()
        self.by_action = Counter()
        self.source_ts_min = {}
        self.source_ts_max = {}
        self.errors = []
        self.notes = []
        self.warnings = set()


def expand_inputs(inputs):
    paths = []
    for item in inputs:
        if os.path.isdir(item):
            names = []
            for name in sorted(os.listdir(item)):
                if name.lower().endswith(".jsonl"):
                    full = os.path.join(item, name)
                    if os.path.isfile(full):
                        names.append(full)
            if not names:
                raise TimelineToolError("no *.jsonl files in directory: %s" % item)
            paths.extend(names)
        else:
            paths.append(item)
    return paths


def make_filters(args):
    sources = None
    if args.source:
        sources = set()
        for item in args.source:
            for token in item.split(","):
                token = token.strip().lower()
                if not token:
                    continue
                if token not in VALID_SOURCES:
                    raise TimelineToolError("unknown source %r; valid: %s" % (token, ", ".join(VALID_SOURCES)))
                sources.add(token)
    since = parse_iso(args.since) if args.since else None
    if args.since and since is None:
        raise TimelineToolError("invalid --since timestamp: %r" % args.since)
    until = parse_iso(args.until) if args.until else None
    if args.until and until is None:
        raise TimelineToolError("invalid --until timestamp: %r" % args.until)
    if since and until and since > until:
        raise TimelineToolError("--since is later than --until")
    return {"sources": sources, "since": since, "until": until}


def _open_jsonl(path):
    if path == "-":
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(newline="\n")
        return sys.stdout, False
    return open(path, "w", encoding="utf-8", newline="\n"), True


def build_report(stats, args, inputs_meta, filters, limits):
    warnings = set(stats.warnings)
    if stats.files_failed:
        warnings.add("files_failed_to_parse")
    if stats.emitted == 0:
        warnings.add("no_records_emitted")
    if stats.errors:
        warnings.add("malformed_lines_present")
    return {
        "tool": "timeline",
        "tool_version": TOOL_VERSION,
        "schema_version": SCHEMA_VERSION,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "inputs": inputs_meta,
        "counts": {
            "files": stats.files_total,
            "parsed": stats.files_parsed,
            "failed": stats.files_failed,
            "records_in": stats.records_in,
            "emitted": stats.emitted,
            "by_source": dict(sorted(stats.by_source.items())),
            "skipped_no_timestamp": dict(sorted(stats.skipped_no_timestamp.items())),
            "skipped_unknown_artifact": dict(sorted(stats.skipped_unknown_artifact.items())),
            "top_actions": [
                {"action": action, "count": count} for action, count in stats.by_action.most_common(20)
            ],
            "source_ranges": {
                source: {"min": stats.source_ts_min.get(source), "max": stats.source_ts_max.get(source)}
                for source in sorted(set(stats.source_ts_min) | set(stats.source_ts_max))
            },
        },
        "notes": stats.notes,
        "errors": stats.errors,
        "filters": {
            "sources": sorted(filters["sources"]) if filters["sources"] else None,
            "since": args.since,
            "until": args.until,
            "limit": limits,
        },
        "warnings": sorted(warnings),
    }


def _print_summary(report, quiet):
    if quiet:
        return
    counts = report["counts"]
    sys.stderr.write(
        "[timeline] files=%d parsed=%d failed=%d records_in=%d emitted=%d by_source=%s\n"
        % (counts["files"], counts["parsed"], counts["failed"], counts["records_in"], counts["emitted"], counts["by_source"])
    )
    for error in report["errors"][:5]:
        sys.stderr.write("[timeline] error: %s line %s: %s\n" % (error.get("path"), error.get("line"), error.get("error")))
    if len(report["errors"]) > 5:
        sys.stderr.write("[timeline] ... %d more line errors (see report)\n" % (len(report["errors"]) - 5))
    if report["warnings"]:
        sys.stderr.write("[timeline] warnings: %s\n" % ", ".join(report["warnings"]))


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="timeline.py",
        description="Fuse parser JSONL outputs into one super-timeline. Methodology: references/timeline-methodology.md",
    )
    ap.add_argument("inputs", nargs="+", help="parser JSONL file(s) and/or directory(ies) containing *.jsonl")
    ap.add_argument("--source", action="append", default=None, help="filter: source(s) (repeatable/comma): usn, mft, pf, evtx, reg")
    ap.add_argument("--since", default=None, help="filter: entries at/after this ISO 8601 time (UTC)")
    ap.add_argument("--until", default=None, help="filter: entries at/before this ISO 8601 time (UTC)")
    ap.add_argument("--jsonl", default="-", help="JSONL output path ('-' = stdout, default)")
    ap.add_argument("--report", default=None, help="write machine-readable JSON report to this path")
    ap.add_argument("--limit", type=int, default=None, help="stop after N emitted entries (after sorting)")
    ap.add_argument("--quiet", action="store_true", help="suppress the stderr summary")
    args = ap.parse_args(argv)

    if args.limit is not None and args.limit <= 0:
        ap.error("--limit must be positive")

    try:
        filters = make_filters(args)
    except TimelineToolError as exc:
        sys.stderr.write("[timeline] usage error: %s\n" % exc)
        return 2
    try:
        paths = expand_inputs(args.inputs)
    except TimelineToolError as exc:
        sys.stderr.write("[timeline] fatal: %s\n" % exc)
        return 1

    stats = Stats()
    inputs_meta = []
    entries = []
    for path in paths:
        stats.files_total += 1
        try:
            fh = open(path, "rb")
        except OSError as exc:
            stats.files_failed += 1
            stats.errors.append({"path": path, "line": None, "error": "cannot_read: %s" % exc})
            continue
        digest = hashlib.sha256()
        size = 0
        source_file = os.path.basename(path)
        line_no = 0
        bad_lines = 0
        with fh:
            for blob in fh:
                digest.update(blob)
                size += len(blob)
                line_no += 1
                line = blob.decode("utf-8", errors="replace").strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except ValueError as exc:
                    bad_lines += 1
                    stats.errors.append({"path": path, "line": line_no, "error": "bad JSON: %s" % exc})
                    continue
                if not isinstance(rec, dict) or "artifact" not in rec:
                    stats.skipped_unknown_artifact["<no artifact field>"] += 1
                    continue
                artifact = rec["artifact"]
                emitter = EMITTERS.get(artifact)
                if emitter is None:
                    if artifact in NO_TIMESTAMP_ARTIFACTS:
                        stats.skipped_no_timestamp[artifact] += 1
                    else:
                        stats.skipped_unknown_artifact[artifact] += 1
                    continue
                stats.records_in += 1
                rec["_source_file"] = source_file
                for entry in emitter(rec):
                    if not entry["ts"] or parse_iso(entry["ts"]) is None:
                        stats.skipped_no_timestamp[artifact] += 1
                        continue
                    entries.append(entry)
        inputs_meta.append({"path": source_file, "size": size, "sha256": digest.hexdigest()})
        stats.files_parsed += 1
        if bad_lines:
            stats.notes.append("%s: %d malformed line(s) skipped" % (source_file, bad_lines))

    entries.sort(key=lambda e: e["ts"])

    fh, should_close = _open_jsonl(args.jsonl)
    try:
        for entry in entries:
            source = entry["source"]
            if filters["sources"] is not None and source not in filters["sources"]:
                continue
            ts = parse_iso(entry["ts"])
            if filters["since"] is not None and ts < filters["since"]:
                continue
            if filters["until"] is not None and ts > filters["until"]:
                continue
            if args.limit is not None and stats.emitted >= args.limit:
                stats.warnings.add("stopped_early_by_limit")
                break
            fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
            stats.emitted += 1
            stats.by_source[source] += 1
            stats.by_action[entry["action"]] += 1
            if source not in stats.source_ts_min or entry["ts"] < stats.source_ts_min[source]:
                stats.source_ts_min[source] = entry["ts"]
            if source not in stats.source_ts_max or entry["ts"] > stats.source_ts_max[source]:
                stats.source_ts_max[source] = entry["ts"]
    finally:
        if should_close:
            fh.close()

    report = build_report(stats, args, inputs_meta, filters, args.limit)
    if args.report:
        try:
            with open(args.report, "w", encoding="utf-8", newline="\n") as report_handle:
                json.dump(report, report_handle, indent=2, ensure_ascii=False)
                report_handle.write("\n")
        except OSError as exc:
            sys.stderr.write("[timeline] fatal: cannot write report: %s\n" % exc)
            return 1

    _print_summary(report, args.quiet)
    return 0


if __name__ == "__main__":
    sys.exit(main())
