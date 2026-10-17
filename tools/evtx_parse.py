#!/usr/bin/env python3
"""Honest parser for Windows event log exports (Phase 5, v1 = XML exports).

Structure knowledge: references/eventlogs.md (Structure Card). This tool parses
the XML produced by `wevtutil qe <channel-or-file> /f:xml` — including the
`<Events>` wrapper form, bare concatenated `<Event>` fragments, UTF-16 BOM
files and (bounded) recovery from a truncated tail. Binary EVTX files
("ElfFile") are rejected with an explicit conversion hint; a binary parser is
backlog (see ROADMAP.md Faz 5.2 notes).

Usage:
  python evtx_parse.py INPUT [INPUT ...] [--channel NAME ...] [--id N ...]

Exit codes: 0 = tool ran (per-file errors inside the report), 1 = fatal
(inputs unreadable / output not writable), 2 = usage error.
"""

import argparse
import hashlib
import json
import os
import re
import sys
from collections import Counter
from datetime import datetime, timezone
import xml.etree.ElementTree as ET

TOOL_VERSION = "0.1.0"
SCHEMA_VERSION = 1

LEVEL_NAMES = {
    0: "LogAlways",
    1: "Critical",
    2: "Error",
    3: "Warning",
    4: "Information",
    5: "Verbose",
}

XML_DECL_RE = re.compile(r"<\?xml[^>]*\?>")
EVENT_RE = re.compile(r"<Event(?=[\s>]).*?</Event>", re.S)
SYSTEMTIME_RE = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(\.\d+)?Z?$")


class EvtxToolError(RuntimeError):
    pass


class EvtxError(EvtxToolError):
    pass


# ---------------------------------------------------------------------------
# small helpers
# ---------------------------------------------------------------------------

def localname(tag):
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


def find_child(elem, name):
    for child in elem:
        if localname(child.tag) == name:
            return child
    return None


def find_children(elem, name):
    return [child for child in elem if localname(child.tag) == name]


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def normalize_systemtime(value, warnings):
    if not value:
        warnings.append("TimeCreated has no SystemTime attribute")
        return None
    match = SYSTEMTIME_RE.match(value.strip())
    if not match:
        warnings.append("unparseable TimeCreated SystemTime %r" % value)
        return None
    fraction = (match.group(2) or "")[1:]
    fraction = (fraction + "000000")[:6]
    return "%s.%sZ" % (match.group(1), fraction)


def int_or_warn(elem, field, warnings, base=10):
    if elem is None or elem.text is None:
        return None
    text = elem.text.strip()
    if not text:
        warnings.append("%s element is empty" % field)
        return None
    try:
        return int(text, base)
    except ValueError:
        warnings.append("%s value %r is not numeric" % (field, text))
        return None


def hex_int_or_warn(value, field, warnings):
    if value is None:
        return None
    try:
        return int(value, 16)
    except (TypeError, ValueError):
        warnings.append("%s value %r is not hex" % (field, value))
        return None


def iso_to_datetime(value):
    """Parse an ISO 8601 timestamp from CLI flags (naive = UTC)."""
    text = value.strip()
    if text.endswith("Z") or text.endswith("z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        raise EvtxToolError("invalid ISO 8601 timestamp: %r" % value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def record_time(rec):
    value = rec.get("time_created")
    if not value:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


# ---------------------------------------------------------------------------
# input loading (encoding detection + binary rejection)
# ---------------------------------------------------------------------------

def load_text(raw, path):
    if not raw.strip():
        raise EvtxError("empty input file")
    if raw[:8].startswith(b"ElfFile"):
        raise EvtxError(
            "binary EVTX file (ElfFile) is not supported by this tool — v1 parses XML exports only. "
            "Convert first: wevtutil qe \"%s\" /f:xml /lf:true > out.xml" % path
        )
    if raw.startswith(b"\xff\xfe") or raw.startswith(b"\xfe\xff"):
        return raw.decode("utf-16"), "utf-16"
    if raw.startswith(b"\xef\xbb\xbf"):
        return raw[3:].decode("utf-8"), "utf-8-sig"
    if b"\x00" in raw[:512]:
        raise EvtxError("input looks binary (NUL bytes) and is neither EVTX (ElfFile) nor XML text")
    try:
        return raw.decode("utf-8"), "utf-8"
    except UnicodeDecodeError:
        pass
    for encoding in ("cp1254", "cp857"):
        try:
            return raw.decode(encoding), encoding
        except UnicodeDecodeError:
            continue
    return raw.decode("latin-1"), "latin-1"


# ---------------------------------------------------------------------------
# XML event extraction
# ---------------------------------------------------------------------------

def extract_events(text):
    """Return (event_elements, notes). Handles <Events> roots, bare fragments,
    multiple XML declarations and a truncated tail (bounded recovery)."""
    notes = []
    cleaned = text.lstrip("\ufeff \t\r\n")
    cleaned = XML_DECL_RE.sub("", cleaned).strip()
    if not cleaned:
        raise EvtxError("no XML content found after removing declarations")

    try:
        root = ET.fromstring(cleaned)
    except ET.ParseError:
        root = None

    if root is not None:
        name = localname(root.tag)
        if name == "Event":
            return [root], notes
        if name == "Events":
            events = []
            skipped = 0
            for child in root:
                if localname(child.tag) == "Event":
                    events.append(child)
                else:
                    skipped += 1
            if skipped:
                notes.append("<Events> wrapper contained %d non-<Event> child element(s); skipped" % skipped)
            if not events:
                raise EvtxError("<Events> wrapper contains no <Event> elements")
            return events, notes
        raise EvtxError(
            "root element <%s> is not an event log export (expected <Event> or <Events>)" % name
        )

    recovered = EVENT_RE.findall(cleaned)
    if not recovered:
        try:
            ET.fromstring("<evtxwrap>" + cleaned + "</evtxwrap>")
        except ET.ParseError as exc:
            raise EvtxError("cannot parse XML: %s" % exc)
        raise EvtxError("XML parsed but no <Event> elements were found")
    notes.append(
        "recovered %d complete <Event> element(s) via fragment scan (file is not a single well-formed XML document)"
        % len(recovered)
    )
    first_start = cleaned.find("<Event")
    if first_start > 0 and cleaned[:first_start].strip():
        notes.append("ignored non-event content before the first <Event> element")
    last_end = cleaned.rfind("</Event>")
    tail = cleaned[last_end + len("</Event>"):]
    if tail.strip():
        notes.append("discarded %d trailing character(s) after the last complete </Event>" % len(tail.strip()))
    events = []
    for index, fragment in enumerate(recovered):
        try:
            events.append(ET.fromstring(fragment))
        except ET.ParseError as exc:
            notes.append("event fragment %d ignored (unparseable: %s)" % (index + 1, exc))
    if not events:
        raise EvtxError("all recovered <Event> fragments were unparseable")
    return events, notes


# ---------------------------------------------------------------------------
# event field extraction
# ---------------------------------------------------------------------------

def xml_to_obj(elem):
    children = list(elem)
    if not children:
        return (elem.text or "").strip()
    obj = {}
    for attr, value in elem.attrib.items():
        obj["@" + attr] = value
    for child in children:
        key = localname(child.tag)
        value = xml_to_obj(child)
        if key in obj:
            if not isinstance(obj[key], list):
                obj[key] = [obj[key]]
            obj[key].append(value)
        else:
            obj[key] = value
    return obj


def parse_event_data(elem, warnings):
    data = {}
    for index, child in enumerate(elem):
        tag = localname(child.tag)
        if tag == "Data":
            name = child.attrib.get("Name") or ("Data[%d]" % index)
        elif tag == "Binary":
            name = "Binary"
        else:
            warnings.append("unexpected <%s> inside EventData" % tag)
            continue
        text = (child.text or "").strip()
        if name in data:
            warnings.append("duplicate EventData name %r" % name)
            suffix = 2
            while "%s#%d" % (name, suffix) in data:
                suffix += 1
            data["%s#%d" % (name, suffix)] = text
        else:
            data[name] = text
    return data


def parse_event(elem, source_file, source_sha, include_raw):
    warnings = []
    rec = {
        "tool": "evtx_parse.py",
        "schema_version": SCHEMA_VERSION,
        "artifact": "eventlog",
        "source_file": source_file,
        "source_sha256": source_sha,
        "channel": None,
        "provider": None,
        "provider_guid": None,
        "event_id": None,
        "event_id_qualifiers": None,
        "version": None,
        "level": None,
        "level_name": None,
        "task": None,
        "opcode": None,
        "keywords": None,
        "time_created": None,
        "record_id": None,
        "computer": None,
        "security_user_id": None,
        "execution_process_id": None,
        "execution_thread_id": None,
        "activity_id": None,
        "related_activity_id": None,
        "event_data": {},
        "user_data": None,
        "warnings": warnings,
    }

    system = find_child(elem, "System")
    if system is None:
        warnings.append("event has no <System> section")
    else:
        provider = find_child(system, "Provider")
        if provider is not None:
            rec["provider"] = provider.attrib.get("Name")
            rec["provider_guid"] = provider.attrib.get("Guid")
        else:
            warnings.append("System has no <Provider>")

        event_id = find_child(system, "EventID")
        if event_id is not None:
            rec["event_id"] = int_or_warn(event_id, "EventID", warnings)
            if "Qualifiers" in event_id.attrib:
                try:
                    rec["event_id_qualifiers"] = int(event_id.attrib["Qualifiers"], 10)
                except ValueError:
                    warnings.append("EventID Qualifiers value %r is not numeric" % event_id.attrib["Qualifiers"])
        else:
            warnings.append("System has no <EventID>")

        rec["version"] = int_or_warn(find_child(system, "Version"), "Version", warnings)
        level_el = find_child(system, "Level")
        rec["level"] = int_or_warn(level_el, "Level", warnings)
        if rec["level"] is not None:
            rec["level_name"] = LEVEL_NAMES.get(rec["level"])
        rec["task"] = int_or_warn(find_child(system, "Task"), "Task", warnings)
        rec["opcode"] = int_or_warn(find_child(system, "Opcode"), "Opcode", warnings)

        keywords = find_child(system, "Keywords")
        if keywords is not None and keywords.text:
            rec["keywords"] = keywords.text.strip()

        time_el = find_child(system, "TimeCreated")
        if time_el is not None:
            rec["time_created"] = normalize_systemtime(time_el.attrib.get("SystemTime"), warnings)
        else:
            warnings.append("System has no <TimeCreated>")

        rec["record_id"] = int_or_warn(find_child(system, "EventRecordID"), "EventRecordID", warnings)

        correlation = find_child(system, "Correlation")
        if correlation is not None:
            rec["activity_id"] = correlation.attrib.get("ActivityID")
            rec["related_activity_id"] = correlation.attrib.get("RelatedActivityID")

        execution = find_child(system, "Execution")
        if execution is not None:
            rec["execution_process_id"] = hex_int_or_warn(execution.attrib.get("ProcessID"), "Execution ProcessID", warnings)
            rec["execution_thread_id"] = hex_int_or_warn(execution.attrib.get("ThreadID"), "Execution ThreadID", warnings)

        channel = find_child(system, "Channel")
        rec["channel"] = channel.text.strip() if channel is not None and channel.text else None
        computer = find_child(system, "Computer")
        rec["computer"] = computer.text.strip() if computer is not None and computer.text else None
        security = find_child(system, "Security")
        if security is not None:
            rec["security_user_id"] = security.attrib.get("UserID")

    event_data = find_child(elem, "EventData")
    user_data = find_child(elem, "UserData")
    if event_data is not None:
        rec["event_data"] = parse_event_data(event_data, warnings)
    if user_data is not None:
        rec["user_data"] = xml_to_obj(user_data)

    if include_raw:
        raw_xml = ET.tostring(elem, encoding="unicode")
        if len(raw_xml) > 65536:
            raw_xml = raw_xml[:65536]
            warnings.append("raw_xml truncated to 65536 characters")
        rec["raw_xml"] = raw_xml

    return rec


# ---------------------------------------------------------------------------
# stats / filters / report
# ---------------------------------------------------------------------------

class Stats:
    def __init__(self):
        self.files_total = 0
        self.files_parsed = 0
        self.files_failed = 0
        self.events_total = 0
        self.emitted = 0
        self.filtered_out = 0
        self.by_channel = Counter()
        self.by_provider = Counter()
        self.by_event_id = Counter()
        self.warning_counts = Counter()
        self.errors = []
        self.notes = []
        self.warnings = set()

    def count_warning_for(self, messages):
        for message in messages:
            self.warning_counts[message] += 1


def make_filters(args):
    ids = None
    if args.id:
        ids = set()
        for item in args.id:
            for token in str(item).split(","):
                token = token.strip()
                if not token:
                    continue
                try:
                    ids.add(int(token))
                except ValueError:
                    raise EvtxToolError("--id values must be integers, got %r" % token)
    channels = None
    if args.channel:
        channels = set()
        for item in args.channel:
            for token in item.split(","):
                token = token.strip().lower()
                if token:
                    channels.add(token)
    provider = args.provider.strip().lower() if args.provider else None
    since = iso_to_datetime(args.since) if args.since else None
    until = iso_to_datetime(args.until) if args.until else None
    if since and until and since > until:
        raise EvtxToolError("--since is later than --until")
    return {"ids": ids, "channels": channels, "provider": provider, "since": since, "until": until}


def passes_filters(rec, filters):
    if filters["ids"] is not None and rec["event_id"] not in filters["ids"]:
        return False
    if filters["channels"] is not None and (rec["channel"] or "").lower() not in filters["channels"]:
        return False
    if filters["provider"] is not None and filters["provider"] not in (rec["provider"] or "").lower():
        return False
    if filters["since"] is not None or filters["until"] is not None:
        ts = record_time(rec)
        if ts is None:
            return False
        if filters["since"] is not None and ts < filters["since"]:
            return False
        if filters["until"] is not None and ts > filters["until"]:
            return False
    return True


def expand_inputs(inputs):
    paths = []
    for item in inputs:
        if os.path.isdir(item):
            names = []
            for name in sorted(os.listdir(item)):
                if name.lower().endswith((".xml", ".evtx")):
                    full = os.path.join(item, name)
                    if os.path.isfile(full):
                        names.append(full)
            if not names:
                raise EvtxToolError("no candidate event-log files (*.xml, *.evtx) in directory: %s" % item)
            paths.extend(names)
        else:
            paths.append(item)
    return paths


def _open_jsonl(path):
    if path == "-":
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(newline="\n")
        return sys.stdout, False
    return open(path, "w", encoding="utf-8", newline="\n"), True


def build_report(stats, args, inputs_meta, filters):
    warnings = set(stats.warnings)
    if stats.files_failed:
        warnings.add("files_failed_to_parse")
    if stats.emitted == 0:
        warnings.add("no_records_emitted")
    return {
        "tool": "evtx_parse",
        "tool_version": TOOL_VERSION,
        "schema_version": SCHEMA_VERSION,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "mode": "offline-xml",
        "inputs": inputs_meta,
        "counts": {
            "files": stats.files_total,
            "parsed": stats.files_parsed,
            "failed": stats.files_failed,
            "events_total": stats.events_total,
            "emitted": stats.emitted,
            "filtered_out": stats.filtered_out,
            "by_channel": dict(sorted(stats.by_channel.items())),
            "by_provider": dict(sorted(stats.by_provider.items())),
            "top_event_ids": [
                {"event_id": event_id, "count": count}
                for event_id, count in stats.by_event_id.most_common(20)
            ],
        },
        "warning_counts": dict(sorted(stats.warning_counts.items())),
        "notes": stats.notes,
        "errors": stats.errors,
        "filters": {
            "channels": sorted(filters["channels"]) if filters["channels"] else None,
            "event_ids": sorted(filters["ids"]) if filters["ids"] else None,
            "provider": filters["provider"],
            "since": args.since,
            "until": args.until,
            "limit": args.limit,
            "raw": bool(args.raw),
        },
        "warnings": sorted(warnings),
    }


def _print_summary(report, quiet):
    if quiet:
        return
    counts = report["counts"]
    sys.stderr.write(
        "[evtx_parse] files=%d parsed=%d failed=%d events=%d emitted=%d filtered_out=%d\n"
        % (counts["files"], counts["parsed"], counts["failed"], counts["events_total"], counts["emitted"], counts["filtered_out"])
    )
    for error in report["errors"]:
        sys.stderr.write("[evtx_parse] error: %s: %s\n" % (error.get("path", "?"), error.get("error", "")))
    for note in report["notes"]:
        sys.stderr.write("[evtx_parse] note: %s\n" % note)
    if report["warnings"]:
        sys.stderr.write("[evtx_parse] warnings: %s\n" % ", ".join(report["warnings"]))


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="evtx_parse.py",
        description="Honest parser for wevtutil XML event exports. Structure knowledge: references/eventlogs.md",
    )
    ap.add_argument("inputs", nargs="+", help="XML export file(s) and/or directory(ies) containing *.xml/*.evtx exports")
    ap.add_argument("--channel", action="append", default=None, help="filter: channel name(s) (repeatable / comma-separated, case-insensitive exact)")
    ap.add_argument("--id", action="append", default=None, help="filter: EventID(s) (repeatable / comma-separated)")
    ap.add_argument("--provider", default=None, help="filter: provider name substring (case-insensitive)")
    ap.add_argument("--since", default=None, help="filter: include events at/after this ISO 8601 time (UTC)")
    ap.add_argument("--until", default=None, help="filter: include events at/before this ISO 8601 time (UTC)")
    ap.add_argument("--jsonl", default="-", help="JSONL output path ('-' = stdout, default)")
    ap.add_argument("--report", default=None, help="write machine-readable JSON report to this path")
    ap.add_argument("--raw", action="store_true", help="include the event re-serialized as XML (capped at 64 KiB per event)")
    ap.add_argument("--limit", type=int, default=None, help="stop after N emitted records")
    ap.add_argument("--quiet", action="store_true", help="suppress the stderr summary")
    args = ap.parse_args(argv)

    if args.limit is not None and args.limit <= 0:
        ap.error("--limit must be positive")

    try:
        filters = make_filters(args)
        paths = expand_inputs(args.inputs)
    except EvtxToolError as exc:
        sys.stderr.write("[evtx_parse] fatal: %s\n" % exc)
        return 1

    stats = Stats()
    inputs_meta = []
    fh, should_close = _open_jsonl(args.jsonl)
    try:
        for path in paths:
            stats.files_total += 1
            try:
                with open(path, "rb") as source_handle:
                    raw_bytes = source_handle.read()
                sha = sha256_bytes(raw_bytes)
                text, encoding = load_text(raw_bytes, path)
                events, notes = extract_events(text)
            except EvtxError as exc:
                stats.files_failed += 1
                stats.errors.append({"path": path, "error": str(exc)})
                continue
            except OSError as exc:
                stats.files_failed += 1
                stats.errors.append({"path": path, "error": "cannot_read: %s" % exc})
                continue

            inputs_meta.append(
                {"path": os.path.basename(path), "size": len(raw_bytes), "sha256": sha, "encoding": encoding}
            )
            if encoding not in ("utf-8", "utf-8-sig", "utf-16"):
                stats.warnings.add("non_utf8_encoding_used")
                stats.notes.append("%s decoded as %s (not UTF)" % (os.path.basename(path), encoding))
            for note in notes:
                stats.notes.append("%s: %s" % (os.path.basename(path), note))

            file_events = 0
            for elem in events:
                rec = parse_event(elem, os.path.basename(path), sha, args.raw)
                stats.events_total += 1
                file_events += 1
                stats.count_warning_for(rec["warnings"])
                if not passes_filters(rec, filters):
                    stats.filtered_out += 1
                    continue
                fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
                stats.emitted += 1
                stats.by_channel[rec["channel"] or "?"] += 1
                stats.by_provider[rec["provider"] or "?"] += 1
                stats.by_event_id[rec["event_id"]] += 1
                if args.limit is not None and stats.emitted >= args.limit:
                    stats.warnings.add("stopped_early_by_limit")
                    break
            stats.files_parsed += 1
            if args.limit is not None and stats.emitted >= args.limit:
                break
    finally:
        if should_close:
            fh.close()

    report = build_report(stats, args, inputs_meta, filters)
    if args.report:
        try:
            with open(args.report, "w", encoding="utf-8", newline="\n") as report_handle:
                json.dump(report, report_handle, indent=2, ensure_ascii=False)
                report_handle.write("\n")
        except OSError as exc:
            sys.stderr.write("[evtx_parse] fatal: cannot write report: %s\n" % exc)
            return 1

    _print_summary(report, args.quiet)
    return 0


if __name__ == "__main__":
    sys.exit(main())
