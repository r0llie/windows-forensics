"""Cross-validation engine for the windows-forensics skill (Phase 8).

Implements the 10 rules of references/timeline-methodology.md section 5 as
automated findings. Consumes raw parser JSONL (same discovery as timeline.py)
and emits findings with severity, rationale and source refs. Rules that lack
the inputs they need are skipped honestly, never guessed.

Usage:
    python tools/validate.py <jsonl-or-dir>... [--jsonl out.jsonl] [--report out.json]
                             [--rules 1,2,5] [--examples 10] [--quiet]

Exit codes: 0 = ran (findings and per-file errors are data), 1 = fatal, 2 = usage.
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone

TOOLS_DIR = os.path.dirname(os.path.abspath(__file__))
if TOOLS_DIR not in sys.path:
    sys.path.insert(0, TOOLS_DIR)

import timeline  # noqa: E402  (expand_inputs, parse_iso reuse)

TOOL_VERSION = "0.1.0"
SCHEMA_VERSION = 1

RULE_NAMES = {
    1: "execution_without_file_evidence",
    2: "timestomp_si_vs_fn",
    3: "service_install_without_file_create",
    4: "log_clear_or_record_gaps",
    5: "bam_without_prefetch_or_userassist",
    6: "amcache_link_date_before_si_created",
    7: "pending_rename_without_usn_activity",
    8: "unexpected_shutdown_uncorroborated",
    9: "process_creation_without_execution_artifacts",
    10: "userassist_run_outside_bam_window",
}

LOG_CLEAR_IDS = {104, 1102}
SHUTDOWN_MARKER_IDS = {6008, 41}
SHUTDOWN_INTENT_IDS = {6006, 1074}

SERVICE_INSTALL_ID = 7045
PROCESS_CREATION_ID = 4688

USN_CREATE_FLAG = "FILE_CREATE"
SERVICE_WINDOW_SECONDS = 600
SHUTDOWN_PRIOR_WINDOW_SECONDS = 24 * 3600
CLUSTER_WINDOW_SECONDS = 300
RECREATION_ID_THRESHOLD = 1000


class ValidateToolError(Exception):
    pass


def base_name(path):
    if not path:
        return ""
    text = str(path).strip().strip('"')
    for prefix in ("\\??\\", "\\\\?\\", "\\SystemRoot\\"):
        if text.lower().startswith(prefix.lower()):
            text = text[len(prefix):]
            break
    text = text.replace("/", "\\").rstrip("\\")
    if not text:
        return ""
    return text.split("\\")[-1].lower()


def _dt(value):
    return timeline.parse_iso(value) if value else None


def _ref(artifact, rec):
    if artifact == "usn":
        return "%s#usn=%s" % (rec.get("_source_file", "?"), rec.get("usn"))
    if artifact == "mft":
        return "%s#record=%s" % (rec.get("_source_file", "?"), rec.get("record_number"))
    if artifact == "pf":
        return "%s#last_run" % rec.get("_source_file", "?")
    if artifact == "evtx":
        src = rec.get("source_file") or rec.get("_source_file", "?")
        return "%s#record=%s" % (src, rec.get("record_id"))
    if artifact == "bam":
        return "%s#%s" % (rec.get("hive", "?"), rec.get("path"))
    if artifact == "userassist":
        return "%s#%s\\%s" % (rec.get("hive", "?"), rec.get("guid"), rec.get("name"))
    if artifact == "amcache_inventory_application_file":
        return "%s#%s" % (rec.get("hive", "?"), rec.get("key_name") or rec.get("path"))
    if artifact == "pending_file_rename_operations":
        return "%s#%s" % (rec.get("hive", "?"), rec.get("source"))
    return "%s#%s" % (rec.get("_source_file", "?"), rec.get("artifact", "?"))


def _project(artifact, rec):
    """Keep only the fields rules consult for very large artifacts ($MFT)."""
    if artifact == "mft":
        si = rec.get("standard_information") or {}
        fns = rec.get("file_names") or []
        return {
            "record_number": rec.get("record_number"),
            "primary_name": rec.get("primary_name"),
            "in_use": rec.get("in_use"),
            "timestomp_flags": rec.get("timestomp_flags") or [],
            "standard_information": {"created": si.get("created"), "modified": si.get("modified"), "accessed": si.get("accessed")},
            "file_names": [{"created": fns[0].get("created")}] if fns else [],
            "_source_file": rec.get("_source_file"),
        }
    return rec


def load_records(paths):
    """Read parser JSONL files into per-artifact lists. Honest per-line errors."""
    data = {
        "usn": [],
        "mft": [],
        "pf": [],
        "evtx": [],
        "bam": [],
        "userassist": [],
        "amcache_inventory_application_file": [],
        "pending_file_rename_operations": [],
    }
    stats = {"files": 0, "parsed": 0, "failed": 0, "lines": 0, "errors": []}
    known = set(data) | {"eventlog"} | set(timeline.NO_TIMESTAMP_ARTIFACTS)
    for path in paths:
        stats["files"] += 1
        try:
            fh = open(path, encoding="utf-8")
        except OSError as exc:
            stats["failed"] += 1
            stats["errors"].append({"path": path, "error": "cannot open: %s" % exc})
            continue
        bad = 0
        with fh:
            for line_no, line in enumerate(fh, 1):
                line = line.strip()
                if not line:
                    continue
                stats["lines"] += 1
                try:
                    rec = json.loads(line)
                except ValueError:
                    bad += 1
                    if len(stats["errors"]) < 50:
                        stats["errors"].append({"path": path, "line": line_no, "error": "malformed JSON"})
                    continue
                artifact = rec.get("artifact")
                if artifact == "eventlog":
                    artifact = "evtx"
                if artifact in data:
                    rec["_source_file"] = os.path.basename(path)
                    data[artifact].append(_project(artifact, rec))
                elif artifact not in known:
                    pass
        if bad:
            stats["failed"] += 1
        else:
            stats["parsed"] += 1
    return data, stats


def _finding(rule, severity, title, count, examples, rationale, extra=None):
    finding = {
        "rule": rule,
        "name": RULE_NAMES[rule],
        "severity": severity,
        "title": title,
        "count": count,
        "examples": examples,
        "rationale": rationale,
    }
    if extra:
        finding.update(extra)
    return finding


def _capped(examples, limit):
    examples = sorted(examples, key=lambda e: (e.get("time") or "", e.get("ref") or ""))
    return examples[:limit]


def ua_target(rec):
    return rec.get("target") or rec.get("name") or rec.get("value_name_raw") or ""


def rule_execution_without_file_evidence(data, limit):
    claims = {}

    def add_claim(kind, path, time_value, artifact, rec):
        base = base_name(path)
        if not base or "." not in base:
            return
        entry = claims.setdefault(base, {"kinds": set(), "example": None})
        entry["kinds"].add(kind)
        if entry["example"] is None:
            entry["example"] = {"exe": base, "claim": kind, "time": time_value, "ref": _ref(artifact, rec), "path": path}

    for rec in data["pf"]:
        add_claim("prefetch_run", rec.get("executable"), rec.get("last_run_time") or (rec.get("run_times") or [None])[0], "pf", rec)
    for rec in data["bam"]:
        add_claim("bam", rec.get("path"), rec.get("execution_time"), "bam", rec)
    for rec in data["amcache_inventory_application_file"]:
        add_claim("amcache", rec.get("path"), rec.get("link_date_ts"), "amcache_inventory_application_file", rec)
    for rec in data["userassist"]:
        target = ua_target(rec)
        if "\\" in target or ":" in target:
            add_claim("userassist", target, rec.get("last_run_time"), "userassist", rec)
    for rec in data["evtx"]:
        if rec.get("event_id") == PROCESS_CREATION_ID:
            name = (rec.get("event_data") or {}).get("NewProcessName")
            if name:
                add_claim("event_4688", name, rec.get("time_created"), "evtx", rec)

    evidence = set()
    for rec in data["usn"]:
        base = base_name(rec.get("name"))
        if base:
            evidence.add(base)
    for rec in data["mft"]:
        base = base_name(rec.get("primary_name"))
        if base:
            evidence.add(base)

    missing = [c["example"] for base, c in sorted(claims.items()) if base not in evidence and c["example"]]
    for example in missing:
        example["claim"] = "+".join(sorted(claims[example["exe"]]["kinds"]))
    rationale = (
        "Execution-type claims exist for these images, but no USN record or $MFT entry ever mentions the basename. "
        "The file may have been deleted with the journal wrapped, or the evidence windows do not overlap. "
        "Absence of evidence is not evidence of absence (usn.md trap 8) - treat as unresolved, not as a verdict."
    )
    return _finding(
        1, "info", "Execution claims without any USN/MFT file evidence",
        len(missing), _capped(missing, limit), rationale,
        {"coverage_note": "evidence base: %d USN names + %d MFT names" % (
            len(set(base_name(r.get("name")) for r in data["usn"])), len(data["mft"]))},
    )


def rule_timestomp_si_vs_fn(data, limit):
    flagged = []
    by_reason = {}
    by_parser_flag = {}
    for rec in data["mft"]:
        si = rec.get("standard_information") or {}
        created = si.get("created")
        fns = rec.get("file_names") or []
        fn_created = fns[0].get("created") if fns else None
        reasons = []
        if created and fn_created:
            c = _dt(created)
            f = _dt(fn_created)
            if c and f and (c - f).total_seconds() >= 1:
                reasons.append("si_created_after_fn_created")
        times = [t for t in (si.get("created"), si.get("modified"), si.get("accessed")) if t]
        if len(times) >= 2 and len(set(times)) == 1 and times[0].endswith(".000000Z"):
            reasons.append("si_all_equal_whole_second")
        for flag in rec.get("timestomp_flags") or []:
            by_parser_flag[flag] = by_parser_flag.get(flag, 0) + 1
        if not reasons:
            continue
        for reason in reasons:
            by_reason[reason] = by_reason.get(reason, 0) + 1
        flagged.append({
            "name": rec.get("primary_name"),
            "reasons": reasons,
            "si_created": created,
            "fn_created": fn_created,
            "deleted": not rec.get("in_use"),
            "parser_flags": rec.get("timestomp_flags") or [],
            "time": created,
            "ref": _ref("mft", rec),
        })
    rationale = (
        "Card rule 2: $SI created more than 1s after $FN created, or all $SI timestamps identical at whole-second "
        "precision (batched timestomp signature). Parser flags (si_whole_second_precision, si_created_before_fn_created) "
        "are observations often caused by normal install/copy flows - they are reported separately, not treated as the rule. "
        "Never a verdict alone; cross-check USN write history (mft.md section 10)."
    )
    return _finding(
        2, "medium", "Files whose $SI/$FN timestamps contradict (card rule 2 signatures)",
        len(flagged), _capped(flagged, limit), rationale,
        {"by_reason": dict(sorted(by_reason.items())), "by_parser_flag_observation": dict(sorted(by_parser_flag.items()))},
    )


def rule_service_install_without_file_create(data, limit):
    usn_creates = {}
    usn_min = None
    for rec in data["usn"]:
        base = base_name(rec.get("name"))
        ts = rec.get("timestamp")
        if not base or not ts:
            continue
        if usn_min is None or ts < usn_min:
            usn_min = ts
        if USN_CREATE_FLAG in (rec.get("reason_flags") or []):
            usn_creates.setdefault(base, []).append(ts)
    hits = []
    coverage_limited = 0
    matched = 0
    for rec in data["evtx"]:
        if rec.get("event_id") != SERVICE_INSTALL_ID:
            continue
        ed = rec.get("event_data") or {}
        image = ed.get("ImagePath") or ""
        base = base_name(image)
        ts = rec.get("time_created")
        if not base or not ts:
            continue
        if usn_min is None or ts < usn_min:
            coverage_limited += 1
            continue
        window = [_dt(t) for t in usn_creates.get(base, []) if t]
        event_dt = _dt(ts)
        near = any(w and abs((w - event_dt).total_seconds()) <= SERVICE_WINDOW_SECONDS for w in window)
        if near:
            matched += 1
        else:
            hits.append({
                "service": ed.get("ServiceName"),
                "image_path": image,
                "time": ts,
                "ref": _ref("evtx", rec),
            })
    rationale = (
        "Service installs (7045) whose ImagePath has no USN FILE_CREATE within +/-%ds of the event: the service was "
        "installed from a pre-existing file or the USN ring no longer covers that time. A missing pair is a lead, not tampering."
        % SERVICE_WINDOW_SECONDS
    )
    return _finding(
        3, "low", "Service installs without a nearby USN FILE_CREATE for the image",
        len(hits), _capped(hits, limit), rationale,
        {"coverage_note": "matched %d, coverage-limited (event outside USN window) %d" % (matched, coverage_limited)},
    )


def rule_log_clear_or_record_gaps(data, limit):
    clears = []
    for rec in data["evtx"]:
        if rec.get("event_id") in LOG_CLEAR_IDS:
            clears.append({
                "event_id": rec.get("event_id"),
                "channel": rec.get("channel"),
                "time": rec.get("time_created"),
                "ref": _ref("evtx", rec),
            })
    by_channel = {}
    for rec in data["evtx"]:
        by_channel.setdefault(rec.get("channel") or "?", []).append(rec)
    channel_rows = []
    discontinuities = []
    missing_total = 0
    for channel, recs in sorted(by_channel.items()):
        ids = sorted(set(r.get("record_id") for r in recs if r.get("record_id") is not None))
        if not ids:
            continue
        span = ids[-1] - ids[0] + 1
        missing = span - len(ids)
        missing_total += missing
        channel_rows.append({
            "channel": channel,
            "records": len(recs),
            "id_range": [ids[0], ids[-1]],
            "missing_ids": missing,
        })
        max_seen = -1
        for rec in sorted(recs, key=lambda r: (r.get("time_created") or "", r.get("record_id") or 0)):
            rid = rec.get("record_id")
            if rid is None:
                continue
            if max_seen - rid > RECREATION_ID_THRESHOLD:
                discontinuities.append({
                    "channel": channel,
                    "type": "id_drop_after_higher",
                    "seen_max": max_seen,
                    "id": rid,
                    "time": rec.get("time_created"),
                    "ref": _ref("evtx", rec),
                })
            if rid > max_seen:
                max_seen = rid
    examples = clears + sorted(discontinuities, key=lambda e: e["time"] or "")
    rationale = (
        "Log-clear events (1102 Security / 104 System-Application) or EventRecordID continuity breaks. Missing IDs inside a "
        "channel's observed range and id drops >%d after higher IDs suggest clearing or recreation (or selective export); "
        "small id/time inversions are normal write-order races and are ignored." % RECREATION_ID_THRESHOLD
    )
    return _finding(
        4, "medium", "Log-clear events or EventRecordID continuity breaks",
        len(clears) + missing_total + len(discontinuities), _capped(examples, limit), rationale,
        {"log_clear_events": len(clears), "missing_record_ids": missing_total,
         "discontinuities": len(discontinuities), "channels": channel_rows},
    )


def rule_bam_without_prefetch_or_userassist(data, limit):
    pf_bases = set(base_name(r.get("executable")) for r in data["pf"] if r.get("executable"))
    ua_bases = set(base_name(ua_target(r)) for r in data["userassist"] if ua_target(r))
    seen = {}
    for rec in data["bam"]:
        base = base_name(rec.get("path"))
        if not base or base in pf_bases or base in ua_bases:
            continue
        if base not in seen:
            seen[base] = {
                "exe": base,
                "path": rec.get("path"),
                "user_sid": rec.get("user_sid"),
                "time": rec.get("execution_time"),
                "ref": _ref("bam", rec),
            }
    rationale = (
        "BAM records a launch but neither Prefetch shows a run nor UserAssist shows an Explorer launch. Mechanism may be "
        "a scheduled task/service, a UWP/URI launch, or the other artifacts were trimmed (prefetch caps, UA per-entry). "
        "BAM only covers roughly the last 7 days."
    )
    return _finding(
        5, "low", "BAM executions with no Prefetch run and no UserAssist entry",
        len(seen), _capped(list(seen.values()), limit), rationale,
        {"coverage_note": "prefetch names: %d, userassist targets: %d" % (len(pf_bases), len(ua_bases))},
    )


def rule_amcache_link_date_before_si_created(data, limit):
    mft_in_use = {}
    mft_any = {}
    for rec in data["mft"]:
        base = base_name(rec.get("primary_name"))
        if not base:
            continue
        si_created = (rec.get("standard_information") or {}).get("created")
        if not si_created:
            continue
        mft_any.setdefault(base, si_created)
        if rec.get("in_use") and base not in mft_in_use:
            mft_in_use[base] = si_created
    hits = []
    matched = 0
    for rec in data["amcache_inventory_application_file"]:
        link = rec.get("link_date_ts")
        base = base_name(rec.get("path"))
        si_created = mft_in_use.get(base) or mft_any.get(base)
        if not link or not si_created:
            continue
        matched += 1
        if link < si_created:
            delta = (_dt(si_created) - _dt(link)).total_seconds()
            hits.append({
                "name": rec.get("name") or base,
                "path": rec.get("path"),
                "link_date_ts": link,
                "si_created": si_created,
                "delta_seconds": int(delta),
                "time": link,
                "ref": _ref("amcache_inventory_application_file", rec),
            })
    rationale = (
        "Amcache recorded the file older than its $SI creation time claims. Amcache link dates of copied/staged files can "
        "predate local creation legitimately (inventory of a temp lineage); investigate the gap direction and size."
    )
    return _finding(
        6, "info", "Amcache link date older than the file's $SI creation",
        len(hits), _capped(hits, limit), rationale,
        {"coverage_note": "comparable pairs: %d" % matched},
    )


def rule_pending_rename_without_usn_activity(data, limit):
    usn_names = set(base_name(r.get("name")) for r in data["usn"] if r.get("name"))
    hits = []
    for rec in data["pending_file_rename_operations"]:
        involved = [base_name(rec.get("source")), base_name(rec.get("destination"))]
        involved = [b for b in involved if b]
        if not involved:
            continue
        if all(b not in usn_names for b in involved):
            hits.append({
                "source": rec.get("source"),
                "destination": rec.get("destination"),
                "operation": rec.get("operation"),
                "ref": _ref("pending_file_rename_operations", rec),
            })
    rationale = (
        "PendingFileRenameOperations entries name paths with zero USN records in the captured journal. The operation was "
        "set long ago, happened in another session, or the journal wrapped past it - pending ops persist until processed."
    )
    return _finding(
        7, "low", "Pending file renames whose paths have no USN activity",
        len(hits), _capped(hits, limit), rationale,
    )


def _cluster_events(events):
    events = sorted(events, key=lambda e: e.get("time_created") or "")
    clusters = []
    for rec in events:
        ts = _dt(rec.get("time_created"))
        if ts is None:
            continue
        if clusters:
            first_ts = _dt(clusters[-1][0].get("time_created"))
            if first_ts and abs((ts - first_ts).total_seconds()) <= CLUSTER_WINDOW_SECONDS:
                clusters[-1].append(rec)
                continue
        clusters.append([rec])
    return clusters


def rule_unexpected_shutdown(data, limit):
    markers = [r for r in data["evtx"] if r.get("event_id") in SHUTDOWN_MARKER_IDS]
    intents = sorted(
        (r for r in data["evtx"] if r.get("event_id") in SHUTDOWN_INTENT_IDS),
        key=lambda r: r.get("time_created") or "",
    )
    findings = []
    for cluster in _cluster_events(markers):
        first_ts = _dt(cluster[0].get("time_created"))
        prior = None
        for rec in intents:
            rec_ts = _dt(rec.get("time_created"))
            if rec_ts is None or rec_ts > first_ts:
                continue
            if (first_ts - rec_ts).total_seconds() <= SHUTDOWN_PRIOR_WINDOW_SECONDS:
                prior = rec
        prior_info = None
        if prior is not None:
            ed = prior.get("event_data") or {}
            prior_info = {
                "event_id": prior.get("event_id"),
                "time": prior.get("time_created"),
                "ref": _ref("evtx", prior),
                "param3": ed.get("param3"),
            }
        findings.append({
            "time": cluster[0].get("time_created"),
            "event_ids": sorted(set(r.get("event_id") for r in cluster)),
            "ref": _ref("evtx", cluster[0]),
            "prior_shutdown_intent": prior_info,
        })
    uncorroborated = [f for f in findings if f["prior_shutdown_intent"] is None]
    rationale = (
        "Kernel-Power 41 / EventLog 6008 clusters. A 1074/6006 within the prior %ds is listed as (weak) intent - note that "
        "1074 with 'Other (Unplanned)' does not contradict a crash. Cross-check registry dirty-hive warnings; the absence "
        "of a clean shutdown record this far back is common, not proof of tampering."
        % SHUTDOWN_PRIOR_WINDOW_SECONDS
    )
    return _finding(
        8, "medium" if uncorroborated else "low", "Unexpected shutdowns and their corroboration",
        len(findings), _capped(findings, limit), rationale,
        {"uncorroborated_clusters": len(uncorroborated)},
    )


def rule_process_creation_without_execution_artifacts(data, limit):
    pf_bases = set(base_name(r.get("executable")) for r in data["pf"] if r.get("executable"))
    bam_bases = set(base_name(r.get("path")) for r in data["bam"] if r.get("path"))
    missing = {}
    total = 0
    empty = 0
    for rec in data["evtx"]:
        if rec.get("event_id") != PROCESS_CREATION_ID:
            continue
        total += 1
        name = (rec.get("event_data") or {}).get("NewProcessName")
        if not name:
            empty += 1
            continue
        base = base_name(name)
        if not base or base in pf_bases or base in bam_bases:
            continue
        if base not in missing:
            missing[base] = {
                "exe": base,
                "path": name,
                "time": rec.get("time_created"),
                "ref": _ref("evtx", rec),
            }
    rationale = (
        "Process-creation audit entries (4688) without a Prefetch run or BAM record for the image. Covered only where "
        "auditing was on and process names were populated; 4688 coverage and Prefetch retention differ, so this is a lead list."
    )
    return _finding(
        9, "low", "4688 process creations with no execution artifact image",
        len(missing), _capped(list(missing.values()), limit), rationale,
        {"coverage_note": "4688 total %d, with empty NewProcessName %d (audit policy)" % (total, empty)},
    )


def rule_userassist_outside_bam_window(data, limit):
    bam_times = [r.get("execution_time") for r in data["bam"] if r.get("execution_time")]
    if not bam_times:
        return None
    window_start = min(bam_times)
    bam_bases = set(base_name(r.get("path")) for r in data["bam"] if r.get("path"))
    hits = {}
    for rec in data["userassist"]:
        last = rec.get("last_run_time")
        if not last or last < window_start:
            continue
        target = ua_target(rec)
        base = base_name(target)
        if not base or base in bam_bases:
            continue
        if base not in hits:
            hits[base] = {
                "target": target,
                "kind": rec.get("kind"),
                "last_run_time": last,
                "time": last,
                "ref": _ref("userassist", rec),
            }
    rationale = (
        "UserAssist shows a launch inside the BAM retention window, yet BAM has no record for that target. UWP "
        "AppUserModelIDs and URI launches (steam://) are not BAM-tracked; otherwise consider BAM tamper/deletion."
    )
    return _finding(
        10, "low", "UserAssist launches inside the BAM window with no BAM record",
        len(hits), _capped(list(hits.values()), limit), rationale,
        {"coverage_note": "bam window start: %s" % window_start},
    )


RULE_FUNCS = {
    1: rule_execution_without_file_evidence,
    2: rule_timestomp_si_vs_fn,
    3: rule_service_install_without_file_create,
    4: rule_log_clear_or_record_gaps,
    5: rule_bam_without_prefetch_or_userassist,
    6: rule_amcache_link_date_before_si_created,
    7: rule_pending_rename_without_usn_activity,
    8: rule_unexpected_shutdown,
    9: rule_process_creation_without_execution_artifacts,
    10: rule_userassist_outside_bam_window,
}

RULE_REQUIREMENTS = {
    1: ((), ("usn", "mft")),
    2: (("mft",), ()),
    3: (("usn", "evtx"), ()),
    4: (("evtx",), ()),
    5: (("bam",), ()),
    6: (("mft", "amcache_inventory_application_file"), ()),
    7: (("usn",), ()),
    8: (("evtx",), ()),
    9: (("evtx",), ()),
    10: (("bam", "userassist"), ()),
}


def run_rules(data, wanted, limit):
    findings = []
    skipped = []
    for rule in sorted(wanted):
        needs_all, needs_any = RULE_REQUIREMENTS.get(rule, ((), ()))
        missing = [key for key in needs_all if not data.get(key)]
        if not missing and needs_any and not any(data.get(key) for key in needs_any):
            missing = list(needs_any)
        if missing:
            skipped.append({
                "rule": rule,
                "name": RULE_NAMES[rule],
                "reason": "missing input: needs %s" % " and ".join(missing),
            })
            continue
        try:
            finding = RULE_FUNCS[rule](data, limit)
        except Exception as exc:  # rule crashes must not kill the run
            skipped.append({
                "rule": rule,
                "name": RULE_NAMES[rule],
                "reason": "rule error: %s: %s" % (type(exc).__name__, exc),
            })
            continue
        if finding is None:
            skipped.append({
                "rule": rule,
                "name": RULE_NAMES[rule],
                "reason": "prerequisite data absent (see rationale)",
            })
            continue
        findings.append(finding)
    return findings, skipped


def build_report(data, stats, findings, skipped, paths, limit):
    by_severity = {}
    for finding in findings:
        by_severity[finding["severity"]] = by_severity.get(finding["severity"], 0) + 1
    records = {name: len(recs) for name, recs in sorted(data.items())}
    return {
        "tool": "validate",
        "tool_version": TOOL_VERSION,
        "schema_version": SCHEMA_VERSION,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "inputs": {"paths": paths, "files": stats["files"], "parsed": stats["parsed"], "failed": stats["failed"]},
        "counts": {
            "records": records,
            "findings": len(findings),
            "by_severity": by_severity,
            "example_cap": limit,
        },
        "skipped_rules": skipped,
        "findings": findings,
        "errors": stats["errors"],
        "warnings": sorted(
            set(["files_failed_to_parse"] if stats["failed"] else [])
            | set(["rules_skipped"] if skipped else [])
        ),
    }


def _open_out(path):
    if path == "-":
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(newline="\n")
        return sys.stdout, False
    return open(path, "w", encoding="utf-8", newline="\n"), True


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="validate.py",
        description="Cross-validation engine: runs the 10 timeline-methodology rules over parser JSONL and emits findings.",
    )
    parser.add_argument("inputs", nargs="*", help="parser JSONL file(s) and/or directories containing them")
    parser.add_argument("--jsonl", default="-", help="findings JSONL output path ('-' = stdout, default)")
    parser.add_argument("--report", help="summary report JSON output path")
    parser.add_argument("--rules", help="comma-separated rule numbers to run (default: all)")
    parser.add_argument("--examples", type=int, default=10, help="max examples per finding (default: 10)")
    parser.add_argument("--quiet", action="store_true", help="suppress the stderr summary")
    args = parser.parse_args(argv)

    try:
        wanted = set(RULE_FUNCS)
        if args.rules:
            wanted = set()
            for token in args.rules.split(","):
                token = token.strip()
                if not token:
                    continue
                if not token.isdigit() or int(token) not in RULE_FUNCS:
                    raise ValidateToolError("unknown rule %r; valid: 1-10" % token)
                wanted.add(int(token))
        if args.examples < 1:
            raise ValidateToolError("--examples must be >= 1")
        if not args.inputs:
            raise ValidateToolError("no inputs given")
        paths = timeline.expand_inputs(args.inputs)
    except (ValidateToolError, timeline.TimelineToolError) as exc:
        sys.stderr.write("[validate] usage error: %s\n" % exc)
        return 2

    data, stats = load_records(paths)
    if stats["parsed"] == 0 and stats["lines"] == 0:
        sys.stderr.write("[validate] fatal: no parsable JSONL records in %d file(s)\n" % stats["files"])
        return 1

    findings, skipped = run_rules(data, wanted, args.examples)
    report = build_report(data, stats, findings, skipped, paths, args.examples)

    out, should_close = _open_out(args.jsonl)
    try:
        for finding in findings:
            out.write(json.dumps(finding, ensure_ascii=False, sort_keys=True) + "\n")
    finally:
        if should_close:
            out.close()

    if args.report:
        try:
            with open(args.report, "w", encoding="utf-8", newline="\n") as fh:
                json.dump(report, fh, ensure_ascii=False, indent=2, sort_keys=True)
                fh.write("\n")
        except OSError as exc:
            sys.stderr.write("[validate] fatal: cannot write report: %s\n" % exc)
            return 1

    if not args.quiet:
        severity = ", ".join("%s=%d" % kv for kv in sorted(report["counts"]["by_severity"].items()))
        sys.stderr.write(
            "[validate] records=%s findings=%d (%s) skipped_rules=%d\n"
            % (
                " ".join("%s:%d" % kv for kv in report["counts"]["records"].items() if kv[1]),
                len(findings),
                severity or "none",
                len(skipped),
            )
        )
        for finding in findings:
            sys.stderr.write(
                "[validate] rule %d %s: %d (%s)\n" % (finding["rule"], finding["name"], finding["count"], finding["severity"])
            )
    return 0


if __name__ == "__main__":
    sys.exit(main())
