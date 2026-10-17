#!/usr/bin/env python3
"""Tests for tools/evtx_parse.py.

All fixtures are synthetic XML event exports built in code; no real event logs
are committed.

Run from the skill root:
    python -m unittest discover -s tests -v
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest

SKILL_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
TOOLS_DIR = os.path.join(SKILL_ROOT, "tools")
if TOOLS_DIR not in sys.path:
    sys.path.insert(0, TOOLS_DIR)

import evtx_parse as ep

PARSER = os.path.join(TOOLS_DIR, "evtx_parse.py")

NS = 'xmlns="http://schemas.microsoft.com/win/2004/08/events/event"'


def read_json(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def read_jsonl(path):
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def system_block(
    event_id=4624,
    channel="Security",
    provider="Microsoft-Windows-Security-Auditing",
    level=0,
    time_str="2024-01-15T09:00:00.1234567Z",
    record_id=100,
    qualifiers=None,
    execution='<Execution ProcessID="0x2f0" ThreadID="0x100"/>',
    security_uid="S-1-5-18",
    computer="PC1",
    activity=None,
    extra="",
):
    parts = ['<System>']
    parts.append('<Provider Name="%s"/>' % provider)
    q = ' Qualifiers="%d"' % qualifiers if qualifiers is not None else ""
    parts.append("<EventID%s>%d</EventID>" % (q, event_id))
    parts.append("<Version>0</Version>")
    parts.append("<Level>%d</Level>" % level)
    parts.append("<Task>0</Task>")
    parts.append("<Opcode>0</Opcode>")
    parts.append("<Keywords>0x8020000000000000</Keywords>")
    if time_str:
        parts.append('<TimeCreated SystemTime="%s"/>' % time_str)
    if activity:
        parts.append('<Correlation ActivityID="%s"/>' % activity)
    parts.append(execution)
    parts.append("<EventRecordID>%d</EventRecordID>" % record_id)
    parts.append("<Channel>%s</Channel>" % channel)
    parts.append("<Computer>%s</Computer>" % computer)
    if security_uid:
        parts.append('<Security UserID="%s"/>' % security_uid)
    parts.append(extra)
    parts.append("</System>")
    return "".join(parts)


def event_xml(
    data=None,
    userdata_xml=None,
    include_system=True,
    binary=None,
    extra_eventdata="",
    **system_kwargs,
):
    parts = ["<Event %s>" % NS]
    if include_system:
        parts.append(system_block(**system_kwargs))
    if data is not None or binary is not None:
        parts.append("<EventData>")
        for item in data or []:
            name, value = item
            if name is None:
                parts.append("<Data>%s</Data>" % value)
            else:
                parts.append('<Data Name="%s">%s</Data>' % (name, value))
        if binary is not None:
            parts.append("<Binary>%s</Binary>" % binary)
        parts.append(extra_eventdata)
        parts.append("</EventData>")
    if userdata_xml is not None:
        parts.append("<UserData>%s</UserData>" % userdata_xml)
    parts.append("</Event>")
    return "".join(parts)


DECL = '<?xml version="1.0" encoding="utf-8" standalone="yes"?>\n'


def wrap_events(*events):
    return DECL + "<Events>\n" + "\n".join(events) + "\n</Events>"


def parse_first(xml_text, include_raw=False):
    events, notes = ep.extract_events(xml_text)
    rec = ep.parse_event(events[0], "test.xml", "0" * 64, include_raw)
    return rec, notes


class EventParsingTests(unittest.TestCase):
    def test_full_event_fields(self):
        rec, _ = parse_first(wrap_events(event_xml(data=[("LogonType", "10"), ("TargetUserName", "sample-user")])))
        self.assertEqual(rec["artifact"], "eventlog")
        self.assertEqual(rec["channel"], "Security")
        self.assertEqual(rec["provider"], "Microsoft-Windows-Security-Auditing")
        self.assertEqual(rec["event_id"], 4624)
        self.assertEqual(rec["level"], 0)
        self.assertEqual(rec["level_name"], "LogAlways")
        self.assertEqual(rec["record_id"], 100)
        self.assertEqual(rec["computer"], "PC1")
        self.assertEqual(rec["security_user_id"], "S-1-5-18")
        self.assertEqual(rec["execution_process_id"], 0x2F0)
        self.assertEqual(rec["execution_thread_id"], 0x100)
        self.assertEqual(rec["keywords"], "0x8020000000000000")
        self.assertEqual(rec["event_data"], {"LogonType": "10", "TargetUserName": "sample-user"})
        self.assertEqual(rec["warnings"], [])

    def test_time_normalized_to_microseconds(self):
        rec, _ = parse_first(wrap_events(event_xml(time_str="2024-01-15T09:00:00.1234567Z")))
        self.assertEqual(rec["time_created"], "2024-01-15T09:00:00.123456Z")

    def test_time_without_fraction(self):
        rec, _ = parse_first(wrap_events(event_xml(time_str="2024-01-15T10:00:00Z")))
        self.assertEqual(rec["time_created"], "2024-01-15T10:00:00.000000Z")

    def test_time_unparseable_warns(self):
        rec, _ = parse_first(wrap_events(event_xml(time_str="yesterday")))
        self.assertIsNone(rec["time_created"])
        self.assertTrue(any("unparseable TimeCreated" in w for w in rec["warnings"]))

    def test_level_name_mapping(self):
        for level, name in ((0, "LogAlways"), (1, "Critical"), (2, "Error"), (3, "Warning"), (4, "Information"), (5, "Verbose")):
            rec, _ = parse_first(wrap_events(event_xml(level=level)))
            self.assertEqual(rec["level_name"], name)
        rec, _ = parse_first(wrap_events(event_xml(level=99)))
        self.assertEqual(rec["level"], 99)
        self.assertIsNone(rec["level_name"])

    def test_qualifiers_preserved(self):
        rec, _ = parse_first(wrap_events(event_xml(event_id=7045, qualifiers=16384)))
        self.assertEqual(rec["event_id"], 7045)
        self.assertEqual(rec["event_id_qualifiers"], 16384)

    def test_keywords_verbatim(self):
        rec, _ = parse_first(wrap_events(event_xml()))
        self.assertEqual(rec["keywords"], "0x8020000000000000")

    def test_event_data_order_and_empty_values(self):
        rec, _ = parse_first(wrap_events(event_xml(data=[("A", "1"), ("Empty", ""), ("B", "2")])))
        self.assertEqual(list(rec["event_data"].keys()), ["A", "Empty", "B"])
        self.assertEqual(rec["event_data"]["Empty"], "")

    def test_event_data_unnamed_positional(self):
        rec, _ = parse_first(wrap_events(event_xml(data=[(None, "first"), ("Named", "x"), (None, "second")])))
        self.assertEqual(rec["event_data"], {"Data[0]": "first", "Named": "x", "Data[2]": "second"})

    def test_event_data_duplicate_names_suffixed(self):
        rec, _ = parse_first(wrap_events(event_xml(data=[("X", "1"), ("X", "2"), ("X", "3")])))
        self.assertEqual(rec["event_data"], {"X": "1", "X#2": "2", "X#3": "3"})
        self.assertTrue(any("duplicate EventData name" in w for w in rec["warnings"]))

    def test_event_data_binary_element_captured(self):
        rec, _ = parse_first(wrap_events(event_xml(data=[("A", "1")], binary="0xDEADBEEF")))
        self.assertEqual(rec["event_data"], {"A": "1", "Binary": "0xDEADBEEF"})
        self.assertEqual(rec["warnings"], [])

    def test_event_data_unexpected_child_warns(self):
        rec, _ = parse_first(wrap_events(event_xml(data=[("A", "1")], extra_eventdata="<Complex>x</Complex>")))
        self.assertEqual(rec["event_data"], {"A": "1"})
        self.assertTrue(any("unexpected <Complex>" in w for w in rec["warnings"]))

    def test_user_data_nested_flatten(self):
        userdata = '<EventXML Version="1"><Param1>a</Param1><Param2>5</Param2><Repeated>x</Repeated><Repeated>y</Repeated></EventXML>'
        rec, _ = parse_first(wrap_events(event_xml(data=None, userdata_xml=userdata)))
        self.assertEqual(
            rec["user_data"],
            {"EventXML": {"@Version": "1", "Param1": "a", "Param2": "5", "Repeated": ["x", "y"]}},
        )

    def test_missing_system_warns_and_returns_nulls(self):
        rec, _ = parse_first(wrap_events(event_xml(include_system=False, data=[("A", "1")])))
        self.assertIsNone(rec["channel"])
        self.assertIsNone(rec["event_id"])
        self.assertTrue(any("no <System>" in w for w in rec["warnings"]))
        self.assertEqual(rec["event_data"], {"A": "1"})

    def test_missing_eventid_warns(self):
        system = "<System><Provider Name=\"P\"/><Level>4</Level></System>"
        rec, _ = parse_first(wrap_events("<Event %s>%s</Event>" % (NS, system)))
        self.assertIsNone(rec["event_id"])
        self.assertTrue(any("no <EventID>" in w for w in rec["warnings"]))

    def test_raw_mode(self):
        rec, _ = parse_first(wrap_events(event_xml(data=[("A", "1")])), include_raw=True)
        self.assertIn("raw_xml", rec)
        self.assertIn("EventData", rec["raw_xml"])
        self.assertIn(">1<", rec["raw_xml"])
        rec2, _ = parse_first(wrap_events(event_xml(data=[("A", "1")])), include_raw=False)
        self.assertNotIn("raw_xml", rec2)


class EventExtractionTests(unittest.TestCase):
    def test_single_event_document(self):
        events, notes = ep.extract_events(DECL + event_xml())
        self.assertEqual(len(events), 1)
        self.assertEqual(notes, [])

    def test_events_wrapper(self):
        events, notes = ep.extract_events(wrap_events(event_xml(), event_xml(record_id=101)))
        self.assertEqual(len(events), 2)
        self.assertEqual(notes, [])

    def test_concatenated_fragments_with_declarations(self):
        text = DECL + event_xml() + "\n" + DECL + event_xml(record_id=101)
        events, notes = ep.extract_events(text)
        self.assertEqual(len(events), 2)
        self.assertTrue(any("fragment scan" in n for n in notes))

    def test_truncated_tail_recovery(self):
        text = DECL + "<Events>\n" + event_xml() + "\n" + event_xml(record_id=101) + "\n<Event><System>trunc"
        events, notes = ep.extract_events(text)
        self.assertEqual(len(events), 2)
        self.assertTrue(any("discarded" in n for n in notes))

    def test_junk_before_first_event_noted(self):
        text = "garbage leading content " + event_xml()
        events, notes = ep.extract_events(text)
        self.assertEqual(len(events), 1)
        self.assertTrue(any("ignored non-event content" in n for n in notes))

    def test_non_event_xml_root_rejected(self):
        with self.assertRaises(ep.EvtxError) as ctx:
            ep.extract_events("<foo><bar/></foo>")
        self.assertIn("<foo>", str(ctx.exception))

    def test_events_wrapper_without_events_rejected(self):
        with self.assertRaises(ep.EvtxError) as ctx:
            ep.extract_events("<Events><NotEvent/></Events>")
        self.assertIn("no <Event> elements", str(ctx.exception))

    def test_all_unparseable_fragments_rejected(self):
        with self.assertRaises(ep.EvtxError):
            ep.extract_events("<Event><broken")


class InputHandlingTests(unittest.TestCase):
    def test_binary_evtx_rejected_with_hint(self):
        raw = b"ElfFile\x00" + b"\x00" * 100
        with self.assertRaises(ep.EvtxError) as ctx:
            ep.load_text(raw, "Security.evtx")
        message = str(ctx.exception)
        self.assertIn("binary EVTX", message)
        self.assertIn("wevtutil qe", message)

    def test_binary_nul_bytes_rejected(self):
        with self.assertRaises(ep.EvtxError) as ctx:
            ep.load_text(b"\x01\x02\x03\x00binary rest", "x.bin")
        self.assertIn("binary", str(ctx.exception))

    def test_empty_file_rejected(self):
        with self.assertRaises(ep.EvtxError) as ctx:
            ep.load_text(b"   \r\n  ", "x.xml")
        self.assertIn("empty", str(ctx.exception))

    def test_utf16_bom_decodes(self):
        text = wrap_events(event_xml())
        raw = text.encode("utf-16")
        decoded, encoding = ep.load_text(raw, "x.xml")
        self.assertEqual(encoding, "utf-16")
        events, _ = ep.extract_events(decoded)
        self.assertEqual(len(events), 1)

    def test_cp1254_fallback(self):
        text = wrap_events(event_xml(data=[("User", "Kullanıcı işçi")]))
        raw = text.encode("cp1254")
        decoded, encoding = ep.load_text(raw, "x.xml")
        self.assertEqual(encoding, "cp1254")
        self.assertIn("Kullanıcı", decoded)


class FilterTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        events = [
            event_xml(event_id=4624, channel="Security", time_str="2024-01-15T09:00:00Z", record_id=1),
            event_xml(
                event_id=7045,
                channel="System",
                provider="Service Control Manager",
                time_str="2024-01-15T10:00:00Z",
                record_id=2,
            ),
            event_xml(event_id=4628, channel="Security", time_str="2024-01-15T09:45:00Z", record_id=3),
        ]
        self.xml_path = os.path.join(self.tmp.name, "events.xml")
        with open(self.xml_path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(wrap_events(*events))

    def run_main(self, extra):
        out = os.path.join(self.tmp.name, "out.jsonl")
        report = os.path.join(self.tmp.name, "report.json")
        rc = ep.main([self.xml_path, "--jsonl", out, "--report", report, "--quiet"] + extra)
        records = read_jsonl(out)
        report_data = read_json(report)
        return rc, records, report_data

    def test_filter_by_ids_comma_separated(self):
        rc, records, report = self.run_main(["--id", "4624,7045"])
        self.assertEqual(rc, 0)
        self.assertEqual([r["event_id"] for r in records], [4624, 7045])
        self.assertEqual(report["counts"]["events_total"], 3)
        self.assertEqual(report["counts"]["filtered_out"], 1)

    def test_filter_by_channel_case_insensitive(self):
        rc, records, _ = self.run_main(["--channel", "SECURITY"])
        self.assertEqual(rc, 0)
        self.assertEqual([r["event_id"] for r in records], [4624, 4628])

    def test_filter_by_provider_substring(self):
        rc, records, _ = self.run_main(["--provider", "service control"])
        self.assertEqual(rc, 0)
        self.assertEqual([r["event_id"] for r in records], [7045])

    def test_filter_since_until(self):
        rc, records, _ = self.run_main(["--since", "2024-01-15T09:30:00", "--until", "2024-01-15T09:50:00Z"])
        self.assertEqual(rc, 0)
        self.assertEqual([r["event_id"] for r in records], [4628])

    def test_filter_since_after_until_fatal(self):
        rc = ep.main([self.xml_path, "--jsonl", os.path.join(self.tmp.name, "o.jsonl"), "--quiet", "--since", "2024-01-16T00:00:00Z", "--until", "2024-01-15T00:00:00Z"])
        self.assertEqual(rc, 1)

    def test_limit_stops_early(self):
        rc, records, report = self.run_main(["--limit", "2"])
        self.assertEqual(rc, 0)
        self.assertEqual(len(records), 2)
        self.assertIn("stopped_early_by_limit", report["warnings"])

    def test_report_top_event_ids(self):
        _, _, report = self.run_main([])
        top = {item["event_id"]: item["count"] for item in report["counts"]["top_event_ids"]}
        self.assertEqual(top[4624], 1)
        self.assertEqual(report["counts"]["by_channel"], {"Security": 2, "System": 1})


class CliTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def run_cli(self, args):
        return subprocess.run(
            [sys.executable, PARSER] + args,
            capture_output=True,
            text=True,
            encoding="utf-8",
        )

    def test_cli_end_to_end(self):
        xml_path = os.path.join(self.tmp.name, "s.xml")
        with open(xml_path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(wrap_events(event_xml(data=[("A", "1")]), event_xml(event_id=7045, channel="System", record_id=2)))
        out = os.path.join(self.tmp.name, "out.jsonl")
        report = os.path.join(self.tmp.name, "report.json")
        result = self.run_cli([xml_path, "--jsonl", out, "--report", report, "--quiet"])
        self.assertEqual(result.returncode, 0)
        records = read_jsonl(out)
        self.assertEqual(len(records), 2)
        report_data = read_json(report)
        self.assertEqual(report_data["counts"]["emitted"], 2)
        self.assertEqual(report_data["inputs"][0]["encoding"], "utf-8")
        self.assertEqual(report_data["warnings"], [])

    def test_cli_binary_evtx_error_entry(self):
        evtx_path = os.path.join(self.tmp.name, "Security.evtx")
        with open(evtx_path, "wb") as fh:
            fh.write(b"ElfFile\x00" + b"\x00" * 200)
        out = os.path.join(self.tmp.name, "out.jsonl")
        report = os.path.join(self.tmp.name, "report.json")
        result = self.run_cli([evtx_path, "--jsonl", out, "--report", report, "--quiet"])
        self.assertEqual(result.returncode, 0)
        report_data = read_json(report)
        self.assertEqual(report_data["counts"]["failed"], 1)
        self.assertIn("binary EVTX", report_data["errors"][0]["error"])
        self.assertIn("no_records_emitted", report_data["warnings"])

    def test_cli_missing_file_error_entry(self):
        out = os.path.join(self.tmp.name, "out.jsonl")
        report = os.path.join(self.tmp.name, "report.json")
        result = self.run_cli([os.path.join(self.tmp.name, "nope.xml"), "--jsonl", out, "--report", report, "--quiet"])
        self.assertEqual(result.returncode, 0)
        report_data = read_json(report)
        self.assertEqual(report_data["counts"]["failed"], 1)
        self.assertIn("cannot_read", report_data["errors"][0]["error"])

    def test_cli_directory_expansion_ignores_non_xml(self):
        with open(os.path.join(self.tmp.name, "a.xml"), "w", encoding="utf-8", newline="\n") as fh:
            fh.write(wrap_events(event_xml(record_id=1)))
        with open(os.path.join(self.tmp.name, "notes.txt"), "w", encoding="utf-8") as fh:
            fh.write("not an export")
        out = os.path.join(self.tmp.name, "out.jsonl")
        report = os.path.join(self.tmp.name, "report.json")
        result = self.run_cli([self.tmp.name, "--jsonl", out, "--report", report, "--quiet"])
        self.assertEqual(result.returncode, 0)
        report_data = read_json(report)
        self.assertEqual(report_data["counts"]["files"], 1)
        self.assertEqual(report_data["counts"]["emitted"], 1)

    def test_cli_usage_error_on_bad_limit(self):
        result = self.run_cli(["-", "--limit", "0"])
        self.assertEqual(result.returncode, 2)


if __name__ == "__main__":
    unittest.main()
