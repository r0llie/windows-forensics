import json
import os
import subprocess
import sys
import tempfile
import unittest

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
TOOLS_DIR = os.path.join(os.path.dirname(TESTS_DIR), "tools")
sys.path.insert(0, TOOLS_DIR)

import timeline  # noqa: E402

PARSER = os.path.join(TOOLS_DIR, "timeline.py")


def usn_rec(ts, name="a.tmp", flags=("FILE_CREATE",), usn=100):
    return {
        "tool": "usn_parse",
        "schema_version": 1,
        "artifact": "usn",
        "version": 2,
        "minor_version": 0,
        "usn": usn,
        "file_reference": "0x001800000006ab9b",
        "parent_file_reference": "0x001800000006ab9a",
        "timestamp": ts,
        "timestamp_filetime": 134000000000000000,
        "reason_mask": 1,
        "reason_flags": list(flags),
        "reason_unknown_mask": 0,
        "source_info_mask": 0,
        "source_flags": [],
        "source_unknown_mask": 0,
        "security_id": 100,
        "file_attributes": 32,
        "name": name,
        "warnings": [],
    }


def mft_rec(created=None, modified=None, name="b.txt", record_number=5):
    return {
        "tool": "mft_parse",
        "schema_version": 1,
        "artifact": "mft",
        "record_number": record_number,
        "record_offset": 2048,
        "in_use": True,
        "is_directory": False,
        "is_extension": False,
        "sequence_number": 1,
        "file_reference": "0x0001000000000005",
        "used_size": 128,
        "allocated_record_size": 1024,
        "attribute_list": [],
        "attributes": [],
        "primary_name": name,
        "size": 42,
        "file_names": [],
        "timestomp_flags": [],
        "warnings": [],
        "standard_information": {"created": created, "modified": modified},
    }


def pf_rec(run_times=(), last_run_time=None, executable="CMD.EXE"):
    return {
        "tool": "pf_parse",
        "schema_version": 1,
        "artifact": "pf",
        "source_path": "C:\\Windows\\Prefetch\\CMD.EXE-12345678.pf",
        "source_sha256": "0" * 64,
        "source_size": 100,
        "container": "MAM",
        "decompressed_size": 200,
        "executable": executable,
        "prefetch_hash": "12345678",
        "flags": 0,
        "is_boot_prefetch": False,
        "filename": "CMD.EXE-12345678.pf",
        "hash_matches_filename": True,
        "exe_matches_filename": True,
        "unknown_string": "",
        "file_information": {},
        "run_count": 5,
        "run_times_filetime": [],
        "run_times": list(run_times),
        "last_run_time": last_run_time,
        "metrics": [],
        "trace_chains": [],
        "volumes": [],
        "warnings": [],
    }


def evtx_rec(ts="2026-02-10T10:00:00.000000Z", event_id=7045, record_id=10):
    return {
        "tool": "evtx_parse",
        "schema_version": 1,
        "artifact": "eventlog",
        "source_file": "System.xml",
        "channel": "System",
        "provider": "Service Control Manager",
        "event_id": event_id,
        "time_created": ts,
        "record_id": record_id,
        "computer": "PC",
        "security_user_id": None,
        "event_data": {"ServiceName": "TestSvc"},
        "warnings": [],
    }


def bam_rec(ts="2026-02-10T09:00:00Z", path="C:\\Tools\\run.exe"):
    return {
        "tool": "reg_parse",
        "schema_version": 1,
        "artifact": "bam",
        "hive": "SYSTEM",
        "key_path": "SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings\\S-1-5-21",
        "warnings": [],
        "control_set": 1,
        "user_sid": "S-1-5-21",
        "path": path,
        "value_size": 24,
        "execution_time": ts,
        "windows_app_flag": 0,
    }


def userassist_rec(ts="2026-02-10T08:00:00Z", name="C:\\Tools\\run.exe"):
    return {
        "tool": "reg_parse",
        "schema_version": 1,
        "artifact": "userassist",
        "hive": "NTUSER.DAT",
        "key_path": "NTUSER.DAT\\...\\UserAssist\\{GUID}\\Count",
        "warnings": [],
        "guid": "{GUID}",
        "version": 5,
        "value_name_raw": "P:\\Gbbyf\\eha.rkr",
        "name": name,
        "kind": None,
        "target": None,
        "entry_size": 72,
        "session_id": 1,
        "run_count": 5,
        "focus_count": 1,
        "focus_time_ms": 100,
        "last_run_time": ts,
    }


def amcache_iaf_rec(ts="2026-02-01T00:00:00Z", path="C:\\Tools\\run.exe"):
    return {
        "tool": "reg_parse",
        "schema_version": 1,
        "artifact": "amcache_inventory_application_file",
        "hive": "Amcache.hve",
        "key_path": "Amcache.hve\\Root\\InventoryApplicationFile",
        "warnings": [],
        "key_name": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
        "path": path,
        "name": "run.exe",
        "sha1": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
        "size": 1000,
        "link_date": "02/01/2026 00:00:00",
        "link_date_ts": ts,
    }


def amcache_file_rec(ts="2026-01-15T00:00:00Z", path="C:\\Tools\\run.exe"):
    return {
        "tool": "reg_parse",
        "schema_version": 1,
        "artifact": "amcache_file",
        "hive": "Amcache.hve",
        "key_path": "Amcache.hve\\Root\\File\\c:\\tools",
        "warnings": [],
        "path": path,
        "sha1_raw": "ab" * 20,
        "file_size": 1000,
        "link_date_ts": ts,
        "modification_time": "2025-12-01T00:00:00Z",
        "creation_time": "2025-11-01T00:00:00Z",
    }


def appcompatcache_rec(ts="2025-06-01T00:00:00Z", path="C:\\Tools\\run.exe"):
    return {
        "tool": "reg_parse",
        "schema_version": 1,
        "artifact": "appcompatcache",
        "hive": "SYSTEM",
        "key_path": "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCompatCache",
        "warnings": [],
        "control_set": 1,
        "path": path,
        "last_modification_time": ts,
        "entry_signature": "10ts",
        "data_size": 32,
    }


class TimelineTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = self.tmp.name

    def tearDown(self):
        self.tmp.cleanup()

    def write_jsonl(self, name, records):
        path = os.path.join(self.dir, name)
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            for rec in records:
                fh.write(json.dumps(rec) + "\n")
        return path

    def run_fusion(self, inputs, *extra):
        out = os.path.join(self.dir, "timeline.jsonl")
        report = os.path.join(self.dir, "report.json")
        rc = timeline.main(list(inputs) + ["--jsonl", out, "--report", report, "--quiet"] + list(extra))
        self.assertEqual(rc, 0)
        entries = []
        with open(out, encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    entries.append(json.loads(line))
        with open(report, encoding="utf-8") as fh:
            rep = json.load(fh)
        return entries, rep

    def test_usn_mapping(self):
        path = self.write_jsonl("usn.jsonl", [usn_rec("2026-02-10T10:00:00.000000Z", flags=("DATA_EXTEND", "FILE_CREATE"))])
        entries, _ = self.run_fusion([path])
        self.assertEqual(len(entries), 1)
        entry = entries[0]
        self.assertEqual(entry["source"], "usn")
        self.assertEqual(entry["action"], "usn:DATA_EXTEND+FILE_CREATE")
        self.assertEqual(entry["target"], "a.tmp")
        self.assertEqual(entry["details"]["usn"], 100)
        self.assertTrue(entry["record_ref"].endswith("#usn=100"))

    def test_mft_splits_created_and_modified(self):
        rec = mft_rec(created="2026-02-10T10:00:00Z", modified="2026-02-10T11:00:00Z")
        path = self.write_jsonl("mft.jsonl", [rec])
        entries, _ = self.run_fusion([path])
        self.assertEqual([e["action"] for e in entries], ["mft:file_created", "mft:file_modified"])
        self.assertEqual(entries[0]["target"], "b.txt")
        self.assertEqual(entries[0]["details"]["record_number"], 5)

    def test_pf_run_times_plus_last_run(self):
        rec = pf_rec(
            run_times=["2026-02-10T12:00:00Z", "2026-02-09T12:00:00Z", "2026-02-08T12:00:00Z"],
            last_run_time="2026-02-10T12:00:00Z",
        )
        path = self.write_jsonl("pf.jsonl", [rec])
        entries, _ = self.run_fusion([path])
        self.assertEqual(len(entries), 4)
        self.assertEqual(entries[0]["action"], "pf:executed")
        self.assertEqual(entries[0]["details"]["run_index"], 2)  # run_times are newest-first; oldest sorts first
        self.assertEqual(entries[0]["ts"], "2026-02-08T12:00:00Z")
        self.assertEqual(entries[-1]["action"], "pf:last_run")
        self.assertNotIn("run_index", entries[-1]["details"])
        self.assertEqual(entries[0]["target"], "CMD.EXE")

    def test_evtx_mapping(self):
        path = self.write_jsonl("evtx.jsonl", [evtx_rec()])
        entries, _ = self.run_fusion([path])
        self.assertEqual(len(entries), 1)
        entry = entries[0]
        self.assertEqual(entry["source"], "evtx")
        self.assertEqual(entry["action"], "evtx:7045")
        self.assertEqual(entry["target"], "Service Control Manager")
        self.assertEqual(entry["ts"], "2026-02-10T10:00:00.000000Z")
        self.assertEqual(entry["details"]["event_data"], {"ServiceName": "TestSvc"})
        self.assertEqual(entry["record_ref"], "System.xml#record=10")

    def test_reg_artifact_mappings(self):
        path = self.write_jsonl(
            "reg.jsonl",
            [bam_rec(), userassist_rec(), amcache_iaf_rec(), amcache_file_rec(), appcompatcache_rec()],
        )
        entries, rep = self.run_fusion([path])
        actions = {e["artifact"]: e["action"] for e in entries}
        self.assertEqual(actions["bam"], "reg:bam_executed")
        self.assertEqual(actions["userassist"], "reg:userassist_last_run")
        self.assertEqual(actions["amcache_inventory_application_file"], "reg:amcache_observed")
        self.assertEqual(actions["amcache_file"], "reg:amcache_observed")
        self.assertEqual(actions["appcompatcache"], "reg:shimcache_seen")
        self.assertEqual(rep["counts"]["by_source"], {"reg": 5})
        self.assertEqual(rep["counts"]["emitted"], 5)

    def test_sorted_ascending(self):
        p1 = self.write_jsonl("a.jsonl", [usn_rec("2026-02-10T12:00:00Z"), usn_rec("2026-02-10T08:00:00Z", usn=101)])
        p2 = self.write_jsonl("b.jsonl", [bam_rec("2026-02-10T10:00:00Z")])
        entries, _ = self.run_fusion([p1, p2])
        times = [e["ts"] for e in entries]
        self.assertEqual(times, sorted(times))
        self.assertEqual(times[0], "2026-02-10T08:00:00Z")
        self.assertEqual(times[-1], "2026-02-10T12:00:00Z")

    def test_skips_no_timestamp_artifacts(self):
        rec = {"artifact": "typedpaths", "hive": "NTUSER.DAT", "paths": ["C:\\a"]}
        path = self.write_jsonl("state.jsonl", [rec, usn_rec("2026-02-10T10:00:00Z")])
        entries, rep = self.run_fusion([path])
        self.assertEqual(len(entries), 1)
        self.assertEqual(rep["counts"]["skipped_no_timestamp"], {"typedpaths": 1})
        self.assertEqual(rep["counts"]["records_in"], 1)

    def test_skips_unknown_artifact(self):
        path = self.write_jsonl("weird.jsonl", [{"artifact": "brand_new_thing"}])
        entries, rep = self.run_fusion([path])
        self.assertEqual(entries, [])
        self.assertEqual(rep["counts"]["skipped_unknown_artifact"], {"brand_new_thing": 1})

    def test_record_without_artifact_field(self):
        path = self.write_jsonl("plain.jsonl", [{"foo": 1}])
        _, rep = self.run_fusion([path])
        self.assertEqual(rep["counts"]["skipped_unknown_artifact"], {"<no artifact field>": 1})

    def test_emitting_artifact_with_null_timestamp_skipped(self):
        rec = userassist_rec()
        rec["last_run_time"] = None
        path = self.write_jsonl("ua.jsonl", [rec])
        entries, rep = self.run_fusion([path])
        self.assertEqual(entries, [])
        self.assertEqual(rep["counts"]["skipped_no_timestamp"], {"userassist": 1})

    def test_source_filter(self):
        p1 = self.write_jsonl("a.jsonl", [usn_rec("2026-02-10T08:00:00Z")])
        p2 = self.write_jsonl("b.jsonl", [bam_rec("2026-02-10T10:00:00Z")])
        entries, rep = self.run_fusion([p1, p2], "--source", "usn")
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["source"], "usn")
        self.assertEqual(rep["filters"]["sources"], ["usn"])

    def test_since_until_filter(self):
        p = self.write_jsonl(
            "a.jsonl",
            [
                usn_rec("2026-02-10T08:00:00Z", usn=1),
                usn_rec("2026-02-10T10:00:00Z", usn=2),
                usn_rec("2026-02-10T12:00:00Z", usn=3),
            ],
        )
        entries, _ = self.run_fusion([p], "--since", "2026-02-10T09:00:00Z", "--until", "2026-02-10T11:00:00Z")
        self.assertEqual([e["details"]["usn"] for e in entries], [2])

    def test_since_until_bounds_are_inclusive(self):
        p = self.write_jsonl("a.jsonl", [usn_rec("2026-02-10T10:00:00Z")])
        entries, _ = self.run_fusion([p], "--since", "2026-02-10T10:00:00Z", "--until", "2026-02-10T10:00:00Z")
        self.assertEqual(len(entries), 1)

    def test_limit_stops_and_warns(self):
        p = self.write_jsonl(
            "a.jsonl",
            [usn_rec("2026-02-10T08:00:00Z", usn=1), usn_rec("2026-02-10T09:00:00Z", usn=2)],
        )
        entries, rep = self.run_fusion([p], "--limit", "1")
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["details"]["usn"], 1)
        self.assertEqual(rep["counts"]["emitted"], 1)
        self.assertIn("stopped_early_by_limit", rep["warnings"])

    def test_malformed_line_is_error_others_survive(self):
        path = os.path.join(self.dir, "broken.jsonl")
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(json.dumps(usn_rec("2026-02-10T08:00:00Z")) + "\n")
            fh.write("{not json}\n")
            fh.write(json.dumps(usn_rec("2026-02-10T09:00:00Z", usn=2)) + "\n")
        entries, rep = self.run_fusion([path])
        self.assertEqual(len(entries), 2)
        self.assertEqual(len(rep["errors"]), 1)
        self.assertEqual(rep["errors"][0]["line"], 2)
        self.assertIn("malformed_lines_present", rep["warnings"])
        self.assertTrue(any("malformed line" in note for note in rep["notes"]))

    def test_directory_expansion_ignores_non_jsonl(self):
        self.write_jsonl("one.jsonl", [usn_rec("2026-02-10T08:00:00Z")])
        self.write_jsonl("two.jsonl", [bam_rec("2026-02-10T10:00:00Z")])
        with open(os.path.join(self.dir, "notes.txt"), "w", encoding="utf-8") as fh:
            fh.write("not jsonl")
        entries, rep = self.run_fusion([self.dir])
        self.assertEqual(len(entries), 2)
        self.assertEqual(rep["counts"]["files"], 2)

    def test_empty_output_warns(self):
        path = self.write_jsonl("empty.jsonl", [{"artifact": "muicache"}])
        _, rep = self.run_fusion([path])
        self.assertIn("no_records_emitted", rep["warnings"])

    def test_invalid_source_is_usage_error(self):
        path = self.write_jsonl("a.jsonl", [usn_rec("2026-02-10T08:00:00Z")])
        rc = timeline.main([path, "--source", "bogus", "--quiet"])
        self.assertEqual(rc, 2)

    def test_invalid_since_is_usage_error(self):
        path = self.write_jsonl("a.jsonl", [usn_rec("2026-02-10T08:00:00Z")])
        rc = timeline.main([path, "--since", "yesterday", "--quiet"])
        self.assertEqual(rc, 2)

    def test_filters_echoed_in_report(self):
        p = self.write_jsonl("a.jsonl", [usn_rec("2026-02-10T08:00:00Z")])
        _, rep = self.run_fusion([p], "--source", "usn,reg", "--since", "2026-02-10T00:00:00Z")
        self.assertEqual(rep["filters"]["sources"], ["reg", "usn"])
        self.assertEqual(rep["filters"]["since"], "2026-02-10T00:00:00Z")
        self.assertEqual(rep["tool"], "timeline")
        self.assertEqual(rep["tool_version"], timeline.TOOL_VERSION)
        self.assertEqual(rep["schema_version"], 1)

    def test_cli_end_to_end(self):
        path = self.write_jsonl("a.jsonl", [usn_rec("2026-02-10T08:00:00Z"), bam_rec("2026-02-10T10:00:00Z")])
        proc = subprocess.run(
            [sys.executable, PARSER, path, "--jsonl", os.path.join(self.dir, "out.jsonl")],
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("emitted=2", proc.stderr)
        with open(os.path.join(self.dir, "out.jsonl"), encoding="utf-8") as fh:
            lines = [json.loads(line) for line in fh if line.strip()]
        self.assertEqual(len(lines), 2)
        self.assertEqual(lines[0]["ts"], "2026-02-10T08:00:00Z")

    def test_cli_stdout_default(self):
        path = self.write_jsonl("a.jsonl", [bam_rec("2026-02-10T10:00:00Z")])
        proc = subprocess.run(
            [sys.executable, PARSER, path, "--quiet"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        lines = [json.loads(line) for line in proc.stdout.splitlines() if line.strip()]
        self.assertEqual(len(lines), 1)
        self.assertEqual(lines[0]["action"], "reg:bam_executed")

    def test_missing_input_records_error_entry(self):
        out = os.path.join(self.dir, "timeline.jsonl")
        report = os.path.join(self.dir, "report.json")
        rc = timeline.main(
            [os.path.join(self.dir, "nope-does-not-exist.jsonl"), "--jsonl", out, "--report", report, "--quiet"]
        )
        self.assertEqual(rc, 0)
        with open(report, encoding="utf-8") as fh:
            rep = json.load(fh)
        self.assertEqual(rep["counts"]["failed"], 1)
        self.assertIn("files_failed_to_parse", rep["warnings"])

    def test_empty_directory_is_fatal(self):
        rc = timeline.main([self.dir, "--quiet"])
        self.assertEqual(rc, 1)


if __name__ == "__main__":
    unittest.main()
