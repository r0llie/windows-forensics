import json
import os
import subprocess
import sys
import tempfile
import unittest

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
TOOLS_DIR = os.path.join(os.path.dirname(TESTS_DIR), "tools")
sys.path.insert(0, TOOLS_DIR)

import validate  # noqa: E402

VALIDATE = os.path.join(TOOLS_DIR, "validate.py")

ARTIFACTS = [
    "usn",
    "mft",
    "pf",
    "evtx",
    "bam",
    "userassist",
    "amcache_inventory_application_file",
    "pending_file_rename_operations",
]


def empty_data():
    return {name: [] for name in ARTIFACTS}


def usn(name, ts, flags=("FILE_CREATE",), usn_id=1, ref="t.jsonl"):
    return {"artifact": "usn", "name": name, "timestamp": ts, "reason_flags": list(flags), "usn": usn_id, "_source_file": ref}


def mft(primary_name, si_created, fn_created=None, flags=(), record=1, in_use=True, si_modified=None, si_accessed=None):
    fns = [{"created": fn_created}] if fn_created else []
    return {
        "artifact": "mft",
        "primary_name": primary_name,
        "record_number": record,
        "in_use": in_use,
        "timestomp_flags": list(flags),
        "standard_information": {
            "created": si_created,
            "modified": si_modified or si_created,
            "accessed": si_accessed or si_created,
        },
        "file_names": fns,
        "_source_file": "t.jsonl",
    }


def evtx(event_id, ts, channel="System", record_id=1, event_data=None):
    return {
        "artifact": "eventlog",
        "event_id": event_id,
        "time_created": ts,
        "channel": channel,
        "record_id": record_id,
        "event_data": event_data or {},
        "source_file": "all.xml",
        "_source_file": "t.jsonl",
    }


def run(data, rule, limit=10):
    findings, skipped = validate.run_rules(data, {rule}, limit)
    if skipped:
        return None, skipped[0]
    return findings[0], None


class RuleTests(unittest.TestCase):
    def test_rule1_flags_claim_without_evidence(self):
        data = empty_data()
        data["usn"] = [usn("present.dll", "2026-01-01T00:00:00Z")]
        data["pf"] = [{"artifact": "pf", "executable": "GHOST.EXE", "run_times": [], "last_run_time": "2026-01-02T00:00:00Z", "_source_file": "t.jsonl"}]
        finding, _ = run(data, 1)
        self.assertEqual(finding["count"], 1)
        self.assertEqual(finding["examples"][0]["exe"], "ghost.exe")

    def test_rule1_matched_claims_not_flagged(self):
        data = empty_data()
        data["mft"] = [mft("present.exe", "2026-01-01T00:00:00Z")]
        data["bam"] = [{"artifact": "bam", "path": "C:\\X\\PRESENT.EXE", "execution_time": "2026-01-02T00:00:00Z", "hive": "h", "_source_file": "t.jsonl"}]
        finding, _ = run(data, 1)
        self.assertEqual(finding["count"], 0)

    def test_rule1_skipped_without_usn_and_mft(self):
        data = empty_data()
        data["pf"] = [{"artifact": "pf", "executable": "A.EXE", "_source_file": "t.jsonl"}]
        finding, skipped = run(data, 1)
        self.assertIsNone(finding)
        self.assertIn("missing input", skipped["reason"])

    def test_rule2_si_after_fn(self):
        data = empty_data()
        data["mft"] = [mft("stomped.exe", "2026-01-01T00:00:05Z", fn_created="2026-01-01T00:00:00Z")]
        finding, _ = run(data, 2)
        self.assertEqual(finding["count"], 1)
        self.assertIn("si_created_after_fn_created", finding["examples"][0]["reasons"])
        self.assertEqual(finding["by_reason"]["si_created_after_fn_created"], 1)

    def test_rule2_within_clock_skew_not_flagged(self):
        data = empty_data()
        data["mft"] = [mft("ok.exe", "2026-01-01T00:00:00.500000Z", fn_created="2026-01-01T00:00:00Z")]
        finding, _ = run(data, 2)
        self.assertEqual(finding["count"], 0)

    def test_rule2_si_before_fn_is_observation_only(self):
        data = empty_data()
        data["mft"] = [mft("installed.dll", "2026-01-01T00:00:00Z", fn_created="2026-02-01T00:00:00Z", flags=("si_created_before_fn_created",))]
        finding, _ = run(data, 2)
        self.assertEqual(finding["count"], 0)
        self.assertEqual(finding["by_parser_flag_observation"]["si_created_before_fn_created"], 1)

    def test_rule2_all_equal_whole_second(self):
        data = empty_data()
        data["mft"] = [mft("batch.dat", "2026-01-01T03:04:05.000000Z")]
        finding, _ = run(data, 2)
        self.assertEqual(finding["count"], 1)
        self.assertIn("si_all_equal_whole_second", finding["examples"][0]["reasons"])

    def test_rule3_create_near_install_matches(self):
        data = empty_data()
        data["evtx"] = [evtx(7045, "2026-01-10T12:00:00Z", event_data={"ServiceName": "Svc", "ImagePath": "C:\\Svc\\agent.exe"}, record_id=1)]
        data["usn"] = [usn("agent.exe", "2026-01-10T11:55:00Z")]
        finding, _ = run(data, 3)
        self.assertEqual(finding["count"], 0)
        self.assertIn("matched 1", finding["coverage_note"])

    def test_rule3_no_create_flags(self):
        data = empty_data()
        data["evtx"] = [evtx(7045, "2026-01-10T12:00:00Z", event_data={"ServiceName": "Svc", "ImagePath": "C:\\Svc\\agent.exe"})]
        data["usn"] = [usn("agent.exe", "2026-01-09T00:00:00Z")]
        finding, _ = run(data, 3)
        self.assertEqual(finding["count"], 1)
        self.assertEqual(finding["examples"][0]["service"], "Svc")

    def test_rule3_event_outside_usn_window_is_coverage_limited(self):
        data = empty_data()
        data["evtx"] = [evtx(7045, "2025-01-01T12:00:00Z", event_data={"ServiceName": "Svc", "ImagePath": "C:\\Svc\\agent.exe"})]
        data["usn"] = [usn("other.exe", "2026-01-10T00:00:00Z")]
        finding, _ = run(data, 3)
        self.assertEqual(finding["count"], 0)
        self.assertIn("coverage-limited", finding["coverage_note"])

    def test_rule4_log_clear_and_missing_ids(self):
        data = empty_data()
        data["evtx"] = [
            evtx(1102, "2026-01-01T00:00:00Z", channel="Security", record_id=100),
            evtx(4624, "2026-01-01T01:00:00Z", channel="Security", record_id=101),
            evtx(4624, "2026-01-01T02:00:00Z", channel="Security", record_id=150),
            evtx(4624, "2026-01-01T03:00:00Z", channel="Security", record_id=3),
        ]
        finding, _ = run(data, 4)
        self.assertEqual(finding["log_clear_events"], 1)
        self.assertEqual(finding["missing_record_ids"], 144)
        self.assertEqual(finding["discontinuities"], 0)

    def test_rule4_contiguous_channel_clean(self):
        data = empty_data()
        data["evtx"] = [evtx(1, "2026-01-01T0%d:00:00Z" % i, record_id=i) for i in range(1, 5)]
        finding, _ = run(data, 4)
        self.assertEqual(finding["count"], 0)
        self.assertEqual(finding["channels"][0]["missing_ids"], 0)

    def test_rule4_id_drop_detected_as_recreation(self):
        data = empty_data()
        data["evtx"] = [
            evtx(1, "2026-01-01T00:00:00Z", record_id=5000),
            evtx(1, "2026-01-01T01:00:00Z", record_id=5001),
            evtx(1, "2026-01-02T00:00:00Z", record_id=5),
        ]
        finding, _ = run(data, 4)
        self.assertEqual(finding["discontinuities"], 1)
        self.assertEqual(finding["examples"][0]["type"], "id_drop_after_higher")

    def test_rule5_bam_without_other_artifacts(self):
        data = empty_data()
        data["bam"] = [{"artifact": "bam", "path": "C:\\Apps\\SOLO.EXE", "execution_time": "2026-01-02T00:00:00Z", "hive": "h", "_source_file": "t.jsonl"}]
        finding, _ = run(data, 5)
        self.assertEqual(finding["count"], 1)
        self.assertEqual(finding["examples"][0]["exe"], "solo.exe")

    def test_rule5_userassist_name_fallback_clears(self):
        data = empty_data()
        data["bam"] = [{"artifact": "bam", "path": "C:\\Apps\\KNOWN.EXE", "execution_time": "2026-01-02T00:00:00Z", "hive": "h", "_source_file": "t.jsonl"}]
        data["userassist"] = [{"artifact": "userassist", "target": None, "name": "C:\\Apps\\KNOWN.EXE", "hive": "h", "_source_file": "t.jsonl"}]
        finding, _ = run(data, 5)
        self.assertEqual(finding["count"], 0)

    def test_rule6_link_date_before_si(self):
        data = empty_data()
        data["mft"] = [mft("file.bin", "2026-06-01T00:00:00Z")]
        data["amcache_inventory_application_file"] = [{
            "artifact": "amcache_inventory_application_file",
            "path": "C:\\stage\\file.bin", "name": "file.bin",
            "link_date_ts": "2026-01-01T00:00:00Z", "key_name": "0000", "hive": "h", "_source_file": "t.jsonl",
        }]
        finding, _ = run(data, 6)
        self.assertEqual(finding["count"], 1)
        self.assertEqual(finding["examples"][0]["delta_seconds"], 151 * 24 * 3600)

    def test_rule6_skipped_without_amcache(self):
        data = empty_data()
        data["mft"] = [mft("file.bin", "2026-06-01T00:00:00Z")]
        finding, skipped = run(data, 6)
        self.assertIsNone(finding)
        self.assertIn("amcache", skipped["reason"])

    def test_rule7_pending_rename_without_usn(self):
        data = empty_data()
        data["usn"] = [usn("other.dll", "2026-01-01T00:00:00Z")]
        data["pending_file_rename_operations"] = [{
            "artifact": "pending_file_rename_operations",
            "source": "\\??\\C:\\Temp\\moved.dll", "destination": "\\??\\C:\\Final\\moved.dll",
            "operation": "rename", "hive": "h", "_source_file": "t.jsonl",
        }]
        finding, _ = run(data, 7)
        self.assertEqual(finding["count"], 1)

    def test_rule7_usn_activity_clears(self):
        data = empty_data()
        data["usn"] = [usn("moved.dll", "2026-01-01T00:00:00Z")]
        data["pending_file_rename_operations"] = [{
            "artifact": "pending_file_rename_operations",
            "source": "\\??\\C:\\Temp\\moved.dll", "destination": "", "operation": "delete",
            "hive": "h", "_source_file": "t.jsonl",
        }]
        finding, _ = run(data, 7)
        self.assertEqual(finding["count"], 0)

    def test_rule8_uncorroborated_cluster(self):
        data = empty_data()
        data["evtx"] = [
            evtx(41, "2026-01-10T08:00:00Z", record_id=1),
            evtx(6008, "2026-01-10T08:00:30Z", record_id=2),
        ]
        finding, _ = run(data, 8)
        self.assertEqual(finding["count"], 1)
        self.assertEqual(finding["uncorroborated_clusters"], 1)
        self.assertEqual(finding["severity"], "medium")
        self.assertEqual(sorted(finding["examples"][0]["event_ids"]), [41, 6008])

    def test_rule8_prior_shutdown_lowers_severity(self):
        data = empty_data()
        data["evtx"] = [
            evtx(1074, "2026-01-10T06:00:00Z", record_id=1, event_data={"param3": "Other (Unplanned)"}),
            evtx(41, "2026-01-10T08:00:00Z", record_id=2),
        ]
        finding, _ = run(data, 8)
        self.assertEqual(finding["severity"], "low")
        self.assertEqual(finding["uncorroborated_clusters"], 0)
        self.assertEqual(finding["examples"][0]["prior_shutdown_intent"]["param3"], "Other (Unplanned)")

    def test_rule9_process_without_execution_artifacts(self):
        data = empty_data()
        data["evtx"] = [
            evtx(4688, "2026-01-10T08:00:00Z", event_data={"NewProcessName": "C:\\Tools\\MYSTERY.EXE"}, record_id=1),
            evtx(4688, "2026-01-10T08:01:00Z", event_data={"NewProcessName": ""}, record_id=2),
        ]
        data["pf"] = [{"artifact": "pf", "executable": "KNOWN.EXE", "_source_file": "t.jsonl"}]
        finding, _ = run(data, 9)
        self.assertEqual(finding["count"], 1)
        self.assertIn("empty NewProcessName 1", finding["coverage_note"])

    def test_rule9_known_exe_clears(self):
        data = empty_data()
        data["evtx"] = [evtx(4688, "2026-01-10T08:00:00Z", event_data={"NewProcessName": "C:\\Tools\\KNOWN.EXE"})]
        data["bam"] = [{"artifact": "bam", "path": "C:\\Tools\\KNOWN.EXE", "execution_time": "2026-01-10T08:00:00Z", "hive": "h", "_source_file": "t.jsonl"}]
        finding, _ = run(data, 9)
        self.assertEqual(finding["count"], 0)

    def test_rule10_userassist_in_bam_window_without_bam(self):
        data = empty_data()
        data["bam"] = [{"artifact": "bam", "path": "C:\\Apps\\A.EXE", "execution_time": "2026-01-05T00:00:00Z", "hive": "h", "_source_file": "t.jsonl"}]
        data["userassist"] = [
            {"artifact": "userassist", "target": None, "name": "steam://run/570", "kind": "uri",
             "last_run_time": "2026-01-06T00:00:00Z", "hive": "h", "_source_file": "t.jsonl"},
            {"artifact": "userassist", "target": "C:\\Apps\\A.EXE", "name": "A",
             "last_run_time": "2026-01-06T00:00:00Z", "hive": "h", "_source_file": "t.jsonl"},
        ]
        finding, _ = run(data, 10)
        self.assertEqual(finding["count"], 1)
        self.assertEqual(finding["examples"][0]["kind"], "uri")

    def test_rule10_old_userassist_ignored(self):
        data = empty_data()
        data["bam"] = [{"artifact": "bam", "path": "C:\\Apps\\A.EXE", "execution_time": "2026-01-05T00:00:00Z", "hive": "h", "_source_file": "t.jsonl"}]
        data["userassist"] = [
            {"artifact": "userassist", "target": "C:\\Apps\\OLD.EXE",
             "last_run_time": "2025-12-01T00:00:00Z", "hive": "h", "_source_file": "t.jsonl"},
        ]
        finding, _ = run(data, 10)
        self.assertEqual(finding["count"], 0)


class CliTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = self.tmp.name

    def tearDown(self):
        self.tmp.cleanup()

    def write_inputs(self, records):
        path = os.path.join(self.dir, "in.jsonl")
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            for rec in records:
                fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
        return path

    def test_cli_end_to_end(self):
        self.write_inputs([
            usn("known.dll", "2026-01-01T00:00:00Z"),
            mft("stomped.exe", "2026-01-01T00:00:05Z", fn_created="2026-01-01T00:00:00Z"),
        ])
        jsonl = os.path.join(self.dir, "findings.jsonl")
        report_path = os.path.join(self.dir, "report.json")
        proc = subprocess.run(
            [sys.executable, VALIDATE, self.dir, "--jsonl", jsonl, "--report", report_path, "--rules", "1,2", "--quiet"],
            capture_output=True, text=True,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        with open(report_path, encoding="utf-8") as fh:
            report = json.load(fh)
        self.assertEqual(report["tool"], "validate")
        self.assertEqual(report["counts"]["records"]["usn"], 1)
        self.assertEqual(report["counts"]["records"]["mft"], 1)
        rules = [f["rule"] for f in report["findings"]]
        self.assertEqual(rules, [1, 2])
        with open(jsonl, encoding="utf-8") as fh:
            lines = [json.loads(line) for line in fh if line.strip()]
        self.assertEqual(len(lines), len(report["findings"]))

    def test_cli_malformed_line_counted(self):
        path = os.path.join(self.dir, "bad.jsonl")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("{not json}\n")
        proc = subprocess.run(
            [sys.executable, VALIDATE, path, "--jsonl", "-", "--report", os.path.join(self.dir, "r.json"), "--quiet"],
            capture_output=True, text=True,
        )
        self.assertEqual(proc.returncode, 0)
        with open(os.path.join(self.dir, "r.json"), encoding="utf-8") as fh:
            report = json.load(fh)
        self.assertEqual(report["inputs"]["failed"], 1)
        self.assertIn("files_failed_to_parse", report["warnings"])

    def test_cli_usage_errors(self):
        proc = subprocess.run([sys.executable, VALIDATE], capture_output=True, text=True)
        self.assertEqual(proc.returncode, 2)
        proc = subprocess.run([sys.executable, VALIDATE, self.dir, "--rules", "99"], capture_output=True, text=True)
        self.assertEqual(proc.returncode, 2)
        proc = subprocess.run([sys.executable, VALIDATE, self.dir, "--examples", "0"], capture_output=True, text=True)
        self.assertEqual(proc.returncode, 2)

    def test_cli_rules_filter_skips_rest(self):
        self.write_inputs([usn("a.dll", "2026-01-01T00:00:00Z")])
        report_path = os.path.join(self.dir, "r.json")
        proc = subprocess.run(
            [sys.executable, VALIDATE, self.dir, "--rules", "7", "--report", report_path, "--jsonl", "-", "--quiet"],
            capture_output=True, text=True,
        )
        self.assertEqual(proc.returncode, 0)
        with open(report_path, encoding="utf-8") as fh:
            report = json.load(fh)
        self.assertEqual([f["rule"] for f in report["findings"]], [7])


if __name__ == "__main__":
    unittest.main()
