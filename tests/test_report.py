import json
import os
import subprocess
import sys
import tempfile
import unittest

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
TOOLS_DIR = os.path.join(os.path.dirname(TESTS_DIR), "tools")
sys.path.insert(0, TOOLS_DIR)

import report  # noqa: E402
import timeline  # noqa: E402

REPORT = os.path.join(TOOLS_DIR, "report.py")


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


def bam_rec(ts="2026-02-10T09:00:00Z", path="C:\\Tools\\run.exe"):
    return {
        "tool": "reg_parse",
        "schema_version": 1,
        "artifact": "bam",
        "hive": "SYSTEM",
        "key_path": "SYSTEM\\...\\bam\\State\\UserSettings\\S-1-5-21",
        "warnings": [],
        "control_set": 1,
        "user_sid": "S-1-5-21",
        "path": path,
        "value_size": 24,
        "execution_time": ts,
        "windows_app_flag": 0,
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
        "run_count": 5,
        "run_times": list(run_times),
        "last_run_time": last_run_time,
        "warnings": [],
    }


def entry(ts, source="usn", action="usn:FILE_CREATE", target="a.tmp"):
    return {
        "ts": ts,
        "source": source,
        "artifact": "usn",
        "action": action,
        "target": target,
        "details": {},
        "record_ref": "%s#x" % source,
    }


class ReportTestCase(unittest.TestCase):
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

    def run_report(self, inputs, *extra):
        story_path = os.path.join(self.dir, "story.md")
        report_path = os.path.join(self.dir, "report.json")
        rc = report.main(
            list(inputs) + ["--out", story_path, "--report", report_path, "--quiet"] + list(extra)
        )
        self.assertEqual(rc, 0)
        with open(story_path, encoding="utf-8") as fh:
            story = fh.read()
        with open(report_path, encoding="utf-8") as fh:
            rep = json.load(fh)
        return story, rep

    def test_story_sections_and_counts(self):
        path = self.write_jsonl("t.jsonl", [entry("2026-02-10T08:00:00Z"), entry("2026-02-10T09:00:00Z", source="reg")])
        story, rep = self.run_report([path], "--title", "unit host")
        self.assertIn("# Machine story - unit host", story)
        self.assertIn("## Inputs", story)
        self.assertIn("## Coverage", story)
        self.assertIn("## Headline observations", story)
        self.assertIn("## Timeline excerpt", story)
        self.assertIn("## Caveats", story)
        self.assertIn("**2 timeline entries**", story)
        self.assertEqual(rep["counts"]["entries"], 2)
        self.assertEqual(rep["counts"]["by_source"], {"reg": 1, "usn": 1})

    def test_parser_records_are_fused_on_the_fly(self):
        path = self.write_jsonl(
            "raw.jsonl",
            [
                usn_rec("2026-02-10T08:00:00Z"),
                bam_rec("2026-02-10T09:00:00Z"),
                pf_rec(run_times=["2026-02-10T10:00:00Z"], last_run_time="2026-02-10T10:00:00Z"),
            ],
        )
        story, rep = self.run_report([path])
        self.assertEqual(rep["counts"]["entries"], 4)
        self.assertEqual(rep["counts"]["by_source"], {"pf": 2, "reg": 1, "usn": 1})
        self.assertIn("Execution evidence", story)
        self.assertIn("CMD.EXE x2", story)

    def test_mixed_timeline_and_parser_inputs(self):
        t = self.write_jsonl("t.jsonl", [entry("2026-02-10T08:00:00Z")])
        raw = self.write_jsonl("raw.jsonl", [bam_rec("2026-02-10T09:00:00Z")])
        story, rep = self.run_report([t, raw])
        self.assertEqual(rep["counts"]["entries"], 2)
        self.assertEqual(rep["counts"]["by_source"], {"reg": 1, "usn": 1})

    def test_excerpt_head_and_tail(self):
        records = [entry("2026-02-10T%02d:00:00Z" % h) for h in range(12)]
        path = self.write_jsonl("t.jsonl", records)
        story, _ = self.run_report([path], "--excerpt", "2")
        self.assertIn("First 2 of 12 entries:", story)
        self.assertIn("Last 2 of 12 entries:", story)
        self.assertNotIn("All 12 entries:", story)
        self.assertIn("2026-02-10T00:00:00Z", story)
        self.assertIn("2026-02-10T11:00:00Z", story)

    def test_small_timeline_prints_all_entries_once(self):
        path = self.write_jsonl("t.jsonl", [entry("2026-02-10T00:00:00Z"), entry("2026-02-10T01:00:00Z")])
        story, _ = self.run_report([path])
        self.assertIn("All 2 entries:", story)
        self.assertNotIn("First 2 of 2", story)

    def test_filters_apply_and_echo(self):
        records = [
            entry("2026-02-10T08:00:00Z"),
            entry("2026-02-10T12:00:00Z", source="reg", action="reg:bam_executed"),
        ]
        path = self.write_jsonl("t.jsonl", records)
        story, rep = self.run_report([path], "--source", "reg", "--since", "2026-02-10T10:00:00Z")
        self.assertEqual(rep["counts"]["entries"], 1)
        self.assertEqual(rep["filters"]["sources"], ["reg"])
        self.assertEqual(rep["filters"]["since"], "2026-02-10T10:00:00Z")
        self.assertIn("reg:bam_executed", story)

    def test_skipped_records_are_reported(self):
        path = self.write_jsonl(
            "mix.jsonl",
            [
                {"artifact": "typedpaths", "paths": []},
                {"artifact": "brand_new"},
                usn_rec("2026-02-10T08:00:00Z"),
            ],
        )
        story, rep = self.run_report([path])
        self.assertEqual(rep["counts"]["skipped_no_timestamp"], {"typedpaths": 1})
        self.assertEqual(rep["counts"]["skipped_unknown_artifact"], {"brand_new": 1})
        self.assertIn("typedpaths: 1", story)
        self.assertIn("brand_new: 1", story)

    def test_malformed_lines_quality_note(self):
        path = os.path.join(self.dir, "broken.jsonl")
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(json.dumps(entry("2026-02-10T08:00:00Z")) + "\n")
            fh.write("{nope}\n")
        story, rep = self.run_report([path])
        self.assertEqual(rep["counts"]["malformed_lines"], 1)
        self.assertIn("malformed_lines_present", rep["warnings"])
        self.assertIn("Data quality:", story)
        self.assertIn("malformed line(s) were skipped", story)

    def test_zero_entries_story(self):
        path = self.write_jsonl("empty.jsonl", [{"artifact": "muicache"}])
        story, rep = self.run_report([path])
        self.assertIn("no_records_emitted", rep["warnings"])
        self.assertIn("_No entries._", story)
        self.assertIn("No entries were narrated", story)

    def test_directory_expansion(self):
        self.write_jsonl("a.jsonl", [entry("2026-02-10T08:00:00Z")])
        self.write_jsonl("b.jsonl", [entry("2026-02-10T09:00:00Z", source="reg")])
        story, rep = self.run_report([self.dir])
        self.assertEqual(rep["counts"]["files"], 2)
        self.assertEqual(rep["counts"]["entries"], 2)

    def test_report_sidecar_sections(self):
        records = [bam_rec("2026-02-10T09:00:00Z"), bam_rec("2026-02-10T11:00:00Z", path="C:\\Tools\\run.exe")]
        path = self.write_jsonl("t.jsonl", records)
        _, rep = self.run_report([path])
        self.assertEqual(rep["tool"], "report")
        self.assertEqual(rep["tool_version"], report.TOOL_VERSION)
        self.assertEqual(rep["schema_version"], 1)
        self.assertEqual(rep["counts"]["execution_targets"][0]["target"], "C:\\Tools\\run.exe")
        self.assertEqual(rep["counts"]["execution_targets"][0]["count"], 2)
        self.assertEqual(rep["counts"]["execution_targets"][0]["last_ts"], "2026-02-10T11:00:00Z")
        self.assertEqual(rep["counts"]["busiest_days"], [{"date": "2026-02-10", "count": 2}])

    def test_extreme_timestamps_are_flagged(self):
        records = [
            entry("1980-01-01T00:00:00Z"),
            entry("2038-01-12T06:39:12Z", source="reg"),
            entry("2026-02-10T08:00:00Z"),
        ]
        path = self.write_jsonl("t.jsonl", records)
        story, rep = self.run_report([path])
        self.assertEqual(rep["counts"]["extreme_timestamps"]["count"], 2)
        self.assertIn("extreme timestamps", story)
        self.assertIn("1980-01-01", rep["counts"]["extreme_timestamps"]["examples"][0])

    def test_nonextreme_timestamps_not_flagged(self):
        path = self.write_jsonl("t.jsonl", [entry("2026-02-10T08:00:00Z"), entry("2010-06-02T11:35:34Z")])
        story, rep = self.run_report([path])
        self.assertEqual(rep["counts"]["extreme_timestamps"]["count"], 0)
        self.assertNotIn("extreme timestamps", story)

    def test_deterministic_story_except_generated_at(self):
        path = self.write_jsonl("t.jsonl", [entry("2026-02-10T08:00:00Z")])
        story1, _ = self.run_report([path])
        story2, _ = self.run_report([path])
        strip = lambda s: "\n".join(line for line in s.splitlines() if not line.startswith("_Generated at"))
        self.assertEqual(strip(story1), strip(story2))

    def test_invalid_source_is_usage_error(self):
        path = self.write_jsonl("t.jsonl", [entry("2026-02-10T08:00:00Z")])
        rc = report.main([path, "--source", "bogus", "--quiet"])
        self.assertEqual(rc, 2)

    def test_invalid_since_is_usage_error(self):
        path = self.write_jsonl("t.jsonl", [entry("2026-02-10T08:00:00Z")])
        rc = report.main([path, "--since", "yesterday", "--quiet"])
        self.assertEqual(rc, 2)

    def test_excerpt_must_be_positive(self):
        path = self.write_jsonl("t.jsonl", [entry("2026-02-10T08:00:00Z")])
        with self.assertRaises(SystemExit):
            report.main([path, "--excerpt", "0", "--quiet"])

    def test_cli_end_to_end(self):
        path = self.write_jsonl("t.jsonl", [usn_rec("2026-02-10T08:00:00Z")])
        out = os.path.join(self.dir, "story.md")
        proc = subprocess.run(
            [sys.executable, REPORT, path, "--out", out, "--title", "cli host"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("entries=1", proc.stderr)
        with open(out, encoding="utf-8") as fh:
            story = fh.read()
        self.assertIn("# Machine story - cli host", story)

    def test_cli_stdout_default(self):
        path = self.write_jsonl("t.jsonl", [usn_rec("2026-02-10T08:00:00Z")])
        proc = subprocess.run([sys.executable, REPORT, path, "--quiet"], capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("# Machine story - host activity", proc.stdout)

    def test_missing_input_records_error_entry(self):
        story_path = os.path.join(self.dir, "story.md")
        report_path = os.path.join(self.dir, "report.json")
        rc = report.main(
            [os.path.join(self.dir, "nope.jsonl"), "--out", story_path, "--report", report_path, "--quiet"]
        )
        self.assertEqual(rc, 0)
        with open(report_path, encoding="utf-8") as fh:
            rep = json.load(fh)
        self.assertEqual(rep["counts"]["failed"], 1)
        self.assertIn("files_failed_to_parse", rep["warnings"])

    def test_empty_directory_is_fatal(self):
        rc = report.main([self.dir, "--quiet"])
        self.assertEqual(rc, 1)


if __name__ == "__main__":
    unittest.main()
