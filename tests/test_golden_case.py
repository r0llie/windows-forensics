"""Synthetic end-to-end regression for the case analysis pipeline."""

import json
import os
import subprocess
import sys
import tempfile
import unittest

import test_mft as mft_fixtures
import test_usn as usn_fixtures

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
TOOLS_DIR = os.path.join(os.path.dirname(TESTS_DIR), "tools")
MFT_PARSE = os.path.join(TOOLS_DIR, "mft_parse.py")
USN_PARSE = os.path.join(TOOLS_DIR, "usn_parse.py")
TIMELINE = os.path.join(TOOLS_DIR, "timeline.py")
REPORT = os.path.join(TOOLS_DIR, "report.py")
VALIDATE = os.path.join(TOOLS_DIR, "validate.py")


def run_tool(args):
    proc = subprocess.run([sys.executable] + args, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(
            "tool failed: %s\nrc=%d\nstderr=%s"
            % (args[0], proc.returncode, proc.stderr[:2000])
        )


def load_json(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def load_jsonl(path):
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


class SyntheticCasePipelineTest(unittest.TestCase):
    """Exercise parser -> timeline -> validation -> report with generated data."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="synthetic_case_")
        self.addCleanup(self.tmp.cleanup)
        self.case = self.tmp.name
        self.parse_dir = os.path.join(self.case, "parse")
        os.makedirs(self.parse_dir)

        mft_path = os.path.join(self.case, "synthetic.mft")
        with open(mft_path, "wb") as fh:
            fh.write(mft_fixtures.build_record(index=0, attrs=mft_fixtures.SIMPLE_ATTRS))
            fh.write(mft_fixtures.build_record(index=1, attrs=mft_fixtures.SIMPLE_ATTRS))
        run_tool([
            MFT_PARSE, mft_path,
            "--jsonl", os.path.join(self.parse_dir, "mft.jsonl"),
            "--report", os.path.join(self.parse_dir, "mft_report.json"),
            "--quiet",
        ])

        usn_path = os.path.join(self.case, "synthetic.usn")
        with open(usn_path, "wb") as fh:
            fh.write(usn_fixtures.rec_v2(usn_val=1000, reason=0x00000100, name="hello.txt"))
            fh.write(usn_fixtures.rec_v2(usn_val=1001, reason=0x00000200, name="hello.txt"))
        run_tool([
            USN_PARSE, usn_path,
            "--jsonl", os.path.join(self.parse_dir, "usn.jsonl"),
            "--report", os.path.join(self.parse_dir, "usn_report.json"),
            "--quiet",
        ])

        self.timeline_path = os.path.join(self.case, "timeline.jsonl")
        run_tool([
            TIMELINE, self.parse_dir,
            "--jsonl", self.timeline_path,
            "--report", os.path.join(self.case, "timeline_report.json"),
            "--quiet",
        ])
        self.findings_path = os.path.join(self.case, "findings.jsonl")
        run_tool([
            VALIDATE, self.parse_dir,
            "--jsonl", self.findings_path,
            "--report", os.path.join(self.case, "validate_report.json"),
            "--quiet",
        ])
        self.story_path = os.path.join(self.case, "case_story.md")
        run_tool([
            REPORT, self.timeline_path,
            "--out", self.story_path,
            "--report", os.path.join(self.case, "case_story_report.json"),
            "--quiet",
        ])

    def test_synthetic_artifacts_parse(self):
        mft_rows = load_jsonl(os.path.join(self.parse_dir, "mft.jsonl"))
        usn_rows = load_jsonl(os.path.join(self.parse_dir, "usn.jsonl"))
        self.assertEqual(len(mft_rows), 2)
        self.assertEqual(mft_rows[0]["primary_name"], "hello.txt")
        self.assertEqual([r["reason_flags"] for r in usn_rows], [["FILE_CREATE"], ["FILE_DELETE"]])

    def test_timeline_contains_both_sources(self):
        rows = load_jsonl(self.timeline_path)
        self.assertGreaterEqual(len(rows), 4)
        self.assertEqual({row["source"] for row in rows}, {"mft", "usn"})
        report = load_json(os.path.join(self.case, "timeline_report.json"))
        self.assertEqual(report["counts"]["emitted"], len(rows))

    def test_validation_reports_missing_inputs(self):
        report = load_json(os.path.join(self.case, "validate_report.json"))
        self.assertTrue(report.get("skipped_rules"))
        self.assertTrue(os.path.isfile(self.findings_path))

    def test_machine_story_is_written(self):
        self.assertTrue(os.path.isfile(self.story_path))
        with open(self.story_path, encoding="utf-8") as fh:
            self.assertTrue(fh.read().strip())


if __name__ == "__main__":
    unittest.main()
