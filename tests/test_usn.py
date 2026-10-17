#!/usr/bin/env python3
"""Tests for tools/usn_parse.py.

Run from the skill root:
    python -m unittest discover -s tests -v
"""

from __future__ import annotations

import json
import os
import struct
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timezone

SKILL_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
TOOLS_DIR = os.path.join(SKILL_ROOT, "tools")
if TOOLS_DIR not in sys.path:
    sys.path.insert(0, TOOLS_DIR)

import usn_parse as usn

PARSER = os.path.join(TOOLS_DIR, "usn_parse.py")
FT_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
SAMPLE_DT = datetime(2024, 1, 15, 12, 0, 0, 123456, tzinfo=timezone.utc)
SAMPLE_FT = None

DEFAULT_FRN = 0x0009000000001234
DEFAULT_PFRN = 0x0005000000000001


def ft_of(dt):
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    delta = dt - FT_EPOCH
    return (delta.days * 86400 + delta.seconds) * 10_000_000 + delta.microseconds * 10


SAMPLE_FT = ft_of(SAMPLE_DT)


def pad8(size):
    return (size + 7) & ~7


def pad_to(data, size):
    return data + b"\x00" * (size - len(data))


def rec_v2(
    usn_val=1000,
    frn=DEFAULT_FRN,
    pfrn=DEFAULT_PFRN,
    reason=0x00000100,
    source=0,
    security_id=256,
    attrs=0x20,
    name="file.txt",
    name_bytes=None,
    minor=0,
    ft_override=None,
    name_len_override=None,
    name_off_override=60,
    rec_len_override=None,
):
    if name_bytes is None:
        name_bytes = name.encode("utf-16-le")
    name_len = len(name_bytes) if name_len_override is None else name_len_override
    ft = SAMPLE_FT if ft_override is None else ft_override
    record_length = pad8(60 + len(name_bytes))
    body = struct.pack(
        "<IHHQQQQIIIIHH",
        record_length,
        2,
        minor,
        frn,
        pfrn,
        usn_val,
        ft,
        reason,
        source,
        security_id,
        attrs,
        name_len,
        name_off_override,
    )
    rec = pad_to(body + name_bytes, record_length)
    if rec_len_override is not None:
        rec = struct.pack("<I", rec_len_override) + rec[4:]
    return rec


def rec_v3(
    usn_val=2000,
    frn=DEFAULT_FRN,
    pfrn=DEFAULT_PFRN,
    reason=0x00000100,
    source=0,
    security_id=256,
    attrs=0x20,
    name="file.txt",
    minor=0,
    ft_override=None,
    rec_len_override=None,
):
    name_bytes = name.encode("utf-16-le")
    ft = SAMPLE_FT if ft_override is None else ft_override
    record_length = pad8(76 + len(name_bytes))
    header = struct.pack("<IHH", record_length, 3, minor)
    body = struct.pack(
        "<16s16sQQIIIIHH",
        frn.to_bytes(16, "little"),
        pfrn.to_bytes(16, "little"),
        usn_val,
        ft,
        reason,
        source,
        security_id,
        attrs,
        len(name_bytes),
        76,
    )
    rec = pad_to(header + body + name_bytes, record_length)
    if rec_len_override is not None:
        rec = struct.pack("<I", rec_len_override) + rec[4:]
    return rec


def rec_v4(
    usn_val=3000,
    frn=DEFAULT_FRN,
    pfrn=DEFAULT_PFRN,
    reason=0x00000100,
    source=0,
    remaining=0,
    extents=((0, 4096), (4096, 1024)),
    ext_size=16,
    minor=0,
):
    record_length = 64 + len(extents) * ext_size
    header = struct.pack("<IHH", record_length, 4, minor)
    body = struct.pack(
        "<16s16sQIIIHH",
        frn.to_bytes(16, "little"),
        pfrn.to_bytes(16, "little"),
        usn_val,
        reason,
        source,
        remaining,
        len(extents),
        ext_size,
    )
    ext = b"".join(struct.pack("<qq", offset, length) for offset, length in extents)
    return pad_to(header + body + ext, record_length)


def patch_usn(rec, value):
    buf = bytearray(rec)
    version = struct.unpack_from("<H", buf, 4)[0]
    pos = 24 if version == 2 else 40
    struct.pack_into("<Q", buf, pos, value)
    return bytes(buf)


def walk(data, include_raw=False):
    stats = usn.Stats()
    records = list(usn.iter_records(data, stats, include_raw=include_raw))
    return records, stats


def report_for(data, **kwargs):
    stats = usn.Stats()
    list(usn.iter_records(data, stats))
    return usn.build_report(stats, mode="offline", input_path="fixture", input_size=len(data), **kwargs)


class UsnParseRecordTests(unittest.TestCase):
    def test_v2_basic_fields(self):
        rec = rec_v2()
        records, _ = walk(rec)
        self.assertEqual(len(records), 1)
        r = records[0]
        self.assertEqual(r["version"], 2)
        self.assertEqual(r["minor_version"], 0)
        self.assertEqual(r["record_offset"], 0)
        self.assertEqual(r["usn"], 1000)
        self.assertEqual(r["file_reference"], "0x0009000000001234")
        self.assertEqual(r["parent_file_reference"], "0x0005000000000001")
        self.assertEqual(r["timestamp"], "2024-01-15T12:00:00.123456Z")
        self.assertEqual(r["timestamp_filetime"], SAMPLE_FT)
        self.assertEqual(r["reason_mask"], 0x100)
        self.assertEqual(r["reason_flags"], ["FILE_CREATE"])
        self.assertEqual(r["reason_unknown_mask"], 0)
        self.assertEqual(r["source_flags"], [])
        self.assertEqual(r["source_unknown_mask"], 0)
        self.assertEqual(r["security_id"], 256)
        self.assertEqual(r["file_attributes"], 0x20)
        self.assertEqual(r["name"], "file.txt")
        self.assertEqual(r["warnings"], [])

    def test_raw_hex_matches_record_bytes(self):
        rec = rec_v2()
        records, _ = walk(rec, include_raw=True)
        self.assertEqual(records[0]["raw_hex"], rec.hex())
        self.assertEqual(len(records[0]["raw_hex"]), 2 * len(rec))

    def test_zero_filetime_is_null_without_warning(self):
        records, _ = walk(rec_v2(ft_override=0))
        self.assertIsNone(records[0]["timestamp"])
        self.assertEqual(records[0]["timestamp_filetime"], 0)
        self.assertEqual(records[0]["warnings"], [])

    def test_timestamp_out_of_range(self):
        records, _ = walk(rec_v2(ft_override=0x7FFFFFFFFFFFFFFF))
        self.assertIsNone(records[0]["timestamp"])
        self.assertIn("timestamp_out_of_range", records[0]["warnings"])

    def test_lossy_name(self):
        name_bytes = "ab".encode("utf-16-le") + b"\x00\xd8"
        records, _ = walk(rec_v2(name_bytes=name_bytes))
        self.assertIn("\ufffd", records[0]["name"])
        self.assertIn("lossy_name", records[0]["warnings"])

    def test_odd_name_length(self):
        records, _ = walk(rec_v2(name="abcdefgh", name_len_override=5))
        self.assertEqual(records[0]["name"], "ab")
        self.assertIn("odd_name_length", records[0]["warnings"])

    def test_unknown_minor_version(self):
        records, _ = walk(rec_v2(minor=7))
        self.assertEqual(records[0]["minor_version"], 7)
        self.assertIn("unknown_minor_version", records[0]["warnings"])

    def test_unknown_reason_and_source_bits(self):
        records, _ = walk(rec_v2(reason=0x100 | 0x00000008, source=0x1 | 0x10))
        r = records[0]
        self.assertEqual(r["reason_flags"], ["FILE_CREATE"])
        self.assertEqual(r["reason_unknown_mask"], 0x8)
        self.assertIn("unknown_reason_bits", r["warnings"])
        self.assertEqual(r["source_flags"], ["DATA_MANAGEMENT"])
        self.assertEqual(r["source_unknown_mask"], 0x10)
        self.assertIn("unknown_source_bits", r["warnings"])

    def test_rename_produces_two_records(self):
        data = rec_v2(usn_val=10, reason=0x1000, name="old.txt") + rec_v2(
            usn_val=11, reason=0x2000, name="new.txt"
        )
        records, _ = walk(data)
        self.assertEqual(len(records), 2)
        self.assertEqual(records[0]["reason_flags"], ["RENAME_OLD_NAME"])
        self.assertEqual(records[1]["reason_flags"], ["RENAME_NEW_NAME"])
        self.assertEqual(records[0]["file_reference"], records[1]["file_reference"])
        self.assertEqual(records[0]["name"], "old.txt")
        self.assertEqual(records[1]["name"], "new.txt")

    def test_zero_gap_resync(self):
        r1 = rec_v2(name="first.txt")
        r2 = rec_v2(name="second.txt", usn_val=2000)
        gap = b"\x00" * 16
        records, stats = walk(r1 + gap + r2)
        self.assertEqual([r["name"] for r in records], ["first.txt", "second.txt"])
        self.assertEqual(records[1]["record_offset"], len(r1) + 16)
        self.assertEqual(
            stats.skipped_regions,
            [{"offset": len(r1), "length": 16, "reason": "zero_fill"}],
        )
        self.assertEqual(stats.zero_bytes, 16)
        rep = report_for(r1 + gap + r2)
        self.assertIn("zero_fill_present", rep["warnings"])

    def test_trailing_zeros_reported(self):
        r1 = rec_v2(name="solo.txt")
        records, stats = walk(r1 + b"\x00" * 24)
        self.assertEqual(len(records), 1)
        self.assertEqual(
            stats.skipped_regions,
            [{"offset": len(r1), "length": 24, "reason": "zero_fill"}],
        )

    def test_garbage_resync(self):
        r1 = rec_v2(name="before.exe")
        r2 = rec_v2(name="after.exe", usn_val=2000)
        garbage = b"\xff" * 8
        records, stats = walk(r1 + garbage + r2)
        self.assertEqual([r["name"] for r in records], ["before.exe", "after.exe"])
        self.assertEqual(stats.garbage_bytes, 8)
        self.assertEqual(
            stats.skipped_regions,
            [{"offset": len(r1), "length": 8, "reason": "no_valid_header"}],
        )

    def test_bad_record_bounds_resync(self):
        bad = rec_v2(name="bad.txt", name_off_override=200)
        good = rec_v2(name="good.txt", usn_val=2000)
        records, stats = walk(bad + good)
        self.assertEqual([r["name"] for r in records], ["good.txt"])
        self.assertEqual(records[0]["record_offset"], len(bad))
        self.assertEqual(
            stats.skipped_regions,
            [{"offset": 0, "length": len(bad), "reason": "no_valid_header"}],
        )

    def test_truncated_tail(self):
        r1 = rec_v2(name="ok.txt")
        r2 = rec_v2(name="cut.txt")
        hacked = rec_v2(name="cut.txt", rec_len_override=len(r2) + 8)
        records, stats = walk(r1 + hacked)
        self.assertEqual([r["name"] for r in records], ["ok.txt"])
        self.assertEqual(stats.truncated_bytes, len(r2))
        self.assertEqual(
            stats.skipped_regions,
            [{"offset": len(r1), "length": len(r2), "reason": "truncated_tail"}],
        )
        rep = report_for(r1 + hacked)
        self.assertIn("truncated_tail_present", rep["warnings"])

    def test_not_a_journal(self):
        records, stats = walk(b"\x42" * 128)
        self.assertEqual(records, [])
        self.assertEqual(stats.garbage_bytes, 128)
        self.assertEqual(
            stats.skipped_regions,
            [{"offset": 0, "length": 128, "reason": "no_valid_header"}],
        )
        rep = report_for(b"\x42" * 128)
        self.assertIn("no_valid_records", rep["warnings"])

    def test_empty_input(self):
        stats = usn.Stats()
        self.assertEqual(list(usn.iter_records(b"", stats)), [])
        rep = usn.build_report(stats, mode="offline", input_path="empty", input_size=0)
        self.assertIn("empty_input", rep["warnings"])

    def test_v3_fields(self):
        rec = rec_v3(name="v3file.txt")
        records, _ = walk(rec)
        r = records[0]
        self.assertEqual(r["version"], 3)
        self.assertEqual(r["file_reference"], "0x%032x" % DEFAULT_FRN)
        self.assertEqual(r["parent_file_reference"], "0x%032x" % DEFAULT_PFRN)
        self.assertEqual(r["timestamp"], "2024-01-15T12:00:00.123456Z")
        self.assertEqual(r["name"], "v3file.txt")
        self.assertEqual(r["reason_flags"], ["FILE_CREATE"])

    def test_v4_extents_and_absent_fields(self):
        rec = rec_v4()
        records, _ = walk(rec)
        r = records[0]
        self.assertEqual(r["version"], 4)
        for key in ("name", "timestamp", "timestamp_filetime", "security_id", "file_attributes"):
            self.assertNotIn(key, r)
        self.assertEqual(r["remaining_extents"], 0)
        self.assertEqual(r["extent_count"], 2)
        self.assertEqual(r["extent_size"], 16)
        self.assertEqual(
            r["extents"],
            [{"offset": 0, "length": 4096}, {"offset": 4096, "length": 1024}],
        )

    def test_v4_unexpected_extent_size(self):
        records, _ = walk(rec_v4(extents=((0, 4096),), ext_size=24))
        self.assertIn("unexpected_extent_size", records[0]["warnings"])

    def test_usn_offset_uniform(self):
        r1 = rec_v2(name="a.txt")
        r2 = rec_v2(name="b.txt")
        data = patch_usn(r1, 0) + patch_usn(r2, len(r1))
        rep = report_for(data)
        self.assertEqual(rep["usn_offset"]["distinct_deltas"], 1)
        self.assertEqual(rep["usn_offset"]["base_delta"], 0)
        self.assertEqual(rep["usn_offset"]["anomaly_records"], 0)
        self.assertNotIn("usn_offset_inconsistent", rep["warnings"])
        self.assertNotIn("capture_not_at_stream_start", rep["warnings"])

    def test_usn_offset_shifted_capture(self):
        r1 = rec_v2(name="a.txt")
        r2 = rec_v2(name="b.txt")
        data = patch_usn(r1, 4096) + patch_usn(r2, 4096 + len(r1))
        rep = report_for(data)
        self.assertEqual(rep["usn_offset"]["base_delta"], 4096)
        self.assertIn("capture_not_at_stream_start", rep["warnings"])

    def test_usn_offset_inconsistent(self):
        r1 = rec_v2(name="a.txt")
        r2 = rec_v2(name="b.txt")
        data = patch_usn(r1, 100) + patch_usn(r2, 600)
        rep = report_for(data)
        self.assertGreaterEqual(rep["usn_offset"]["distinct_deltas"], 2)
        self.assertEqual(rep["usn_offset"]["anomaly_records"], 1)
        self.assertIn("usn_offset_inconsistent", rep["warnings"])

    def test_record_matches_filters(self):
        records, _ = walk(rec_v2(usn_val=1000, reason=0x100, name="Dropper.EXE"))
        r = records[0]
        self.assertTrue(
            usn.record_matches(r, min_usn=999, max_usn=1001, reason_mask=0x100, name_contains="dropper")
        )
        self.assertFalse(usn.record_matches(r, min_usn=1001))
        self.assertFalse(usn.record_matches(r, max_usn=999))
        self.assertFalse(usn.record_matches(r, reason_mask=0x200))
        self.assertFalse(usn.record_matches(r, name_contains="other"))
        v4, _ = walk(rec_v4())
        self.assertTrue(usn.record_matches(v4[0]))
        self.assertFalse(usn.record_matches(v4[0], name_contains="x"))

    def test_parse_reason_arg(self):
        self.assertEqual(usn.parse_reason_arg("0x100"), 0x100)
        self.assertEqual(usn.parse_reason_arg("USN_REASON_FILE_CREATE"), 0x100)
        self.assertEqual(usn.parse_reason_arg("file_create"), 0x100)
        self.assertEqual(usn.parse_reason_arg("RENAME_OLD_NAME"), 0x1000)
        with self.assertRaises(ValueError):
            usn.parse_reason_arg("NOPE")

    def test_stats_counts_and_report_shape(self):
        data = rec_v2(name="x.txt", reason=0x100) + rec_v2(name="y.txt", reason=0x200, usn_val=2000)
        records, stats = walk(data)
        rep = usn.build_report(stats, mode="offline", input_path="f", input_size=len(data))
        self.assertEqual(rep["counts"]["records"], 2)
        self.assertEqual(rep["counts"]["by_version"], {2: 2})
        self.assertEqual(rep["counts"]["by_reason"]["FILE_CREATE"], 1)
        self.assertEqual(rep["counts"]["by_reason"]["FILE_DELETE"], 1)
        self.assertEqual(rep["usn_range"], {"min": 1000, "max": 2000})
        self.assertEqual(rep["time_range"]["min_utc"], "2024-01-15T12:00:00.123456Z")
        self.assertEqual(rep["tool"], "usn_parse")
        self.assertEqual(rep["schema_version"], 1)


class UsnParseCliTests(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmpdir.cleanup)
        self.tmp = self._tmpdir.name

    def run_cli(self, *args):
        return subprocess.run(
            [sys.executable, PARSER, *args],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            cwd=self.tmp,
        )

    def write_capture(self, data, name="capture.usn"):
        path = os.path.join(self.tmp, name)
        with open(path, "wb") as fh:
            fh.write(data)
        return path

    def read_jsonl(self, path):
        with open(path, encoding="utf-8") as fh:
            return [json.loads(line) for line in fh if line.strip()]

    def read_report(self, path):
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)

    def test_offline_jsonl_and_report(self):
        capture = self.write_capture(rec_v2() + rec_v3())
        out = os.path.join(self.tmp, "out.jsonl")
        rep = os.path.join(self.tmp, "report.json")
        p = self.run_cli(capture, "--jsonl", out, "--report", rep, "--quiet")
        self.assertEqual(p.returncode, 0, p.stderr)
        lines = self.read_jsonl(out)
        self.assertEqual(len(lines), 2)
        self.assertEqual([line["version"] for line in lines], [2, 3])
        report = self.read_report(rep)
        self.assertEqual(report["mode"], "offline")
        self.assertEqual(report["counts"]["records"], 2)
        self.assertEqual(report["counts"]["by_version"], {"2": 1, "3": 1})
        self.assertEqual(report["skipped_regions"], [])
        self.assertEqual(report["input"]["size_bytes"], len(rec_v2()) + len(rec_v3()))

    def test_name_filter(self):
        capture = self.write_capture(
            rec_v2(name="keep-me.txt") + rec_v2(name="drop-me.txt", usn_val=1001)
        )
        out = os.path.join(self.tmp, "out.jsonl")
        p = self.run_cli(capture, "--jsonl", out, "--name-contains", "KEEP", "--quiet")
        self.assertEqual(p.returncode, 0, p.stderr)
        lines = self.read_jsonl(out)
        self.assertEqual([line["name"] for line in lines], ["keep-me.txt"])

    def test_reason_filter_by_name_and_hex(self):
        capture = self.write_capture(
            rec_v2(name="keep-me.txt", reason=0x100) + rec_v2(name="drop-me.txt", reason=0x200, usn_val=1001)
        )
        out = os.path.join(self.tmp, "out.jsonl")
        p = self.run_cli(capture, "--jsonl", out, "--reason", "FILE_DELETE", "--quiet")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual([line["name"] for line in self.read_jsonl(out)], ["drop-me.txt"])
        out2 = os.path.join(self.tmp, "out2.jsonl")
        p2 = self.run_cli(capture, "--jsonl", out2, "--reason", "0x100", "--quiet")
        self.assertEqual(p2.returncode, 0, p2.stderr)
        self.assertEqual([line["name"] for line in self.read_jsonl(out2)], ["keep-me.txt"])

    def test_limit(self):
        capture = self.write_capture(rec_v2(name="one.txt") + rec_v2(name="two.txt", usn_val=1001))
        out = os.path.join(self.tmp, "out.jsonl")
        rep = os.path.join(self.tmp, "report.json")
        p = self.run_cli(capture, "--jsonl", out, "--report", rep, "--limit", "1", "--quiet")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(len(self.read_jsonl(out)), 1)
        report = self.read_report(rep)
        self.assertEqual(report["counts"]["emitted"], 1)
        self.assertEqual(report["counts"]["records"], 1)
        self.assertIn("stopped_early_by_limit", report["warnings"])

    def test_raw_mode(self):
        rec = rec_v2()
        capture = self.write_capture(rec)
        out = os.path.join(self.tmp, "out.jsonl")
        p = self.run_cli(capture, "--jsonl", out, "--raw", "--quiet")
        self.assertEqual(p.returncode, 0, p.stderr)
        lines = self.read_jsonl(out)
        self.assertEqual(bytes.fromhex(lines[0]["raw_hex"]), rec)

    def test_empty_file(self):
        capture = self.write_capture(b"")
        out = os.path.join(self.tmp, "out.jsonl")
        rep = os.path.join(self.tmp, "report.json")
        p = self.run_cli(capture, "--jsonl", out, "--report", rep, "--quiet")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(self.read_jsonl(out), [])
        report = self.read_report(rep)
        self.assertIn("empty_input", report["warnings"])

    def test_usage_errors(self):
        capture = self.write_capture(rec_v2())
        self.assertEqual(self.run_cli().returncode, 2)
        self.assertEqual(self.run_cli(capture, "--volume", "C:").returncode, 2)
        self.assertEqual(self.run_cli(capture, "--reason", "NOPE").returncode, 2)

    def test_missing_input_is_fatal(self):
        p = self.run_cli(os.path.join(self.tmp, "does-not-exist.usn"))
        self.assertEqual(p.returncode, 1)
        self.assertIn("fatal", p.stderr)


if __name__ == "__main__":
    unittest.main()
