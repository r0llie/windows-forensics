#!/usr/bin/env python3
"""Tests for tools/mft_parse.py.

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

import mft_parse as mft

PARSER = os.path.join(TOOLS_DIR, "mft_parse.py")
FT_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
DT = datetime(2024, 1, 15, 10, 0, 0, 123456, tzinfo=timezone.utc)
DT2 = datetime(2024, 1, 15, 11, 0, 0, 654321, tzinfo=timezone.utc)
WHOLE_SECOND = datetime(2021, 5, 5, 5, 5, 5, 0, tzinfo=timezone.utc)
OLD_DT = datetime(2020, 1, 1, 0, 0, 0, 500000, tzinfo=timezone.utc)


def ft_of(dt):
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    delta = dt - FT_EPOCH
    return (delta.days * 86400 + delta.seconds) * 10_000_000 + delta.microseconds * 10


def si_value(created=DT, modified=DT2, mft_modified=DT2, accessed=DT2, dos=0x20, owner=0, sec=512, quota=0, usn=123):
    return struct.pack(
        "<QQQQIIIIIIQQ",
        ft_of(created),
        ft_of(modified),
        ft_of(mft_modified),
        ft_of(accessed),
        dos,
        0,
        0,
        0,
        owner,
        sec,
        quota,
        usn,
    )


def fn_value(
    name,
    namespace=3,
    parent=5,
    created=DT,
    modified=DT2,
    mft_modified=DT2,
    accessed=DT2,
    alloc=0,
    real=5,
    flags=0x20,
):
    name_bytes = name.encode("utf-16-le")
    return struct.pack(
        "<QQQQQQQIIBB",
        parent,
        ft_of(created),
        ft_of(modified),
        ft_of(mft_modified),
        ft_of(accessed),
        alloc,
        real,
        flags,
        0,
        len(name),
        namespace,
    ) + name_bytes


def attr(atype, value, name="", aflags=0, aid=0, indexed=0, override_length=None):
    name_bytes = name.encode("utf-16-le")
    name_off = 0x18 if name_bytes else 0
    value_offset = (0x18 + len(name_bytes) + 7) & ~7
    total = (value_offset + len(value) + 7) & ~7
    head = struct.pack("<IIBBHHH", atype, total, 0, len(name_bytes) // 2, name_off, aflags, aid)
    head += struct.pack("<IHBB", len(value), value_offset, indexed, 0)
    data = head + name_bytes
    data = data + b"\x00" * (value_offset - len(data)) + value
    data = data + b"\x00" * (total - len(data))
    if override_length is not None:
        data = data[:4] + struct.pack("<I", override_length) + data[8:]
    return data


def attr_data_nonresident(runs_bytes, alloc, real, init, cunit=0, name="", aflags=0, aid=0, last_vcn=0, start_vcn=0):
    name_bytes = name.encode("utf-16-le")
    name_off = 0x40 if name_bytes else 0
    runs_off = (0x40 + len(name_bytes) + 7) & ~7
    total = (runs_off + len(runs_bytes) + 7) & ~7
    head = struct.pack("<IIBBHHH", 0x80, total, 1, len(name_bytes) // 2, name_off, aflags, aid)
    head += struct.pack("<qqHHIQQQ", start_vcn, last_vcn, runs_off, cunit, 0, alloc, real, init)
    data = head + name_bytes
    data = data + b"\x00" * (runs_off - len(data)) + runs_bytes
    data = data + b"\x00" * (total - len(data))
    return data


def attr_list(entries):
    body = b""
    for atype, vcn, base_ref, aid in entries:
        entry = struct.pack("<IHBBQQH", atype, 32, 0, 0x1A, vcn, base_ref, aid)
        entry += b"\x00" * (32 - len(entry))
        body += entry
    return attr(0x20, body, aid=1)


def build_record(
    index=5,
    attrs=b"",
    seq=1,
    links=1,
    flags=1,
    lsn=100,
    base_ref=0,
    next_id=7,
    record_size=1024,
    usa_off=0x30,
    corrupt_fixup=False,
):
    num_sectors = record_size // 512
    usa_words = num_sectors + 1
    first_attr = (usa_off + usa_words * 2 + 7) & ~7
    rec = bytearray(record_size)
    used = (first_attr + len(attrs) + 4 + 7) & ~7
    struct.pack_into(
        "<4sHHQHHHHIIQHH",
        rec,
        0,
        b"FILE",
        usa_off,
        usa_words,
        lsn,
        seq,
        links,
        first_attr,
        flags,
        used,
        record_size,
        base_ref,
        next_id,
        0,
    )
    struct.pack_into("<I", rec, 0x2C, index)
    rec[first_attr : first_attr + len(attrs)] = attrs
    struct.pack_into("<I", rec, first_attr + len(attrs), 0xFFFFFFFF)
    usn_val = 0x00AB
    struct.pack_into("<H", rec, usa_off, usn_val)
    for i in range(1, usa_words):
        pos = i * 512 - 2
        original = int.from_bytes(rec[pos : pos + 2], "little")
        struct.pack_into("<H", rec, usa_off + 2 * i, original)
        if corrupt_fixup and i == 1:
            rec[pos : pos + 2] = b"\xAA\xBB"
        else:
            struct.pack_into("<H", rec, pos, usn_val)
    return bytes(rec)


SIMPLE_ATTRS = attr(0x10, si_value()) + attr(0x30, fn_value("hello.txt", real=5)) + attr(0x80, b"hello")


def walk(data, record_size=1024, include_raw=False):
    stats = mft.Stats()
    records = list(mft.iter_records(data, record_size, stats, include_raw=include_raw))
    return records, stats


def report_for(data, record_size=1024, **kwargs):
    stats = mft.Stats()
    list(mft.iter_records(data, record_size, stats))
    return mft.build_report(stats, input_path="fixture", input_size=len(data), record_size=record_size, **kwargs)


class MftParseRecordTests(unittest.TestCase):
    def test_basic_record(self):
        rec = build_record(index=0, attrs=SIMPLE_ATTRS)
        records, stats = walk(rec)
        self.assertEqual(len(records), 1)
        r = records[0]
        self.assertEqual(r["record_number"], 0)
        self.assertEqual(r["record_offset"], 0)
        self.assertTrue(r["in_use"])
        self.assertFalse(r["is_directory"])
        self.assertFalse(r["is_extension"])
        self.assertEqual(r["sequence_number"], 1)
        self.assertEqual(r["file_reference"], "0x0001000000000000")
        self.assertIsNone(r["base_record_reference"])
        self.assertEqual(r["primary_name"], "hello.txt")
        self.assertEqual(r["size"], 5)
        self.assertEqual(r["standard_information"]["created"], "2024-01-15T10:00:00.123456Z")
        self.assertEqual(r["standard_information"]["modified"], "2024-01-15T11:00:00.654321Z")
        self.assertEqual(r["standard_information"]["dos_flags"], 0x20)
        self.assertEqual(r["standard_information"]["security_id"], 512)
        self.assertEqual(r["standard_information"]["last_usn"], 123)
        self.assertEqual(r["data"], [{"name": None, "non_resident": False, "size": 5}])
        self.assertEqual(r["timestomp_flags"], [])
        self.assertEqual(r["warnings"], [])
        self.assertEqual(stats.slots, 1)
        self.assertEqual(stats.parsed, 1)
        self.assertEqual(stats.in_use, 1)

    def test_deleted_record(self):
        attrs = attr(0x10, si_value()) + attr(0x30, fn_value("gone.txt", real=5))
        records, stats = walk(build_record(index=0, flags=0, seq=9, attrs=attrs))
        r = records[0]
        self.assertFalse(r["in_use"])
        self.assertEqual(r["sequence_number"], 9)
        self.assertEqual(r["file_reference"], "0x0009000000000000")
        self.assertEqual(stats.deleted, 1)
        self.assertEqual(stats.in_use, 0)

    def test_namespace_priority(self):
        attrs = (
            attr(0x10, si_value())
            + attr(0x30, fn_value("LONGFILE.TXT", namespace=1))
            + attr(0x30, fn_value("LONGFI~1.TXT", namespace=2))
        )
        records, _ = walk(build_record(attrs=attrs))
        r = records[0]
        self.assertEqual(len(r["file_names"]), 2)
        self.assertEqual(r["primary_name"], "LONGFILE.TXT")
        namespaces = {fn["namespace_name"] for fn in r["file_names"]}
        self.assertEqual(namespaces, {"Win32", "DOS"})

    def test_dos_only_name_fallback(self):
        attrs = attr(0x10, si_value()) + attr(0x30, fn_value("SHORT.TXT", namespace=2))
        records, _ = walk(build_record(attrs=attrs))
        self.assertEqual(records[0]["primary_name"], "SHORT.TXT")

    def test_timestomp_si_before_fn(self):
        attrs = attr(0x10, si_value(created=OLD_DT, modified=OLD_DT, mft_modified=OLD_DT, accessed=OLD_DT))
        attrs += attr(0x30, fn_value("backdated.exe", created=DT))
        records, stats = walk(build_record(attrs=attrs))
        r = records[0]
        self.assertIn("si_created_before_fn_created", r["timestomp_flags"])
        self.assertEqual(stats.timestomp["si_created_before_fn_created"], 1)
        self.assertEqual(stats.timestomp_records, 1)

    def test_whole_second_precision_flag(self):
        attrs = attr(0x10, si_value(created=WHOLE_SECOND, modified=WHOLE_SECOND))
        attrs += attr(0x30, fn_value("packed.bin", created=WHOLE_SECOND, modified=WHOLE_SECOND))
        records, _ = walk(build_record(attrs=attrs))
        r = records[0]
        self.assertIn("si_whole_second_precision", r["timestomp_flags"])
        self.assertNotIn("si_created_before_fn_created", r["timestomp_flags"])

    def test_si_zero_timestamps_flag(self):
        zero_si = struct.pack("<QQQQIIIIIIQQ", 0, 0, 0, 0, 0x20, 0, 0, 0, 0, 0, 0, 0)
        attrs = attr(0x10, zero_si) + attr(0x30, fn_value("zeroed.txt"))
        records, _ = walk(build_record(attrs=attrs))
        self.assertEqual(records[0]["timestomp_flags"], ["si_timestamps_zero"])

    def test_fixup_restores_sector_end_bytes(self):
        value = b"A" * 600
        rec = build_record(attrs=attr(0x10, si_value()) + attr(0x30, fn_value("big.bin")) + attr(0x80, value))
        self.assertEqual(struct.unpack_from("<H", rec, 510)[0], 0x00AB)
        warnings = []
        fixed = mft.apply_fixup(rec, 0, 1024, warnings)
        self.assertEqual(warnings, [])
        self.assertEqual(fixed[510:512], b"AA")
        records, _ = walk(rec)
        self.assertEqual(records[0]["data"][0]["size"], 600)
        self.assertEqual(records[0]["warnings"], [])

    def test_usa_mismatch_is_reported(self):
        rec = build_record(attrs=SIMPLE_ATTRS, corrupt_fixup=True)
        warnings = []
        mft.apply_fixup(rec, 0, 1024, warnings)
        self.assertIn("usa_mismatch", warnings)
        records, stats = walk(rec)
        self.assertIn("usa_mismatch", records[0]["warnings"])
        self.assertEqual(stats.usa_mismatches, 1)
        rep = report_for(rec)
        self.assertIn("usa_mismatch_records_present", rep["warnings"])

    def test_attribute_walk_abort(self):
        attrs = attr(0x10, si_value()) + attr(0x30, fn_value("cut.off"), override_length=0xFFFF)
        records, _ = walk(build_record(attrs=attrs))
        r = records[0]
        self.assertIn("attribute_walk_aborted", r["warnings"])
        self.assertIsNotNone(r.get("standard_information"))
        self.assertEqual(r["file_names"], [])
        self.assertIsNone(r["primary_name"])

    def test_zero_and_no_magic_regions_merge(self):
        rec_in = build_record(index=0, attrs=SIMPLE_ATTRS)
        rec_out = build_record(index=3, attrs=SIMPLE_ATTRS)
        data = rec_in + b"\x00" * 2048 + b"\xff" * 1024 + rec_out
        records, stats = walk(data)
        self.assertEqual([r["record_number"] for r in records], [0, 4])
        self.assertEqual(stats.zero_slots, 2)
        self.assertEqual(stats.no_magic_slots, 1)
        self.assertEqual(
            stats.skipped_regions,
            [
                {"offset": 1024, "length": 2048, "reason": "zero_fill"},
                {"offset": 3072, "length": 1024, "reason": "no_file_magic"},
            ],
        )
        rep = report_for(data)
        self.assertIn("zero_slots_present", rep["warnings"])
        self.assertIn("no_magic_slots_present", rep["warnings"])

    def test_truncated_tail(self):
        rec = build_record(index=0, attrs=SIMPLE_ATTRS)
        data = rec + b"\x00" * 300
        records, stats = walk(data)
        self.assertEqual(len(records), 1)
        self.assertEqual(
            stats.skipped_regions[-1],
            {"offset": 1024, "length": 300, "reason": "truncated_tail"},
        )
        rep = report_for(data)
        self.assertIn("truncated_tail_present", rep["warnings"])

    def test_extension_record(self):
        attrs = attr(0x10, si_value()) + attr(0x30, fn_value("ext.bin"))
        rec = build_record(index=77, flags=0x1 | 0x4, base_ref=0x0005000000000001, attrs=attrs)
        records, stats = walk(rec)
        r = records[0]
        self.assertTrue(r["is_extension"])
        self.assertEqual(r["base_record_reference"], "0x0005000000000001")
        self.assertEqual(stats.extensions, 1)

    def test_attribute_list_resident(self):
        entries = [(0x80, 0, 0x000A000000000005, 3)]
        attrs = attr(0x10, si_value()) + attr(0x30, fn_value("big.dat", real=5000000)) + attr_list(entries)
        records, _ = walk(build_record(attrs=attrs))
        r = records[0]
        self.assertTrue(r["has_attribute_list"])
        self.assertEqual(
            r["attribute_list"],
            [
                {
                    "type": 0x80,
                    "type_name": "DATA",
                    "starting_vcn": 0,
                    "record_number": 5,
                    "record_sequence": 10,
                    "base_reference": "0x000a000000000005",
                    "attribute_id": 3,
                    "name": None,
                }
            ],
        )

    def test_attribute_list_stale_reference_is_skipped(self):
        base_attrs = (
            attr(0x10, si_value())
            + attr(0x30, fn_value("current.bin", real=64))
            + attr_list([(0x30, 0, ((9 << 48) | 1), 2)])
        )
        data = build_record(index=0, attrs=base_attrs) + build_record(
            index=1, attrs=attr(0x30, fn_value("reused.bin", namespace=1, real=999), aid=2), seq=1
        )
        records, stats = walk(data)
        r = records[0]
        self.assertIn("attribute_list_entry_stale", r["warnings"])
        self.assertEqual([fn["name"] for fn in r["file_names"]], ["current.bin"])
        self.assertEqual(r["primary_name"], "current.bin")
        self.assertEqual(r["size"], 64)
        self.assertEqual(stats.stale_attribute_list_entries, 1)

    def test_attribute_list_merges_extension_file_name(self):
        base_attrs = (
            attr(0x10, si_value())
            + attr(0x30, fn_value("PROGRA~3", namespace=2, real=0), aid=2)
            + attr_list([(0x30, 0, 0, 2), (0x30, 0, (1 << 48) | 1, 3)])
        )
        ext_attrs = attr(0x30, fn_value("ProgramData", namespace=1, real=0), aid=3)
        data = build_record(index=0, attrs=base_attrs, next_id=4) + build_record(
            index=1, attrs=ext_attrs, base_ref=(1 << 48) | 0
        )
        records, stats = walk(data)
        r = records[0]
        self.assertEqual(sorted(fn["name"] for fn in r["file_names"]), ["PROGRA~3", "ProgramData"])
        self.assertEqual(r["primary_name"], "ProgramData")
        self.assertEqual(stats.extension_attributes, 1)

    def test_attribute_list_merges_extension_data_fragment(self):
        base_attrs = (
            attr(0x10, si_value())
            + attr_data_nonresident(bytes([0x11, 1, 16, 0]), 8192, 8192, 8192, aid=4)
            + attr_list([(0x80, 0, 0, 4), (0x80, 1, (1 << 48) | 1, 5)])
        )
        ext_attrs = attr_data_nonresident(bytes([0x11, 1, 32, 0]), 8192, 8192, 8192, aid=5, start_vcn=1, last_vcn=1)
        data = build_record(index=0, attrs=base_attrs) + build_record(index=1, attrs=ext_attrs, base_ref=(1 << 48) | 0)
        records, stats = walk(data)
        r = records[0]
        self.assertEqual(len(r["data"]), 2)
        merged = r["data"][1]
        self.assertEqual(merged["fragment_record"], 1)
        self.assertEqual(merged["starting_vcn"], 1)
        self.assertEqual(merged["size"], 8192)
        self.assertEqual(r["size"], 8192)
        self.assertEqual(stats.extension_attributes, 1)

    def test_attribute_list_extension_outside_capture_warns(self):
        base_attrs = (
            attr(0x10, si_value())
            + attr(0x30, fn_value("SHORT.TXT", namespace=2))
            + attr_list([(0x30, 0, (1 << 48) | 40, 2)])
        )
        records, stats = walk(build_record(index=0, attrs=base_attrs))
        r = records[0]
        self.assertIn("attribute_list_extension_outside_capture", r["warnings"])
        self.assertEqual(r["primary_name"], "SHORT.TXT")
        self.assertEqual(stats.extension_attributes, 0)

    def test_nonresident_data_runs(self):
        runs = bytes.fromhex("2118345600")
        attrs = attr(0x10, si_value()) + attr(0x30, fn_value("vid.mp4", real=90000))
        attrs += attr_data_nonresident(runs, alloc=98304, real=90000, init=90000, last_vcn=0x17)
        records, _ = walk(build_record(attrs=attrs))
        data = records[0]["data"][0]
        self.assertTrue(data["non_resident"])
        self.assertEqual(data["size"], 90000)
        self.assertEqual(data["allocated_size"], 98304)
        self.assertEqual(data["run_count"], 1)
        self.assertEqual(data["first_lcn"], 0x5634)
        self.assertFalse(data["fragmented"])

    def test_decode_runs_backwards_lcn(self):
        runs, warning = mft.decode_runs(bytes.fromhex("113060211000011120E000"), 0)
        self.assertIsNone(warning)
        self.assertEqual(
            [(run["lcn"], run["clusters"]) for run in runs],
            [(0x60, 0x30), (0x160, 0x10), (0x140, 0x20)],
        )

    def test_detect_record_size(self):
        data1024 = b"".join(build_record(index=i, attrs=SIMPLE_ATTRS) for i in range(4))
        size, info = mft.detect_record_size(data1024)
        self.assertEqual(size, 1024)
        self.assertEqual(info["sampled_slots"], 4)
        data4096 = b"".join(build_record(index=i, attrs=SIMPLE_ATTRS, record_size=4096) for i in range(4))
        size, _ = mft.detect_record_size(data4096)
        self.assertEqual(size, 4096)
        size, info = mft.detect_record_size(b"\x42" * 4096)
        self.assertIsNone(size)
        self.assertEqual(info, {})

    def test_record_matches_filters(self):
        records, _ = walk(build_record(attrs=SIMPLE_ATTRS))
        r = records[0]
        self.assertTrue(mft.record_matches(r, in_use=True))
        self.assertFalse(mft.record_matches(r, deleted=True))
        self.assertTrue(mft.record_matches(r, name_contains="HELLO"))
        self.assertFalse(mft.record_matches(r, name_contains="nope"))
        self.assertTrue(mft.record_matches(r, min_size=5))
        self.assertFalse(mft.record_matches(r, min_size=6))

    def test_empty_input_report(self):
        stats = mft.Stats()
        self.assertEqual(list(mft.iter_records(b"", None, stats)), [])
        rep = mft.build_report(stats, input_path="empty", input_size=0, record_size=None)
        self.assertIn("empty_input", rep["warnings"])


class MftParseCliTests(unittest.TestCase):
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

    def write_capture(self, data, name="capture.mft"):
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

    def test_cli_jsonl_and_report(self):
        deleted = build_record(
            index=42,
            flags=0,
            seq=3,
            attrs=attr(0x10, si_value()) + attr(0x30, fn_value("ghost.sys", real=5)),
        )
        capture = self.write_capture(build_record(index=0, attrs=SIMPLE_ATTRS) + deleted)
        out = os.path.join(self.tmp, "out.jsonl")
        rep = os.path.join(self.tmp, "report.json")
        p = self.run_cli(capture, "--jsonl", out, "--report", rep, "--quiet")
        self.assertEqual(p.returncode, 0, p.stderr)
        lines = self.read_jsonl(out)
        self.assertEqual([line["primary_name"] for line in lines], ["hello.txt", "ghost.sys"])
        report = self.read_report(rep)
        self.assertEqual(report["record_size"], 1024)
        self.assertEqual(report["counts"]["parsed"], 2)
        self.assertEqual(report["counts"]["in_use"], 1)
        self.assertEqual(report["counts"]["deleted"], 1)
        self.assertIn("record_size_auto_detected", report["warnings"])
        self.assertIn("note", report["timestomp"])

    def test_cli_deleted_and_name_filters(self):
        deleted = build_record(
            index=42,
            flags=0,
            attrs=attr(0x10, si_value()) + attr(0x30, fn_value("ghost.sys", real=5)),
        )
        capture = self.write_capture(build_record(index=0, attrs=SIMPLE_ATTRS) + deleted)
        out = os.path.join(self.tmp, "out.jsonl")
        p = self.run_cli(capture, "--jsonl", out, "--deleted", "--quiet")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual([line["primary_name"] for line in self.read_jsonl(out)], ["ghost.sys"])
        out2 = os.path.join(self.tmp, "out2.jsonl")
        p2 = self.run_cli(capture, "--jsonl", out2, "--name-contains", "GHOST", "--quiet")
        self.assertEqual(p2.returncode, 0, p2.stderr)
        self.assertEqual([line["primary_name"] for line in self.read_jsonl(out2)], ["ghost.sys"])

    def test_cli_min_size_and_limit(self):
        small = build_record(index=0, attrs=attr(0x10, si_value()) + attr(0x30, fn_value("small.txt", real=5)))
        big = build_record(index=1, attrs=attr(0x10, si_value()) + attr(0x30, fn_value("big.iso", real=600000)))
        capture = self.write_capture(small + big)
        out = os.path.join(self.tmp, "out.jsonl")
        p = self.run_cli(capture, "--jsonl", out, "--min-size", "1000", "--quiet")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual([line["primary_name"] for line in self.read_jsonl(out)], ["big.iso"])
        out2 = os.path.join(self.tmp, "out2.jsonl")
        rep = os.path.join(self.tmp, "report.json")
        p2 = self.run_cli(capture, "--jsonl", out2, "--report", rep, "--limit", "1", "--quiet")
        self.assertEqual(p2.returncode, 0, p2.stderr)
        self.assertEqual(len(self.read_jsonl(out2)), 1)
        report = self.read_report(rep)
        self.assertIn("stopped_early_by_limit", report["warnings"])

    def test_cli_raw_mode(self):
        rec = build_record(index=0, attrs=SIMPLE_ATTRS)
        capture = self.write_capture(rec)
        out = os.path.join(self.tmp, "out.jsonl")
        p = self.run_cli(capture, "--jsonl", out, "--raw", "--quiet")
        self.assertEqual(p.returncode, 0, p.stderr)
        lines = self.read_jsonl(out)
        self.assertEqual(bytes.fromhex(lines[0]["raw_hex"]), rec)

    def test_cli_explicit_record_size(self):
        capture = self.write_capture(build_record(index=0, attrs=SIMPLE_ATTRS))
        rep = os.path.join(self.tmp, "report.json")
        p = self.run_cli(capture, "--report", rep, "--record-size", "1024", "--quiet")
        self.assertEqual(p.returncode, 0, p.stderr)
        report = self.read_report(rep)
        self.assertNotIn("record_size_auto_detected", report["warnings"])

    def test_cli_empty_file(self):
        capture = self.write_capture(b"")
        rep = os.path.join(self.tmp, "report.json")
        p = self.run_cli(capture, "--report", rep, "--quiet")
        self.assertEqual(p.returncode, 0, p.stderr)
        report = self.read_report(rep)
        self.assertIn("empty_input", report["warnings"])
        self.assertIsNone(report["record_size"])

    def test_cli_usage_and_fatal_errors(self):
        capture = self.write_capture(build_record(index=0, attrs=SIMPLE_ATTRS))
        self.assertEqual(self.run_cli(capture, "--in-use", "--deleted").returncode, 2)
        p = self.run_cli(os.path.join(self.tmp, "missing.mft"))
        self.assertEqual(p.returncode, 1)
        self.assertIn("fatal", p.stderr)
        garbage = self.write_capture(b"\x42" * 4096, name="garbage.mft")
        p2 = self.run_cli(garbage)
        self.assertEqual(p2.returncode, 1)
        self.assertIn("cannot detect", p2.stderr)


if __name__ == "__main__":
    unittest.main()
