#!/usr/bin/env python3
"""Tests for tools/pf_parse.py.

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

SKILL_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
TOOLS_DIR = os.path.join(SKILL_ROOT, "tools")
if TOOLS_DIR not in sys.path:
    sys.path.insert(0, TOOLS_DIR)

import pf_parse as pf

PARSER = os.path.join(TOOLS_DIR, "pf_parse.py")
# ---------------------------------------------------------------------------
# Synthetic XPRESS-Huffman encoder (uniform 9-bit code table, table byte 0x99)
# ---------------------------------------------------------------------------


def _encode_block(events, table_byte=0x99, prefilled_table=None):
    """Encode one XPRESS-Huffman block: 256-byte table + bit stream.

    events: list of tuples in decoder read order:
      ("sym", symbol)       -> 9-bit code
      ("ext8", value)       -> byte-aligned byte
      ("ext16", value)      -> byte-aligned u16 LE
      ("off", value, nbits) -> raw offset bits (nbits, MSB first)
    """
    bits = []
    for event in events:
        if event[0] == "sym":
            for i in range(8, -1, -1):
                bits.append((event[1] >> i) & 1)
        elif event[0] == "off":
            _, value, n = event
            for i in range(n - 1, -1, -1):
                bits.append((value >> i) & 1)
    bit_index = 0

    def take_word():
        nonlocal bit_index
        word = 0
        for _ in range(16):
            if bit_index < len(bits):
                word = (word << 1) | bits[bit_index]
                bit_index += 1
            else:
                word = word << 1
        return word

    out = bytearray(prefilled_table if prefilled_table is not None else bytes([table_byte]) * 256)
    out += take_word().to_bytes(2, "little")
    out += take_word().to_bytes(2, "little")
    avail = 32

    def maybe_refill():
        nonlocal avail
        if avail < 16:
            out.extend(take_word().to_bytes(2, "little"))
            avail += 16

    for event in events:
        if event[0] == "sym":
            avail -= 9
            maybe_refill()
        elif event[0] == "ext8":
            out.append(event[1])
        elif event[0] == "ext16":
            out += event[1].to_bytes(2, "little")
        elif event[0] == "off":
            avail -= event[2]
            maybe_refill()
    return bytes(out)


def _literal_block(data):
    return _encode_block([("sym", b) for b in data])


def parse_bytes(name, raw):
    container, payload, declared = pf.unwrap_container(raw)
    return pf.build_record(name, raw, container, declared, payload, [])


def synthetic_v30_prefetch(executable="SYNTH.EXE", hash_value=0x1234ABCD):
    """Build a minimal synthetic v30 SCCA file without host-specific data."""
    payload = bytearray(0x180)
    struct.pack_into("<I", payload, 0, 30)
    payload[4:8] = b"SCCA"
    struct.pack_into("<I", payload, 12, len(payload))
    name = executable.encode("utf-16-le")
    payload[16:16 + len(name)] = name
    struct.pack_into("<I", payload, 76, hash_value)
    struct.pack_into("<9I", payload, pf.FILE_INFO_OFFSET,
                     pf.V30_VARIANT2_METRICS_OFFSET, 0,
                     0x150, 0, 0x150, 0, 0x150, 0, 0)
    struct.pack_into("<Q", payload, pf.FILE_INFO_OFFSET + 44, 134000000000000000)
    struct.pack_into("<I", payload, pf.FILE_INFO_OFFSET + 116, 1)
    struct.pack_into("<II", payload, pf.FILE_INFO_OFFSET + 128, 0x150, 0)
    return bytes(payload)


# ---------------------------------------------------------------------------
# XPRESS-Huffman decoder unit tests
# ---------------------------------------------------------------------------


class XpressHuffmanSyntheticTests(unittest.TestCase):
    def test_literals_round_trip(self):
        block = _literal_block(b"HELLO WORLD")
        self.assertEqual(pf.decompress_xpress_huffman(block, 11), b"HELLO WORLD")

    def test_overlapping_match(self):
        # A B <match len=4 offset=2> -> ABABAB (one-byte-at-a-time overlap copy)
        sym_match = 256 + 1 + (1 << 4)
        block = _encode_block([("sym", ord("A")), ("sym", ord("B")), ("sym", sym_match), ("off", 0, 1)])
        self.assertEqual(pf.decompress_xpress_huffman(block, 6), b"ABABAB")

    def test_symbol_256_is_a_match_not_end_of_stream(self):
        # Regression: symbol 256 = length nibble 0, offset bits 0 -> copy 3 bytes
        # from offset 1 ("repeat last byte 3x"). Old code treated it as EOS.
        block = _encode_block([("sym", ord("A")), ("sym", ord("B")), ("sym", 256)])
        self.assertEqual(pf.decompress_xpress_huffman(block, 5), b"ABBBB")

    def test_extended_length_via_255_and_u16(self):
        # "A" + match(len nibble 15, offset 1) with ext 255 + u16 65532 -> 65535 bytes
        block = _encode_block([("sym", ord("A")), ("sym", 271), ("ext8", 255), ("ext16", 65532)])
        self.assertEqual(pf.decompress_xpress_huffman(block, 65536), b"A" * 65536)

    def test_invalid_extended_length_rejected(self):
        # u16 value below 15 after the 255 escape is invalid per MS-XCA
        block = _encode_block([("sym", ord("A")), ("sym", 271), ("ext8", 255), ("ext16", 3)])
        with self.assertRaises(pf.XpressError):
            pf.decompress_xpress_huffman(block, 16)

    def test_two_blocks_with_64k_boundary(self):
        block1 = _encode_block([("sym", ord("A")), ("sym", 271), ("ext8", 255), ("ext16", 65532)])
        block2 = _literal_block(b"B" * 100)
        out = pf.decompress_xpress_huffman(block1 + block2, 65636)
        self.assertEqual(out, b"A" * 65536 + b"B" * 100)

    def test_match_overrun_rejected(self):
        # AB + len4/off2 match needs 6 bytes; asking for 3 must not silently succeed
        sym_match = 256 + 1 + (1 << 4)
        block = _encode_block([("sym", ord("A")), ("sym", ord("B")), ("sym", sym_match), ("off", 0, 1)])
        with self.assertRaises(pf.XpressError):
            pf.decompress_xpress_huffman(block, 3)

    def test_incomplete_huffman_table_rejected(self):
        with self.assertRaises(pf.XpressError):
            pf.build_huffman_table(b"\x00" * 256)


# ---------------------------------------------------------------------------
# Container unwrapping
# ---------------------------------------------------------------------------


class ContainerTests(unittest.TestCase):
    def test_mam_round_trip(self):
        payload = bytes(range(200))
        block = _literal_block(payload)
        raw = b"MAM\x04" + len(payload).to_bytes(4, "little") + block
        container, out, declared = pf.unwrap_container(raw)
        self.assertEqual(container, "mam_xpress_huffman")
        self.assertEqual(declared, 200)
        self.assertEqual(out, payload)

    def test_mam_0x84_signature_byte_accepted(self):
        payload = b"abc"
        raw = b"MAM\x84" + (3).to_bytes(4, "little") + _literal_block(payload)
        container, out, declared = pf.unwrap_container(raw)
        self.assertEqual(container, "mam_xpress_huffman")
        self.assertEqual(out, payload)

    def test_raw_scca_passthrough(self):
        raw = b"\x1e\x00\x00\x00SCCA" + b"\x00" * 10
        container, out, declared = pf.unwrap_container(raw)
        self.assertEqual(container, "raw_scca")
        self.assertEqual(out, raw)
        self.assertIsNone(declared)


# ---------------------------------------------------------------------------
# Honest failure modes
# ---------------------------------------------------------------------------


class RecordErrorTests(unittest.TestCase):
    def test_empty_file_rejected(self):
        with self.assertRaises(pf.PfParseError) as ctx:
            parse_bytes("X.EXE-00000000.pf", b"")
        self.assertIn("empty file", str(ctx.exception))

    def test_zero_filled_file_rejected(self):
        with self.assertRaises(pf.PfParseError) as ctx:
            parse_bytes("X.EXE-00000000.pf", b"\x00" * 4096)
        self.assertIn("0x00", str(ctx.exception))

    def test_non_prefetch_garbage_rejected(self):
        with self.assertRaises(pf.PfParseError) as ctx:
            parse_bytes("X.EXE-00000000.pf", b"not a prefetch file at all...." * 4)
        self.assertIn("version", str(ctx.exception))


# ---------------------------------------------------------------------------
# Synthetic v30 record tests
# ---------------------------------------------------------------------------


class PfSyntheticRecordTests(unittest.TestCase):
    def test_header_identity_and_run_time(self):
        raw = synthetic_v30_prefetch()
        rec = parse_bytes("SYNTH.EXE-1234ABCD.pf", raw)
        self.assertEqual(rec["format_version"], 30)
        self.assertEqual(rec["signature"], "SCCA")
        self.assertEqual(rec["file_information"]["layout_variant"], 2)
        self.assertEqual(rec["executable"], "SYNTH.EXE")
        self.assertEqual(rec["prefetch_hash"], "1234ABCD")
        self.assertTrue(rec["hash_matches_filename"])
        self.assertTrue(rec["exe_matches_filename"])
        self.assertEqual(rec["run_count"], 1)
        self.assertEqual(rec["warnings"], [])


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


class PfParseCliTests(unittest.TestCase):
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

    def read_jsonl(self, path):
        with open(path, encoding="utf-8") as fh:
            return [json.loads(line) for line in fh if line.strip()]

    def read_report(self, path):
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)

    def test_synthetic_files_jsonl_and_report(self):
        out = os.path.join(self.tmp, "out.jsonl")
        rep = os.path.join(self.tmp, "report.json")
        paths = []
        for name, exe in (("SYNTH.EXE-1234ABCD.pf", "SYNTH.EXE"),
                          ("DEMO.EXE-87654321.pf", "DEMO.EXE")):
            path = os.path.join(self.tmp, name)
            with open(path, "wb") as fh:
                fh.write(synthetic_v30_prefetch(exe, 0x1234ABCD if exe == "SYNTH.EXE" else 0x87654321))
            paths.append(path)
        p = self.run_cli(*paths, "--jsonl", out, "--report", rep, "--quiet")
        self.assertEqual(p.returncode, 0, p.stderr)
        lines = self.read_jsonl(out)
        self.assertEqual(len(lines), 2)
        report = self.read_report(rep)
        self.assertEqual(report["tool"], "pf_parse")
        self.assertEqual(report["schema_version"], 1)
        self.assertEqual(report["mode"], "offline")
        self.assertEqual(report["counts"]["files"], 2)
        self.assertEqual(report["counts"]["parsed"], 2)
        self.assertEqual(report["counts"]["failed"], 0)
        self.assertEqual(report["counts"]["by_version"], {"30": 2})
        self.assertEqual(
            report["observations"]["hash_matches_filename"], {"true": 2, "false": 0, "unknown": 0}
        )

    def test_zero_filled_file_reports_honest_error(self):
        path = os.path.join(self.tmp, "ZERO.EXE-DEADBEEF.pf")
        with open(path, "wb") as fh:
            fh.write(b"\x00" * 128)
        out = os.path.join(self.tmp, "out.jsonl")
        rep = os.path.join(self.tmp, "report.json")
        p = self.run_cli(path, "--jsonl", out, "--report", rep, "--quiet")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(self.read_jsonl(out), [])
        report = self.read_report(rep)
        self.assertEqual(report["counts"]["failed"], 1)
        self.assertIn("0x00", report["errors"][0]["error"])
        self.assertIn("files_failed_to_parse", report["warnings"])

    def test_directory_input_with_filters(self):
        sample_dir = os.path.join(self.tmp, "samples")
        os.makedirs(sample_dir)
        for name, exe, hash_value in (("SYNTH.EXE-1234ABCD.pf", "SYNTH.EXE", 0x1234ABCD),
                                      ("FILTERDEMO.EXE-87654321.pf", "FILTERDEMO.EXE", 0x87654321)):
            with open(os.path.join(sample_dir, name), "wb") as fh:
                fh.write(synthetic_v30_prefetch(exe, hash_value))
        out = os.path.join(self.tmp, "out.jsonl")
        rep = os.path.join(self.tmp, "report.json")
        p = self.run_cli(
            sample_dir, "--name-contains", "filterdemo", "--min-runs", "1",
            "--jsonl", out, "--report", rep, "--quiet",
        )
        self.assertEqual(p.returncode, 0, p.stderr)
        lines = self.read_jsonl(out)
        self.assertEqual([line["filename"] for line in lines], ["FILTERDEMO.EXE-87654321.pf"])
        report = self.read_report(rep)
        self.assertEqual(report["counts"]["files"], 2)
        self.assertEqual(report["counts"]["emitted"], 1)
        self.assertEqual(report["filters"], {"min_runs": 1, "name_contains": "filterdemo", "limit": None})


if __name__ == "__main__":
    unittest.main()
