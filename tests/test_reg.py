#!/usr/bin/env python3
"""Tests for tools/reg_parse.py.

Includes a minimal synthetic regf writer (format 1.5) so that container
parsing, big-data (db) values and artifact extractors can be tested without
committing real registry hives.

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

import reg_parse as rp

PARSER = os.path.join(TOOLS_DIR, "reg_parse.py")

FT_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


def ft(dt):
    return int((dt - FT_EPOCH).total_seconds() * 10 ** 7)


T0 = datetime(2020, 5, 1, 12, 0, 0, tzinfo=timezone.utc)
FT0 = ft(T0)
T_RUN = datetime(2026, 1, 2, 3, 4, 5, 678000, tzinfo=timezone.utc)
FT_RUN = ft(T_RUN)


def iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


# ---------------------------------------------------------------------------
# Minimal regf writer (format 1.5)
# ---------------------------------------------------------------------------

class HiveBuilder:
    def __init__(self):
        self.cells = []  # [offset, bytearray payload]
        self.offset = 32  # after the 32-byte hbin header

    def add(self, payload):
        off = self.offset
        total = ((4 + len(payload)) + 7) // 8 * 8
        self.offset += total
        self.cells.append([off, bytearray(payload)])
        return off

    def patch(self, off, pos, data):
        for cell in self.cells:
            if cell[0] == off:
                cell[1][pos:pos + len(data)] = data
                return
        raise KeyError(off)

    def assemble(self, root_offset, seq=(1, 1), lwt=FT0, file_type=0, major=1, minor=5):
        blob = bytearray()
        for _off, payload in self.cells:
            total = ((4 + len(payload)) + 7) // 8 * 8
            blob += struct.pack("<i", -total) + bytes(payload) + b"\x00" * (total - 4 - len(payload))
        hbin_size = ((32 + len(blob)) // 4096 + 1) * 4096
        remainder = hbin_size - 32 - len(blob)
        while remainder < 8:
            hbin_size += 4096
            remainder += 4096
        blob += struct.pack("<i", remainder) + b"\x00" * (remainder - 4)  # trailing free cell
        hbin = b"hbin" + struct.pack("<II", 0, hbin_size) + b"\x00" * 20 + bytes(blob)
        header = bytearray(4096)
        header[0:4] = b"regf"
        struct.pack_into("<I", header, 4, seq[0])
        struct.pack_into("<I", header, 8, seq[1])
        struct.pack_into("<Q", header, 12, lwt)
        struct.pack_into("<I", header, 20, major)
        struct.pack_into("<I", header, 24, minor)
        struct.pack_into("<I", header, 28, file_type)
        struct.pack_into("<I", header, 36, root_offset)
        struct.pack_into("<I", header, 40, hbin_size)
        checksum = 0
        for i in range(0, 508, 4):
            checksum ^= struct.unpack_from("<I", header, i)[0]
        struct.pack_into("<I", header, 508, checksum)
        return bytes(header) + hbin


def add_value(b, name, vtype, data, mode="auto", ascii_name=True):
    name_bytes = name.encode("ascii") if ascii_name else name.encode("utf-16le")
    vflags = 0x1 if ascii_name else 0x0

    def make_vk(size_field, data_off):
        vk = bytearray(20 + len(name_bytes))
        vk[0:2] = b"vk"
        struct.pack_into("<H", vk, 2, len(name_bytes))
        struct.pack_into("<I", vk, 4, size_field)
        if data_off is not None:
            struct.pack_into("<I", vk, 8, data_off)
        struct.pack_into("<I", vk, 12, vtype)
        struct.pack_into("<H", vk, 16, vflags)
        vk[20:] = name_bytes
        return b.add(bytes(vk))

    if mode == "inline" or (mode == "auto" and len(data) <= 4):
        vk = bytearray(20 + len(name_bytes))
        vk[0:2] = b"vk"
        struct.pack_into("<H", vk, 2, len(name_bytes))
        struct.pack_into("<I", vk, 4, 0x80000000 | len(data))
        vk[8:8 + len(data)] = data
        struct.pack_into("<I", vk, 12, vtype)
        struct.pack_into("<H", vk, 16, vflags)
        vk[20:] = name_bytes
        return b.add(bytes(vk))
    if mode == "big" or (mode == "auto" and len(data) > rp.BIG_DATA_THRESHOLD):
        chunks = [data[i:i + 0x3FD8] for i in range(0, len(data), 0x3FD8)]
        seg_offs = [b.add(c) for c in chunks]
        seg_list = b.add(b"".join(struct.pack("<I", o) for o in seg_offs))
        db = b"db" + struct.pack("<H", len(chunks)) + struct.pack("<I", seg_list)
        return make_vk(len(data), b.add(db))
    return make_vk(len(data), b.add(data))


def add_nk_cell(b, name, n_sub, sub_list_off, n_val, val_list_off, lwt=FT0, ascii_name=True):
    name_bytes = name.encode("ascii") if ascii_name else name.encode("utf-16le")
    payload = bytearray(76 + len(name_bytes))
    payload[0:2] = b"nk"
    struct.pack_into("<H", payload, 2, 0x20 if ascii_name else 0)
    struct.pack_into("<Q", payload, 4, lwt)
    struct.pack_into("<I", payload, 16, 0xFFFFFFFF)
    struct.pack_into("<I", payload, 20, n_sub)
    struct.pack_into("<I", payload, 28, sub_list_off)
    struct.pack_into("<I", payload, 36, n_val)
    struct.pack_into("<I", payload, 40, val_list_off)
    struct.pack_into("<I", payload, 44, 0xFFFFFFFF)
    struct.pack_into("<H", payload, 72, len(name_bytes))
    payload[76:] = name_bytes
    return b.add(bytes(payload))


def build_node(b, name, val_offsets, sub_offsets, lwt=FT0, list_kind="lf", ascii_name=True):
    vals_list_off = 0xFFFFFFFF
    if val_offsets:
        vals_list_off = b.add(b"".join(struct.pack("<I", o) for o in val_offsets))
    sub_list_off = 0xFFFFFFFF
    if sub_offsets:
        if list_kind == "li":
            payload = b"li" + struct.pack("<H", len(sub_offsets)) + b"".join(
                struct.pack("<I", o) for o in sub_offsets
            )
        else:
            payload = list_kind.encode("ascii") + struct.pack("<H", len(sub_offsets)) + b"".join(
                struct.pack("<II", o, 0) for o in sub_offsets
            )
        sub_list_off = b.add(payload)
    return add_nk_cell(b, name, len(sub_offsets), sub_list_off, len(val_offsets), vals_list_off, lwt, ascii_name)


def make_hive(spec, seq=(1, 1), lwt=FT0, file_type=0, major=1, minor=5):
    b = HiveBuilder()

    def rec(node):
        subs = [rec(c) for c in node.get("subkeys", [])]
        vals = [
            add_value(
                b,
                v["name"],
                v.get("type", 1),
                v["data"],
                v.get("mode", "auto"),
                v.get("ascii_name", True),
            )
            for v in node.get("values", [])
        ]
        return build_node(
            b,
            node["name"],
            vals,
            subs,
            node.get("lwt", lwt),
            node.get("list_kind", "lf"),
            node.get("ascii_name", True),
        )

    root_off = rec(spec)
    return b.assemble(root_off, seq=seq, lwt=lwt, file_type=file_type, major=major, minor=minor)


def write_tmp(data, suffix=".hive"):
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=suffix)
    tmp.write(data)
    tmp.close()
    return tmp.name


def u16le(text):
    return text.encode("utf-16le") + b"\x00\x00"


def multi_sz(strings):
    return "\x00".join(strings).encode("utf-16le") + b"\x00\x00\x00\x00"


# ---------------------------------------------------------------------------
# Container-level tests
# ---------------------------------------------------------------------------

class HiveCoreTests(unittest.TestCase):
    def setUp(self):
        spec = {
            "name": "ROOT",
            "values": [
                {"name": "InlineDword", "type": 4, "data": struct.pack("<I", 0xDEADBEEF)},
                {"name": "InlineSmallStr", "type": 1, "data": "hi".encode("utf-16le")},
                {"name": "ResidentStr", "type": 1, "data": u16le("Hello Resident")},
                {"name": "MultiSz", "type": 7, "data": multi_sz(["a", "", "b"])},
                {"name": "Qword", "type": 11, "data": struct.pack("<Q", 2 ** 40 + 7)},
            ],
            "subkeys": [
                {"name": "ChildOne", "values": [{"name": "V", "type": 4, "data": struct.pack("<I", 1)}]},
                {"name": "ChildTwo"},
            ],
        }
        self.data = make_hive(spec)
        self.hive = rp.Hive(self.data, "synthetic.hive")

    def test_header_fields(self):
        self.assertEqual(self.hive.version, "1.5")
        self.assertEqual(self.hive.root()["name"], "ROOT")
        self.assertEqual(self.hive.last_written, iso(T0))

    def test_find_key_and_values(self):
        root = self.hive.root()
        names = [v["name"] for v in self.hive.values(root)]
        self.assertIn("InlineDword", names)
        child = self.hive.find_key("ChildOne")
        self.assertIsNotNone(child)
        vk, data = self.hive.get_value(child, "V")
        self.assertEqual(rp.u32(data, 0), 1)
        self.assertIsNone(self.hive.find_key("Nope\\Child"))

    def test_inline_and_resident_roundtrip(self):
        root = self.hive.root()
        vk, data = self.hive.get_value(root, "InlineDword")
        self.assertTrue(vk["inline"])
        self.assertEqual(rp.u32(data, 0), 0xDEADBEEF)
        vk, data = self.hive.get_value(root, "ResidentStr")
        self.assertFalse(vk["inline"])
        self.assertEqual(rp.decode_reg_string(data), "Hello Resident")
        vk, data = self.hive.get_value(root, "Qword")
        self.assertEqual(rp.u64(data, 0), 2 ** 40 + 7)

    def test_multisz_interior_empty_preserved(self):
        root = self.hive.root()
        vk, data = self.hive.get_value(root, "MultiSz")
        self.assertEqual(rp.decode_multi_string(data), ["a", "", "b"])

    def test_subkey_list_children_and_duplicates_are_stable(self):
        root = self.hive.root()
        children = sorted(k["name"] for k in self.hive.subkeys(root))
        self.assertEqual(children, ["ChildOne", "ChildTwo"])

    def test_li_and_ri_lists(self):
        b = HiveBuilder()
        c1 = add_nk_cell(b, "K1", 0, 0xFFFFFFFF, 0, 0xFFFFFFFF)
        c2 = add_nk_cell(b, "K2", 0, 0xFFFFFFFF, 0, 0xFFFFFFFF)
        li_off = b.add(b"li" + struct.pack("<H", 2) + struct.pack("<II", c1, c2))
        ri_off = b.add(b"ri" + struct.pack("<H", 1) + struct.pack("<I", li_off))
        root_off = add_nk_cell(b, "ROOT", 2, ri_off, 0, 0xFFFFFFFF)
        data = b.assemble(root_off)
        hive = rp.Hive(data, "ri.hive")
        names = sorted(k["name"] for k in hive.subkeys(hive.root()))
        self.assertEqual(names, ["K1", "K2"])

    def test_dirty_hive_warning(self):
        data = make_hive({"name": "ROOT"}, seq=(7, 6))
        hive = rp.Hive(data, "dirty.hive")
        self.assertTrue(any("dirty" in w for w in hive.warnings))

    def test_big_data_roundtrip(self):
        payload = bytes(range(256)) * 157  # 40192 bytes, above the 16344 threshold
        data = make_hive({"name": "ROOT", "values": [{"name": "Blob", "type": 3, "data": payload}]})
        hive = rp.Hive(data, "big.hive")
        vk, out = hive.get_value(hive.root(), "Blob")
        self.assertEqual(len(out), len(payload))
        self.assertEqual(out, payload)
        self.assertGreater(vk["size"], rp.BIG_DATA_THRESHOLD)

    def test_big_data_declared_without_db_cell_is_error(self):
        b = HiveBuilder()
        data_off = b.add(b"X" * 20000)
        vk = bytearray(20 + 4)
        vk[0:2] = b"vk"
        struct.pack_into("<H", vk, 2, 4)
        struct.pack_into("<I", vk, 4, 20000)
        struct.pack_into("<I", vk, 8, data_off)
        struct.pack_into("<I", vk, 12, 3)
        struct.pack_into("<H", vk, 16, 0x1)
        vk[20:] = b"Bad1"
        vk_off = b.add(bytes(vk))
        vals = b.add(struct.pack("<I", vk_off))
        root_off = add_nk_cell(b, "ROOT", 0, 0xFFFFFFFF, 1, vals)
        hive = rp.Hive(b.assemble(root_off), "bad.hive")
        with self.assertRaises(rp.RegfError) as ctx:
            hive.get_value(hive.root(), "Bad1")
        self.assertIn("not a 'db' data block", str(ctx.exception))

    def test_zero_size_cell_is_error(self):
        data = bytearray(make_hive({"name": "ROOT"}))
        hive = rp.Hive(bytes(data), "z.hive")
        root_off = hive.root_offset
        struct.pack_into("<i", data, 4096 + root_off, 0)
        hive2 = rp.Hive(bytes(data), "z2.hive")
        with self.assertRaises(rp.RegfError) as ctx:
            hive2.root()
        self.assertIn("zero size", str(ctx.exception))

    def test_bad_magic_and_small_file(self):
        with self.assertRaises(rp.RegfError):
            rp.Hive(b"not a hive at all", "x.hive")
        with self.assertRaises(rp.RegfError):
            rp.Hive(b"regf" + b"\x00" * 100, "small.hive")

    def test_transaction_log_rejected(self):
        data = make_hive({"name": "ROOT"}, file_type=1)
        with self.assertRaises(rp.RegfError) as ctx:
            rp.Hive(data, "log.hive")
        self.assertIn("transaction log", str(ctx.exception))

    def test_unicode_key_and_value_names(self):
        spec = {
            "name": "Kéy-Ω",
            "ascii_name": False,
            "values": [{"name": "Ödül", "ascii_name": False, "type": 1, "data": u16le("değer")}],
        }
        data = make_hive(spec)
        hive = rp.Hive(data, "u.hive")
        self.assertEqual(hive.root()["name"], "Kéy-Ω")
        vk, val = hive.get_value(hive.root(), "Ödül")
        self.assertEqual(rp.decode_reg_string(val), "değer")

    def test_subkey_count_mismatch_warns(self):
        b = HiveBuilder()
        c1 = add_nk_cell(b, "A", 0, 0xFFFFFFFF, 0, 0xFFFFFFFF)
        c2 = add_nk_cell(b, "B", 0, 0xFFFFFFFF, 0, 0xFFFFFFFF)
        lf_off = b.add(b"lf" + struct.pack("<H", 2) + struct.pack("<II", c1, 0) + struct.pack("<II", c2, 0))
        root_off = add_nk_cell(b, "ROOT", 1, lf_off, 0, 0xFFFFFFFF)
        hive = rp.Hive(b.assemble(root_off), "mismatch.hive")
        children = hive.subkeys(hive.root())
        self.assertEqual(len(children), 2)
        self.assertTrue(any("reports 1 subkeys" in w for w in hive.warnings))


# ---------------------------------------------------------------------------
# Artifact extractor tests
# ---------------------------------------------------------------------------

GUID_EA = "{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}"
GUID_LNK = "{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}"
SID = "S-1-5-21-1111-2222-3333-1001"

SHA1_HEX = "a" * 40

RUNPATH_RAW = "HRZR_EHACNGU:P:\\Grfg\\ncc.rkr"  # rot13 of UEME_RUNPATH:C:\Test\app.exe
RUNPATH_DECODED = "UEME_RUNPATH:C:\\Test\\app.exe"
CTLSESSION_RAW = "HRZR_PGYFRFFVBA"  # rot13 of UEME_CTLSESSION


def v5_entry(run_count, focus_count, focus_ms, last_run):
    data = bytearray(72)
    struct.pack_into("<I", data, 0, 0xFFFFFFFF)
    struct.pack_into("<I", data, 4, run_count)
    struct.pack_into("<I", data, 8, focus_count)
    struct.pack_into("<i", data, 12, focus_ms)
    struct.pack_into("<Q", data, 60, last_run)
    return bytes(data)


def v3_entry(session_id, run_count, last_run):
    return struct.pack("<IIQ", session_id, run_count, last_run)


def bam_value(exec_time_ft, app_flag=0):
    data = bytearray(24)
    struct.pack_into("<Q", data, 0, exec_time_ft)
    struct.pack_into("<I", data, 16, app_flag)
    struct.pack_into("<I", data, 20, 2)
    return bytes(data)


def appcache_win10_entry(path, mtime_ft, data=b""):
    path_bytes = path.encode("utf-16le")
    body = struct.pack("<H", len(path_bytes)) + path_bytes + struct.pack("<Q", mtime_ft)
    body += struct.pack("<I", len(data)) + data
    return b"10ts" + struct.pack("<II", 0x00430000, len(body)) + body


def appcache_blob_win10(entries, header_size=48):
    header = bytearray(header_size)
    struct.pack_into("<I", header, 0, header_size)
    struct.pack_into("<I", header, 36 if header_size == 48 else 40, len(entries))
    return bytes(header) + b"".join(entries)


def appcache_win8_entry(path, mtime_ft, signature=b"00ts"):
    path_bytes = path.encode("utf-16le")
    body = struct.pack("<H", len(path_bytes)) + path_bytes
    body += struct.pack("<II", 1, 0)  # two unknown u32
    if signature == b"10ts":
        body += struct.pack("<H", 0)
    body += struct.pack("<Q", mtime_ft) + struct.pack("<I", 0)
    return signature + struct.pack("<II", 0, len(body)) + body


def art_spec():
    """One synthetic hive containing every supported artifact anchor."""
    return {
        "name": "AMCACHE",
        "subkeys": [
            {
                "name": "Root",
                "subkeys": [
                    {
                        "name": "InventoryApplicationFile",
                        "subkeys": [
                            {
                                "name": "SAMPLE.EXE|abcdef01",
                                "lwt": FT_RUN,
                                "values": [
                                    {"name": "FileId", "type": 1, "data": u16le("0000" + SHA1_HEX)},
                                    {"name": "LowerCaseLongPath", "type": 1, "data": u16le("c:\\tools\\sample.exe")},
                                    {"name": "Name", "type": 1, "data": u16le("SAMPLE.EXE")},
                                    {"name": "Size", "type": 11, "data": struct.pack("<Q", 123456)},
                                    {"name": "Language", "type": 4, "data": struct.pack("<I", 1033)},
                                    {"name": "LinkDate", "type": 1, "data": u16le("06/01/2020 00:00:00")},
                                    {"name": "BinaryType", "type": 1, "data": u16le("pe32_amd64")},
                                    {"name": "ExtraValue", "type": 1, "data": u16le("kept-in-other")},
                                ],
                            }
                        ],
                    },
                    {
                        "name": "InventoryApplication",
                        "values": [{"name": "LastScanTime", "type": 11, "data": struct.pack("<Q", FT0)}],
                        "subkeys": [
                            {
                                "name": "0123456789abcdef",
                                "values": [
                                    {"name": "Name", "type": 1, "data": u16le("Sample App")},
                                    {"name": "Publisher", "type": 1, "data": u16le("ACME")},
                                    {"name": "InstallDate", "type": 1, "data": u16le("20200101")},
                                    {"name": "Source", "type": 1, "data": u16le("AddRemoveProgram")},
                                ],
                            }
                        ],
                    },
                    {
                        "name": "File",
                        "subkeys": [
                            {
                                "name": "{11111111-2222-3333-4444-555555555555}",
                                "subkeys": [
                                    {
                                        "name": "100001605a",
                                        "values": [
                                            {"name": "0", "type": 1, "data": u16le("LegacyApp")},
                                            {"name": "1", "type": 1, "data": u16le("Legacy Co")},
                                            {"name": "6", "type": 4, "data": struct.pack("<I", 4096)},
                                            {"name": "f", "type": 4, "data": struct.pack("<I", 1590000000)},
                                            {"name": "11", "type": 11, "data": struct.pack("<Q", FT_RUN)},
                                            {"name": "15", "type": 1, "data": u16le("c:\\legacy\\app.exe")},
                                            {"name": "101", "type": 1, "data": u16le("0000" + "b" * 40)},
                                        ],
                                    }
                                ],
                            }
                        ],
                    },
                    {
                        "name": "Programs",
                        "subkeys": [
                            {
                                "name": "0123",
                                "values": [
                                    {"name": "0", "type": 1, "data": u16le("ProgramsApp")},
                                    {"name": "2", "type": 1, "data": u16le("P Co")},
                                    {"name": "a", "type": 4, "data": struct.pack("<I", 1580000000)},
                                ],
                            }
                        ],
                    },
                ],
            },
            {
                "name": "ControlSet001",
                "subkeys": [
                    {
                        "name": "Control",
                        "subkeys": [
                            {
                                "name": "Session Manager",
                                "subkeys": [
                                    {
                                        "name": "AppCompatCache",
                                        "lwt": FT_RUN,
                                        "values": [
                                            {
                                                "name": "AppCompatCache",
                                                "type": 3,
                                                "data": appcache_blob_win10(
                                                    [
                                                        appcache_win10_entry("C:\\Windows\\System32\\cmd.exe", FT_RUN, b"\x00" * 16),
                                                        appcache_win10_entry("C:\\Tools\\tool.exe", FT0),
                                                    ]
                                                ),
                                            }
                                        ],
                                    }
                                ],
                                "values": [
                                    {
                                        "name": "PendingFileRenameOperations",
                                        "type": 7,
                                        "data": multi_sz(
                                            [
                                                "\\??\\C:\\stage\\new.dll",
                                                "\\??\\C:\\Windows\\System32\\old.dll",
                                                "\\??\\C:\\Temp\\drop.tmp",
                                                "",
                                            ]
                                        ),
                                    }
                                ],
                            }
                        ],
                    },
                    {
                        "name": "Services",
                        "subkeys": [
                            {
                                "name": "bam",
                                "subkeys": [
                                    {
                                        "name": "State",
                                        "subkeys": [
                                            {
                                                "name": "UserSettings",
                                                "subkeys": [
                                                    {
                                                        "name": SID,
                                                        "values": [
                                                            {"name": "Version", "type": 4, "data": struct.pack("<I", 2)},
                                                            {"name": "SequenceNumber", "type": 4, "data": struct.pack("<I", 9)},
                                                            {
                                                                "name": "\\Device\\HarddiskVolume3\\Windows\\System32\\cmd.exe",
                                                                "type": 3,
                                                                "data": bam_value(FT_RUN, 0),
                                                            },
                                                            {
                                                                "name": "Microsoft.WindowsCalculator_8wekyb3d8bbwe!App",
                                                                "type": 3,
                                                                "data": bam_value(FT0, 1),
                                                            },
                                                        ],
                                                    }
                                                ],
                                            }
                                        ],
                                    }
                                ],
                            }
                        ],
                    },
                ],
            },
            {
                "name": "Software",
                "subkeys": [
                    {
                        "name": "Microsoft",
                        "subkeys": [
                            {
                                "name": "Windows",
                                "subkeys": [
                                    {
                                        "name": "CurrentVersion",
                                        "subkeys": [
                                            {
                                                "name": "Explorer",
                                                "subkeys": [
                                                    {
                                                        "name": "UserAssist",
                                                        "subkeys": [
                                                            {
                                                                "name": GUID_EA,
                                                                "values": [{"name": "Version", "type": 4, "data": struct.pack("<I", 5)}],
                                                                "subkeys": [
                                                                    {
                                                                        "name": "Count",
                                                                        "values": [
                                                                            {
                                                                                "name": RUNPATH_RAW,
                                                                                "ascii_name": False,
                                                                                "type": 3,
                                                                                "data": v5_entry(7, 3, -1, FT_RUN),
                                                                            },
                                                                            {
                                                                                "name": CTLSESSION_RAW,
                                                                                "ascii_name": False,
                                                                                "type": 3,
                                                                                "data": v5_entry(42, 0, -1, FT_RUN),
                                                                            },
                                                                        ],
                                                                    }
                                                                ],
                                                            },
                                                            {
                                                                "name": GUID_LNK,
                                                                "values": [{"name": "Version", "type": 4, "data": struct.pack("<I", 3)}],
                                                                "subkeys": [
                                                                    {
                                                                        "name": "Count",
                                                                        "values": [
                                                                            {
                                                                                "name": RUNPATH_RAW,
                                                                                "ascii_name": False,
                                                                                "type": 3,
                                                                                "data": v3_entry(2, 9, FT0),
                                                                            }
                                                                        ],
                                                                    }
                                                                ],
                                                            },
                                                        ],
                                                    },
                                                    {
                                                        "name": "RunMRU",
                                                        "values": [
                                                            {"name": "MRUList", "type": 1, "data": u16le("ba")},
                                                            {"name": "a", "type": 1, "data": u16le("notepad")},
                                                            {"name": "b", "type": 1, "data": u16le("calc")},
                                                            {"name": "c", "type": 1, "data": u16le("cmd /k whoami")},
                                                        ],
                                                    },
                                                    {
                                                        "name": "TypedPaths",
                                                        "values": [
                                                            {"name": "url1", "type": 1, "data": u16le("\\\\server\\share")},
                                                            {"name": "url2", "type": 1, "data": u16le("C:\\projects")},
                                                        ],
                                                    },
                                                ],
                                            },
                                        ],
                                    }
                                ],
                            },
                            {
                                "name": "Windows NT",
                                "subkeys": [
                                    {
                                        "name": "CurrentVersion",
                                        "subkeys": [
                                            {
                                                "name": "AppCompatFlags",
                                                "subkeys": [
                                                    {
                                                        "name": "Layers",
                                                        "values": [
                                                            {
                                                                "name": "C:\\Tools\\tool.exe",
                                                                "type": 1,
                                                                "data": u16le("~ RUNASADMIN"),
                                                            },
                                                            {
                                                                "name": "C:\\Old\\win98app.exe",
                                                                "type": 1,
                                                                "data": u16le("~ WIN98"),
                                                            },
                                                        ],
                                                    }
                                                ],
                                            },
                                        ],
                                    }
                                ],
                            },
                        ],
                    },
                    {
                        "name": "Classes",
                        "subkeys": [
                            {
                                "name": "Local Settings",
                                "subkeys": [
                                    {
                                        "name": "Software",
                                        "subkeys": [
                                            {
                                                "name": "Microsoft",
                                                "subkeys": [
                                                    {
                                                        "name": "Windows",
                                                        "subkeys": [
                                                            {
                                                                "name": "Shell",
                                                                "subkeys": [
                                                                    {
                                                                        "name": "MuiCache",
                                                                        "values": [
                                                                            {
                                                                                "name": "C:\\Windows\\notepad.exe",
                                                                                "type": 1,
                                                                                "data": u16le("Notepad"),
                                                                            },
                                                                            {
                                                                                "name": "C:\\Tools\\tool.exe.FriendlyAppName",
                                                                                "type": 1,
                                                                                "data": u16le("The Tool"),
                                                                            },
                                                                        ],
                                                                    }
                                                                ],
                                                            }
                                                        ],
                                                    }
                                                ],
                                            }
                                        ],
                                    }
                                ],
                            }
                        ],
                    },
                ],
            },
        ],
    }


def parse_all(data, name="art.hive", selected=None, explicit=False):
    hive = rp.Hive(data, name)
    stats = rp.Stats()
    names = selected or list(rp.EXTRACTORS)
    records = list(rp.run_extractors(hive, "0" * 64, names, explicit, stats, False))
    return hive, stats, records


def by_artifact(records, artifact):
    return [r for r in records if r["artifact"] == artifact]


class ArtifactExtractorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = make_hive(art_spec())
        cls.hive, cls.stats, cls.records = parse_all(cls.data)

    def test_amcache_inventory_application_file(self):
        recs = by_artifact(self.records, "amcache_inventory_application_file")
        self.assertEqual(len(recs), 1)
        rec = recs[0]
        self.assertEqual(rec["key_name"], "SAMPLE.EXE|abcdef01")
        self.assertEqual(rec["sha1"], SHA1_HEX)
        self.assertEqual(rec["file_id_raw"], "0000" + SHA1_HEX)
        self.assertEqual(rec["path"], "c:\\tools\\sample.exe")
        self.assertEqual(rec["size"], 123456)
        self.assertEqual(rec["language"], 1033)
        self.assertEqual(rec["binary_type"], "pe32_amd64")
        self.assertEqual(rec["link_date"], "06/01/2020 00:00:00")
        self.assertEqual(rec["link_date_ts"], "2020-06-01T00:00:00Z")
        self.assertEqual(rec["key_last_write_time"], iso(T_RUN))
        self.assertEqual(rec["other_values"]["ExtraValue"], "kept-in-other")

    def test_amcache_inventory_application(self):
        recs = by_artifact(self.records, "amcache_inventory_application")
        self.assertEqual(len(recs), 1)
        rec = recs[0]
        self.assertEqual(rec["name"], "Sample App")
        self.assertEqual(rec["publisher"], "ACME")
        self.assertEqual(rec["install_date"], "20200101")
        self.assertEqual(rec["source"], "AddRemoveProgram")
        self.assertEqual(rec["inventory_last_scan_time"], iso(T0))

    def test_amcache_legacy_file_key(self):
        recs = by_artifact(self.records, "amcache_file")
        self.assertEqual(len(recs), 1)
        rec = recs[0]
        self.assertEqual(rec["identifier"], "100001605a")
        self.assertEqual(rec["file_reference_sequence"], 1)
        self.assertEqual(rec["file_reference_mft_entry"], 0x1605A)
        self.assertEqual(rec["name"], "LegacyApp")
        self.assertEqual(rec["company"], "Legacy Co")
        self.assertEqual(rec["file_size"], 4096)
        self.assertEqual(rec["link_date_ts"], "2020-05-20T18:40:00Z")
        self.assertEqual(rec["modification_time"], iso(T_RUN))
        self.assertEqual(rec["path"], "c:\\legacy\\app.exe")
        self.assertEqual(rec["sha1"], "b" * 40)

    def test_amcache_programs(self):
        recs = by_artifact(self.records, "amcache_programs")
        self.assertEqual(len(recs), 1)
        rec = recs[0]
        self.assertEqual(rec["name"], "ProgramsApp")
        self.assertEqual(rec["publisher"], "P Co")
        self.assertTrue(rec["install_time_ts"].startswith("2020-01-26T"))

    def test_appcompatcache_win10(self):
        recs = by_artifact(self.records, "appcompatcache")
        self.assertEqual(len(recs), 2)
        first = recs[0]
        self.assertEqual(first["path"], "C:\\Windows\\System32\\cmd.exe")
        self.assertEqual(first["last_modification_time"], iso(T_RUN))
        self.assertEqual(first["entry_signature"], "10ts")
        self.assertEqual(first["data_size"], 16)
        self.assertEqual(first["control_set"], "ControlSet001")
        stats = {r["path"]: r for r in recs}
        self.assertEqual(stats["C:\\Tools\\tool.exe"]["data_size"], 0)

    def test_appcompatcache_win8_entries(self):
        blob = bytearray(0x80)
        struct.pack_into("<I", blob, 0, 0x80)
        blob += appcache_win8_entry("C:\\Win8\\a.exe", FT0, b"00ts")
        blob += appcache_win8_entry("C:\\Win8\\b.exe", FT_RUN, b"10ts")
        data = make_hive(
            {
                "name": "ROOT",
                "subkeys": [
                    {
                        "name": "ControlSet001",
                        "subkeys": [
                            {
                                "name": "Control",
                                "subkeys": [
                                    {
                                        "name": "Session Manager",
                                        "subkeys": [
                                            {
                                                "name": "AppCompatCache",
                                                "values": [{"name": "AppCompatCache", "type": 3, "data": bytes(blob)}],
                                            }
                                        ],
                                    }
                                ],
                            }
                        ],
                    }
                ],
            }
        )
        hive, stats, recs = parse_all(data)
        acc = [r for r in recs if r["artifact"] == "appcompatcache"]
        self.assertEqual(stats.errors, [])
        self.assertEqual([r["path"] for r in acc], ["C:\\Win8\\a.exe", "C:\\Win8\\b.exe"])
        self.assertEqual([r["entry_signature"] for r in acc], ["00ts", "10ts"])
        self.assertEqual(acc[1]["last_modification_time"], iso(T_RUN))

    def test_bam(self):
        recs = by_artifact(self.records, "bam")
        self.assertEqual(len(recs), 2)
        paths = {r["path"]: r for r in recs}
        self.assertNotIn("Version", paths)
        self.assertNotIn("SequenceNumber", paths)
        cmd = paths["\\Device\\HarddiskVolume3\\Windows\\System32\\cmd.exe"]
        self.assertEqual(cmd["user_sid"], SID)
        self.assertEqual(cmd["execution_time"], iso(T_RUN))
        self.assertEqual(cmd["windows_app_flag"], 0)
        uwp = paths["Microsoft.WindowsCalculator_8wekyb3d8bbwe!App"]
        self.assertEqual(uwp["windows_app_flag"], 1)
        self.assertEqual(uwp["execution_time"], iso(T0))

    def test_userassist(self):
        recs = by_artifact(self.records, "userassist")
        self.assertEqual(len(recs), 2)
        v5 = [r for r in recs if r["version"] == 5][0]
        self.assertEqual(v5["value_name_raw"], RUNPATH_RAW)
        self.assertEqual(v5["name"], RUNPATH_DECODED)
        self.assertEqual(v5["kind"], "UEME_RUNPATH")
        self.assertEqual(v5["target"], "C:\\Test\\app.exe")
        self.assertEqual(v5["run_count"], 7)
        self.assertEqual(v5["focus_count"], 3)
        self.assertEqual(v5["focus_time_ms"], -1)
        self.assertEqual(v5["last_run_time"], iso(T_RUN))
        v3 = [r for r in recs if r["version"] == 3][0]
        self.assertEqual(v3["session_id"], 2)
        self.assertEqual(v3["run_count"], 9)
        self.assertEqual(v3["last_run_time"], iso(T0))
        self.assertIsNone(v3["focus_time_ms"])
        self.assertTrue(any("UEME_CTLSESSION" in n for n in self.stats.notes))

    def test_userassist_plain_path_name_has_no_kind(self):
        raw = "P:\\Gbbyf\\cynva.rkr"  # rot13 of C:\Tools\plain.exe
        data = make_hive(
            {
                "name": "ROOT",
                "subkeys": [
                    {
                        "name": "Software",
                        "subkeys": [
                            {
                                "name": "Microsoft",
                                "subkeys": [
                                    {
                                        "name": "Windows",
                                        "subkeys": [
                                            {
                                                "name": "CurrentVersion",
                                                "subkeys": [
                                                    {
                                                        "name": "Explorer",
                                                        "subkeys": [
                                                            {
                                                                "name": "UserAssist",
                                                                "subkeys": [
                                                                    {
                                                                        "name": GUID_EA,
                                                                        "values": [
                                                                            {"name": "Version", "type": 4, "data": struct.pack("<I", 5)}
                                                                        ],
                                                                        "subkeys": [
                                                                            {
                                                                                "name": "Count",
                                                                                "values": [
                                                                                    {
                                                                                        "name": raw,
                                                                                        "ascii_name": False,
                                                                                        "type": 3,
                                                                                        "data": v5_entry(3, 1, -1, FT_RUN),
                                                                                    }
                                                                                ],
                                                                            }
                                                                        ],
                                                                    }
                                                                ],
                                                            }
                                                        ],
                                                    }
                                                ],
                                            }
                                        ],
                                    }
                                ],
                            }
                        ],
                    }
                ],
            }
        )
        hive, stats, recs = parse_all(data)
        ua = by_artifact(recs, "userassist")
        self.assertEqual(len(ua), 1)
        self.assertEqual(ua[0]["name"], "C:\\Tools\\plain.exe")
        self.assertIsNone(ua[0]["kind"])
        self.assertIsNone(ua[0]["target"])
        self.assertEqual(ua[0]["run_count"], 3)

    def test_muicache(self):
        recs = by_artifact(self.records, "muicache")
        self.assertEqual(len(recs), 2)
        by_path = {r["executable_path"]: r for r in recs}
        self.assertEqual(by_path["C:\\Windows\\notepad.exe"]["display_name"], "Notepad")
        self.assertIsNone(by_path["C:\\Windows\\notepad.exe"]["value_name_suffix"])
        tool = by_path["C:\\Tools\\tool.exe"]
        self.assertEqual(tool["value_name_suffix"], "FriendlyAppName")
        self.assertEqual(tool["display_name"], "The Tool")

    def test_runmru(self):
        recs = by_artifact(self.records, "runmru")
        self.assertEqual(len(recs), 3)
        by_slot = {r["slot"]: r for r in recs}
        self.assertEqual(by_slot["b"]["position"], 0)
        self.assertTrue(by_slot["b"]["is_most_recent"])
        self.assertEqual(by_slot["b"]["command"], "calc")
        self.assertEqual(by_slot["a"]["position"], 1)
        self.assertEqual(by_slot["c"]["position"], None)
        self.assertFalse(by_slot["c"]["is_most_recent"])

    def test_typedpaths(self):
        recs = by_artifact(self.records, "typedpaths")
        self.assertEqual([r["position"] for r in recs], [1, 2])
        self.assertEqual(recs[0]["path"], "\\\\server\\share")
        self.assertEqual(recs[1]["path"], "C:\\projects")

    def test_layers(self):
        recs = by_artifact(self.records, "appcompatflags_layers")
        self.assertEqual(len(recs), 2)
        by_exe = {r["executable_path"]: r for r in recs}
        tool = by_exe["C:\\Tools\\tool.exe"]
        self.assertEqual(tool["scope"], "user")
        self.assertTrue(tool["run_as_admin"])
        self.assertEqual(tool["layer_flags"], ["RUNASADMIN"])
        other = by_exe["C:\\Old\\win98app.exe"]
        self.assertFalse(other["run_as_admin"])
        self.assertEqual(other["layer_flags"], ["WIN98"])

    def test_pending_file_renames(self):
        recs = by_artifact(self.records, "pending_file_rename_operations")
        self.assertEqual(len(recs), 2)
        rename, delete = recs
        self.assertEqual(rename["operation"], "rename")
        self.assertEqual(rename["source"], "\\??\\C:\\stage\\new.dll")
        self.assertEqual(rename["destination"], "\\??\\C:\\Windows\\System32\\old.dll")
        self.assertEqual(rename["source_display"], "C:\\stage\\new.dll")
        self.assertEqual(rename["control_set"], "ControlSet001")
        self.assertEqual(delete["operation"], "delete")
        self.assertEqual(delete["source"], "\\??\\C:\\Temp\\drop.tmp")
        self.assertIsNone(delete["destination"])

    def test_no_spurious_errors_or_notes(self):
        self.assertEqual(self.stats.errors, [])
        expected = ("CTLSESSION", "not referenced by MRUList")
        residual = [n for n in self.stats.notes if not any(e in n for e in expected)]
        self.assertEqual(residual, [])


class ArtifactEdgeCaseTests(unittest.TestCase):
    def test_link_date_conversion(self):
        self.assertEqual(rp.amcache_link_date_to_iso("06/02/2010 11:35:34"), "2010-06-02T11:35:34Z")
        self.assertIsNone(rp.amcache_link_date_to_iso(""))
        self.assertIsNone(rp.amcache_link_date_to_iso(None))

    def test_link_date_implausible_sentinel_warns(self):
        warnings = []
        self.assertIsNone(rp.amcache_link_date_to_iso("01/21/2083 21:12:07", warnings))
        self.assertEqual(len(warnings), 1)
        self.assertIn("implausible", warnings[0])

    def test_link_date_signed32_ceiling_is_inclusive(self):
        self.assertEqual(rp.amcache_link_date_to_iso("01/19/2038 03:14:07"), "2038-01-19T03:14:07Z")
        warnings = []
        self.assertIsNone(rp.amcache_link_date_to_iso("01/19/2038 03:14:08", warnings))
        self.assertEqual(len(warnings), 1)

    def test_link_date_unparseable_warns(self):
        warnings = []
        self.assertIsNone(rp.amcache_link_date_to_iso("not a date", warnings))
        self.assertEqual(len(warnings), 1)
        self.assertIn("MM/DD/YYYY", warnings[0])

    def test_legacy_appcompatcache_honest_error(self):
        blob = struct.pack("<I", 0xBADC0FEE) + b"\x00" * 128
        data = make_hive(
            {
                "name": "ROOT",
                "subkeys": [
                    {
                        "name": "ControlSet001",
                        "subkeys": [
                            {
                                "name": "Control",
                                "subkeys": [
                                    {
                                        "name": "Session Manager",
                                        "subkeys": [
                                            {
                                                "name": "AppCompatCache",
                                                "values": [{"name": "AppCompatCache", "type": 3, "data": blob}],
                                            }
                                        ],
                                    }
                                ],
                            }
                        ],
                    }
                ],
            }
        )
        hive, stats, recs = parse_all(data, explicit=False)
        recs = [r for r in recs if r["artifact"] == "appcompatcache"]
        self.assertEqual(recs, [])
        self.assertEqual(len(stats.errors), 1)
        self.assertIn("legacy AppCompatCache format", stats.errors[0]["error"])

    def test_appcompatcache_malformed_tail_warns_and_keeps_valid(self):
        entries = [
            appcache_win10_entry("C:\\A.exe", FT0),
            appcache_win10_entry("C:\\B.exe", FT0),
        ]
        blob = bytearray(appcache_blob_win10(entries))
        struct.pack_into("<I", blob, 36, 4)  # claim 4 entries, supply 2 + garbage
        blob += b"\x99" * 40
        data = make_hive(
            {
                "name": "ROOT",
                "subkeys": [
                    {
                        "name": "ControlSet001",
                        "subkeys": [
                            {
                                "name": "Control",
                                "subkeys": [
                                    {
                                        "name": "Session Manager",
                                        "subkeys": [
                                            {
                                                "name": "AppCompatCache",
                                                "values": [{"name": "AppCompatCache", "type": 3, "data": bytes(blob)}],
                                            }
                                        ],
                                    }
                                ],
                            }
                        ],
                    }
                ],
            }
        )
        hive, stats, recs = parse_all(data)
        acc = [r for r in recs if r["artifact"] == "appcompatcache"]
        self.assertEqual(len(acc), 2)
        self.assertTrue(any("expected '10ts'" in w for w in hive.warnings + list(stats.warning_counts)))

    def test_appcompatcache_count_field_not_authoritative(self):
        entries = [
            appcache_win10_entry("C:\\Cnt\\a.exe", FT0),
            appcache_win10_entry("C:\\Cnt\\b.exe", FT0),
        ]
        blob = bytearray(appcache_blob_win10(entries))
        struct.pack_into("<I", blob, 36, 9)  # lifetime counter, not the current entry count
        data = make_hive(
            {
                "name": "ROOT",
                "subkeys": [
                    {
                        "name": "ControlSet001",
                        "subkeys": [
                            {
                                "name": "Control",
                                "subkeys": [
                                    {
                                        "name": "Session Manager",
                                        "subkeys": [
                                            {
                                                "name": "AppCompatCache",
                                                "values": [{"name": "AppCompatCache", "type": 3, "data": bytes(blob)}],
                                            }
                                        ],
                                    }
                                ],
                            }
                        ],
                    }
                ],
            }
        )
        hive, stats, recs = parse_all(data)
        acc = [r for r in recs if r["artifact"] == "appcompatcache"]
        self.assertEqual(len(acc), 2)
        self.assertTrue(any("lifetime counter" in n for n in stats.notes))

    def test_pending_renames_malformed_tail(self):
        data = make_hive(
            {
                "name": "ROOT",
                "subkeys": [
                    {
                        "name": "ControlSet001",
                        "subkeys": [
                            {
                                "name": "Control",
                                "subkeys": [
                                    {
                                        "name": "Session Manager",
                                        "values": [
                                            {
                                                "name": "PendingFileRenameOperations",
                                                "type": 7,
                                                "data": multi_sz(["\\??\\C:\\only-source.tmp"]),
                                            }
                                        ],
                                    }
                                ],
                            }
                        ],
                    }
                ],
            }
        )
        hive, stats, recs = parse_all(data)
        recs = [r for r in recs if r["artifact"] == "pending_file_rename_operations"]
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0]["operation"], "malformed")
        self.assertTrue(any("odd number of strings" in w for w in recs[0]["warnings"]))

    def test_bam_wrong_value_size_warns(self):
        data = make_hive(
            {
                "name": "ROOT",
                "subkeys": [
                    {
                        "name": "ControlSet001",
                        "subkeys": [
                            {
                                "name": "Services",
                                "subkeys": [
                                    {
                                        "name": "bam",
                                        "subkeys": [
                                            {
                                                "name": "State",
                                                "subkeys": [
                                                    {
                                                        "name": "UserSettings",
                                                        "subkeys": [
                                                            {
                                                                "name": SID,
                                                                "values": [
                                                                    {"name": "\\Device\\X\\short.exe", "type": 3, "data": b"\x01\x02"}
                                                                ],
                                                            }
                                                        ],
                                                    }
                                                ],
                                            }
                                        ],
                                    }
                                ],
                            }
                        ],
                    }
                ],
            }
        )
        hive, stats, recs = parse_all(data)
        recs = [r for r in recs if r["artifact"] == "bam"]
        self.assertEqual(len(recs), 1)
        self.assertIsNone(recs[0]["execution_time"])
        self.assertTrue(any("too small" in w for w in recs[0]["warnings"]))

    def test_userassist_unexpected_version_warns(self):
        data = make_hive(
            {
                "name": "ROOT",
                "subkeys": [
                    {
                        "name": "Software",
                        "subkeys": [
                            {
                                "name": "Microsoft",
                                "subkeys": [
                                    {
                                        "name": "Windows",
                                        "subkeys": [
                                            {
                                                "name": "CurrentVersion",
                                                "subkeys": [
                                                    {
                                                        "name": "Explorer",
                                                        "subkeys": [
                                                            {
                                                                "name": "UserAssist",
                                                                "subkeys": [
                                                                    {
                                                                        "name": GUID_EA,
                                                                        "values": [
                                                                            {"name": "Version", "type": 4, "data": struct.pack("<I", 4)}
                                                                        ],
                                                                        "subkeys": [
                                                                            {
                                                                                "name": "Count",
                                                                                "values": [
                                                                                    {
                                                                                        "name": RUNPATH_RAW,
                                                                                        "ascii_name": False,
                                                                                        "type": 3,
                                                                                        "data": v5_entry(1, 0, 0, FT0),
                                                                                    }
                                                                                ],
                                                                            }
                                                                        ],
                                                                    }
                                                                ],
                                                            }
                                                        ],
                                                    }
                                                ],
                                            }
                                        ],
                                    }
                                ],
                            }
                        ],
                    }
                ],
            }
        )
        hive, stats, recs = parse_all(data)
        recs = [r for r in recs if r["artifact"] == "userassist"]
        self.assertEqual(len(recs), 1)
        self.assertTrue(any("unexpected UserAssist version" in w for w in recs[0]["warnings"]))

    def test_explicit_missing_anchor_reports_error(self):
        data = make_hive({"name": "ROOT"})
        hive, stats, recs = parse_all(data, selected=["pending_file_rename_operations"], explicit=True)
        self.assertEqual(recs, [])
        self.assertEqual(len(stats.errors), 1)
        self.assertIn("not present", stats.errors[0]["error"])

    def test_explicit_amcache_on_non_amcache_hive(self):
        data = make_hive({"name": "ROOT"})
        hive, stats, recs = parse_all(data, selected=["amcache"], explicit=True)
        self.assertEqual(recs, [])
        self.assertEqual(len(stats.errors), 1)
        self.assertIn("Amcache anchor", stats.errors[0]["error"])


# ---------------------------------------------------------------------------
# CLI tests
# ---------------------------------------------------------------------------

class RegParseCliTests(unittest.TestCase):
    def _run(self, *args):
        return subprocess.run(
            [sys.executable, PARSER, *args],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="regtest_")

    def _path(self, name):
        return os.path.join(self.tmpdir, name)

    def test_cli_jsonl_and_report(self):
        hive_path = write_tmp(make_hive(art_spec()), ".hive")
        jsonl_path = self._path("out.jsonl")
        report_path = self._path("report.json")
        proc = self._run(hive_path, "--jsonl", jsonl_path, "--report", report_path)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        with open(jsonl_path, encoding="utf-8") as fh:
            records = [json.loads(line) for line in fh if line.strip()]
        self.assertGreater(len(records), 10)
        artifacts = {r["artifact"] for r in records}
        self.assertIn("amcache_inventory_application_file", artifacts)
        self.assertIn("userassist", artifacts)
        self.assertIn("pending_file_rename_operations", artifacts)
        with open(report_path, encoding="utf-8") as fh:
            report = json.load(fh)
        self.assertEqual(report["tool"], "reg_parse")
        self.assertEqual(report["counts"]["hives"], 1)
        self.assertEqual(report["counts"]["parsed"], 1)
        self.assertEqual(report["counts"]["failed"], 0)
        self.assertEqual(report["counts"]["emitted"], len(records))
        self.assertNotIn("no_records_emitted", report["warnings"])

    def test_cli_artifact_filter(self):
        hive_path = write_tmp(make_hive(art_spec()), ".hive")
        jsonl_path = self._path("ua.jsonl")
        proc = self._run(hive_path, "--artifact", "userassist", "--jsonl", jsonl_path)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        with open(jsonl_path, encoding="utf-8") as fh:
            records = [json.loads(line) for line in fh if line.strip()]
        self.assertTrue(records)
        self.assertEqual({r["artifact"] for r in records}, {"userassist"})

    def test_cli_unknown_artifact_usage_error(self):
        hive_path = write_tmp(make_hive({"name": "ROOT"}), ".hive")
        proc = self._run(hive_path, "--artifact", "bogus")
        self.assertEqual(proc.returncode, 2)

    def test_cli_limit(self):
        hive_path = write_tmp(make_hive(art_spec()), ".hive")
        jsonl_path = self._path("lim.jsonl")
        proc = self._run(hive_path, "--jsonl", jsonl_path, "--limit", "3")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        with open(jsonl_path, encoding="utf-8") as fh:
            records = [json.loads(line) for line in fh if line.strip()]
        self.assertEqual(len(records), 3)

    def test_cli_raw_adds_hex(self):
        hive_path = write_tmp(make_hive(art_spec()), ".hive")
        jsonl_path = self._path("raw.jsonl")
        proc = self._run(hive_path, "--artifact", "bam", "--raw", "--jsonl", jsonl_path)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        with open(jsonl_path, encoding="utf-8") as fh:
            records = [json.loads(line) for line in fh if line.strip()]
        self.assertTrue(all("data_hex" in r for r in records))

    def test_cli_zero_filled_reports_honest_error(self):
        hive_path = write_tmp(b"\x00" * 8192, ".hive")
        report_path = self._path("zero_report.json")
        proc = self._run(hive_path, "--jsonl", self._path("zero.jsonl"), "--report", report_path)
        self.assertEqual(proc.returncode, 0)
        with open(report_path, encoding="utf-8") as fh:
            report = json.load(fh)
        self.assertEqual(report["counts"]["parsed"], 0)
        self.assertEqual(report["counts"]["failed"], 1)
        self.assertTrue(any("bad magic" in e["error"] for e in report["errors"]))
        self.assertIn("hives_failed_to_parse", report["warnings"])

    def test_cli_directory_expansion_skips_logs_and_manifest(self):
        d = self._path("dir")
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "GOOD.hive"), "wb") as fh:
            fh.write(make_hive(art_spec()))
        with open(os.path.join(d, "TINY.hive"), "wb") as fh:
            fh.write(make_hive({"name": "ROOT"}))
        with open(os.path.join(d, "Amcache.hve.LOG1"), "wb") as fh:
            fh.write(b"HvLE" + b"\x00" * 100)
        with open(os.path.join(d, "collect_reg.json"), "w", encoding="utf-8") as fh:
            fh.write("{}")
        jsonl_path = self._path("dir.jsonl")
        report_path = self._path("dir_report.json")
        proc = self._run(d, "--jsonl", jsonl_path, "--report", report_path)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        with open(report_path, encoding="utf-8") as fh:
            report = json.load(fh)
        self.assertEqual(report["counts"]["hives"], 2)
        self.assertEqual(report["counts"]["parsed"], 2)
        self.assertTrue(any("no supported registry artifact" in e["error"] for e in report["errors"]))

    def test_cli_list_prints_key_tree(self):
        hive_path = write_tmp(make_hive(art_spec()), ".hive")
        proc = self._run(hive_path, "--jsonl", self._path("list.jsonl"), "--quiet", "--list", "ControlSet001")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("ControlSet001", proc.stdout)
        self.assertIn("Services", proc.stdout)

    def test_cli_quiet_suppresses_summary(self):
        hive_path = write_tmp(make_hive(art_spec()), ".hive")
        proc = self._run(hive_path, "--jsonl", self._path("q.jsonl"), "--quiet")
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(proc.stderr.strip(), "")


if __name__ == "__main__":
    unittest.main()
