import json
import os
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
TOOLS_DIR = os.path.join(os.path.dirname(TESTS_DIR), "tools")
sys.path.insert(0, TOOLS_DIR)

import collect  # noqa: E402

COLLECT = os.path.join(TOOLS_DIR, "collect.py")


def build_synthetic_volume(path, runlist_bytes=None):
    """Fake NTFS volume image: 512-byte sectors, 8 sectors/cluster, 1024-byte records.

    $MFT record 0 lives at LCN 4 and carries a non-resident unnamed $DATA whose
    runs point at pattern areas. Returns (expected_stream, lcn_map).
    """
    sector = 512
    cluster = 4096
    mft_lcn = 4
    mft_start = mft_lcn * cluster
    record_size = 1024

    if runlist_bytes is None:
        # run 1: LCN 8, 2 clusters; run 2: LCN 16, 1 cluster
        runlist_bytes = bytes([0x11, 2, 8, 0x11, 1, 8, 0])
        total_clusters = 3
    else:
        total_clusters = None

    record = bytearray(record_size)
    record[0:4] = b"FILE"
    struct.pack_into("<HH", record, 0x04, 0x30, 3)  # usa offset/count
    struct.pack_into("<H", record, 0x10, 1)  # sequence
    struct.pack_into("<HH", record, 0x12, 1, 0x38)  # hardlinks, first attr
    struct.pack_into("<H", record, 0x16, 1)  # in use
    struct.pack_into("<I", record, 0x1C, record_size)
    struct.pack_into("<H", record, 0x28, 2)

    attr_off = 0x38
    runlist_at = attr_off + 64
    attr_len = 64 + len(runlist_bytes)
    attr_len += (-attr_len) % 8
    struct.pack_into("<II", record, attr_off, 0x80, attr_len)
    record[attr_off + 8] = 1  # non-resident
    struct.pack_into("<QQ", record, attr_off + 16, 0, (total_clusters - 1) if total_clusters else 1)
    struct.pack_into("<H", record, attr_off + 32, 64)  # runs offset
    struct.pack_into("<QQQ", record, attr_off + 40, 0x1000, 0x1000, 0x1000)
    record[runlist_at : runlist_at + len(runlist_bytes)] = runlist_bytes
    struct.pack_into("<I", record, attr_off + attr_len, 0xFFFFFFFF)
    used = attr_off + attr_len + 4
    struct.pack_into("<I", record, 0x18, used)

    struct.pack_into("<H", record, 0x30, 0x0001)  # update sequence number
    struct.pack_into("<HH", record, 0x32, 0, 0)  # original tails
    struct.pack_into("<H", record, 510, 0x0001)
    struct.pack_into("<H", record, 1022, 0x0001)

    boot = bytearray(sector)
    boot[3:11] = b"NTFS    "
    struct.pack_into("<H", boot, 0x0B, sector)
    boot[0x0D] = cluster // sector
    struct.pack_into("<Q", boot, 0x30, mft_lcn)
    boot[0x40] = 0xF6  # signed -10 -> 1024-byte records

    a_area = b"A" * (2 * cluster)
    b_area = b"B" * cluster
    size = 17 * cluster
    image = bytearray(size)
    image[0:sector] = boot
    image[mft_start : mft_start + record_size] = record
    image[8 * cluster : 10 * cluster] = a_area
    image[16 * cluster : 17 * cluster] = b_area
    with open(path, "wb") as fh:
        fh.write(image)
    return a_area + b_area, {"cluster": cluster, "mft_start": mft_start, "record_size": record_size}


def _file_record(record_size, attrs):
    record = bytearray(record_size)
    record[0:4] = b"FILE"
    struct.pack_into("<HH", record, 0x04, 0x30, 3)
    struct.pack_into("<H", record, 0x10, 1)
    struct.pack_into("<HH", record, 0x12, 1, 0x38)
    struct.pack_into("<H", record, 0x16, 1)
    struct.pack_into("<I", record, 0x1C, record_size)
    off = 0x38
    for attr in attrs:
        record[off : off + len(attr)] = attr
        off += len(attr)
    struct.pack_into("<I", record, off, 0xFFFFFFFF)
    struct.pack_into("<I", record, 0x18, off + 4)
    struct.pack_into("<H", record, 0x30, 0x0001)
    struct.pack_into("<HH", record, 0x32, 0, 0)
    struct.pack_into("<H", record, 510, 0x0001)
    struct.pack_into("<H", record, 1022, 0x0001)
    return bytes(record)


def _data_attr(runlist, lowest_vcn, alloc, real):
    attr_len = 64 + len(runlist)
    attr_len += (-attr_len) % 8
    attr = bytearray(attr_len)
    struct.pack_into("<II", attr, 0, 0x80, attr_len)
    attr[8] = 1
    struct.pack_into("<QQ", attr, 16, lowest_vcn, lowest_vcn + 1)
    struct.pack_into("<H", attr, 32, 64)
    struct.pack_into("<QQQ", attr, 40, alloc, real, real)
    attr[64 : 64 + len(runlist)] = runlist
    return bytes(attr)


def _attribute_list_entry(atype, lowest_vcn, record_number, sequence=1):
    entry = bytearray(32)
    struct.pack_into("<IH", entry, 0, atype, 32)
    struct.pack_into("<Q", entry, 8, lowest_vcn)
    struct.pack_into("<Q", entry, 16, record_number | (sequence << 48))
    return bytes(entry)


def _resident_attr_list(content):
    attr_len = 24 + len(content)
    attr_len += (-attr_len) % 8
    attr = bytearray(attr_len)
    struct.pack_into("<II", attr, 0, 0x20, attr_len)
    struct.pack_into("<I", attr, 16, len(content))
    struct.pack_into("<H", attr, 20, 24)
    attr[24 : 24 + len(content)] = content
    return bytes(attr)


def _nonresident_attr_list(runlist, size):
    attr_len = 64 + len(runlist)
    attr_len += (-attr_len) % 8
    attr = bytearray(attr_len)
    struct.pack_into("<II", attr, 0, 0x20, attr_len)
    attr[8] = 1
    struct.pack_into("<QQ", attr, 16, 0, 0)
    struct.pack_into("<H", attr, 32, 64)
    struct.pack_into("<QQQ", attr, 40, size, size, size)
    attr[64 : 64 + len(runlist)] = runlist
    return bytes(attr)


def build_synthetic_volume_attrlist(path, nonresident_list=False, extension_record=5):
    """Volume whose $MFT $DATA runlist is split via $ATTRIBUTE_LIST.

    Base fragment: LCN 8, 2 clusters ("A" area). Extension record N carries the
    second fragment: LCN 16, 1 cluster ("B" area). Declared total: 3 clusters.
    """
    sector = 512
    cluster = 4096
    mft_lcn = 4
    mft_start = mft_lcn * cluster
    record_size = 1024

    base_runlist = bytes([0x11, 2, 8, 0])
    ext_runlist = bytes([0x11, 1, 16, 0])
    total_bytes = 3 * cluster

    entries = _attribute_list_entry(0x80, 0, 0) + _attribute_list_entry(0x80, 2, extension_record)
    if nonresident_list:
        list_runlist = bytes([0x11, 1, 24, 0])
        attrs = [
            _nonresident_attr_list(list_runlist, len(entries)),
            _data_attr(base_runlist, 0, total_bytes, total_bytes),
        ]
    else:
        attrs = [
            _resident_attr_list(entries),
            _data_attr(base_runlist, 0, total_bytes, total_bytes),
        ]
    record0 = _file_record(record_size, attrs)
    ext_record = _file_record(record_size, [_data_attr(ext_runlist, 2, cluster, cluster)])

    a_area = bytearray(b"A" * (2 * cluster))
    b_area = b"B" * cluster
    ext_stream_off = extension_record * record_size
    if ext_stream_off + record_size <= len(a_area):
        # extension records live inside the $MFT stream itself: splice it in
        a_area[ext_stream_off : ext_stream_off + record_size] = ext_record
    image = bytearray(26 * cluster)
    boot = bytearray(sector)
    boot[3:11] = b"NTFS    "
    struct.pack_into("<H", boot, 0x0B, sector)
    boot[0x0D] = cluster // sector
    struct.pack_into("<Q", boot, 0x30, mft_lcn)
    boot[0x40] = 0xF6
    image[0:sector] = boot
    image[mft_start : mft_start + record_size] = record0
    image[8 * cluster : 10 * cluster] = a_area
    image[16 * cluster : 17 * cluster] = b_area
    image[24 * cluster : 24 * cluster + len(entries)] = entries
    with open(path, "wb") as fh:
        fh.write(image)
    return bytes(a_area) + b_area, {"cluster": cluster, "mft_start": mft_start, "record_size": record_size}


class SyntheticVolumeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = self.tmp.name

    def tearDown(self):
        self.tmp.cleanup()

    def test_extract_mft_stream_synthetic(self):
        vol = os.path.join(self.dir, "volume.img")
        expected, info = build_synthetic_volume(vol)
        out = os.path.join(self.dir, "mft.bin")
        meta = collect.extract_mft_stream(vol, out)
        with open(out, "rb") as fh:
            data = fh.read()
        self.assertEqual(data, expected)
        self.assertEqual(meta["mft_total_bytes"], 3 * info["cluster"])
        self.assertEqual(meta["mft_bytes_written"], 3 * info["cluster"])
        self.assertEqual(meta["mft_run_count"], 2)
        self.assertFalse(meta["mft_truncated"])
        self.assertEqual(meta["record_size"], 1024)

    def test_extract_mft_truncates_on_max_bytes(self):
        vol = os.path.join(self.dir, "volume.img")
        build_synthetic_volume(vol)
        out = os.path.join(self.dir, "mft.bin")
        meta = collect.extract_mft_stream(vol, out, max_bytes=5000)
        with open(out, "rb") as fh:
            data = fh.read()
        self.assertEqual(len(data), 5000)
        self.assertTrue(meta["mft_truncated"])
        self.assertEqual(meta["mft_bytes_written"], 5000)

    def test_extract_mft_rejects_sparse_run(self):
        vol = os.path.join(self.dir, "volume.img")
        # sparse run first (no LCN), then normal run
        build_synthetic_volume(vol, runlist_bytes=bytes([0x01, 1, 0x11, 1, 16, 0]))
        out = os.path.join(self.dir, "mft.bin")
        with self.assertRaises(collect.CollectError) as ctx:
            collect.extract_mft_stream(vol, out)
        self.assertIn("sparse", str(ctx.exception))

    def test_extract_mft_follows_resident_attribute_list(self):
        vol = os.path.join(self.dir, "volume.img")
        expected, info = build_synthetic_volume_attrlist(vol)
        out = os.path.join(self.dir, "mft.bin")
        meta = collect.extract_mft_stream(vol, out)
        with open(out, "rb") as fh:
            self.assertEqual(fh.read(), expected)
        self.assertEqual(meta["mft_total_bytes"], 3 * info["cluster"])
        self.assertEqual(meta["mft_bytes_written"], 3 * info["cluster"])
        self.assertEqual(meta["mft_run_count"], 2)
        self.assertTrue(meta["mft_attribute_list"])
        self.assertEqual(meta["mft_extension_records"], 1)
        self.assertEqual(meta["mft_fragment_count"], 2)
        self.assertEqual(meta["mft_data_allocated_bytes"], 3 * info["cluster"])
        self.assertFalse(any("run_total_bytes" in w for w in meta["mft_run_warnings"]))

    def test_extract_mft_follows_nonresident_attribute_list(self):
        vol = os.path.join(self.dir, "volume.img")
        expected, info = build_synthetic_volume_attrlist(vol, nonresident_list=True)
        out = os.path.join(self.dir, "mft.bin")
        meta = collect.extract_mft_stream(vol, out)
        with open(out, "rb") as fh:
            self.assertEqual(fh.read(), expected)
        self.assertEqual(meta["mft_total_bytes"], 3 * info["cluster"])
        self.assertTrue(meta["mft_attribute_list"])
        self.assertEqual(meta["mft_extension_records"], 1)

    def test_extract_mft_attribute_list_extension_unreachable(self):
        vol = os.path.join(self.dir, "volume.img")
        # extension record 40 - its bytes would live far beyond the known base runs
        build_synthetic_volume_attrlist(vol, extension_record=40)
        out = os.path.join(self.dir, "mft.bin")
        with self.assertRaises(collect.CollectError) as ctx:
            collect.extract_mft_stream(vol, out)
        self.assertIn("outside the known", str(ctx.exception))

    def test_parse_boot_sector_rejects_non_ntfs(self):
        boot = b"\x00" * 512
        with self.assertRaises(collect.CollectError):
            collect.parse_boot_sector(boot)

    def test_read_exact_short_read(self):
        path = os.path.join(self.dir, "short.bin")
        with open(path, "wb") as fh:
            fh.write(b"x" * 600)
        with open(path, "rb") as fh:
            with self.assertRaises(collect.CollectError):
                collect.read_exact(fh, 0, 1024, 512)
            self.assertEqual(collect.read_exact(fh, 0, 100, 512), b"x" * 100)


class UsnCaptureTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = self.tmp.name

    def tearDown(self):
        self.tmp.cleanup()

    def test_capture_with_fake_io(self):
        calls = {"n": 0}

        def fake_open(volume):
            return "handle"

        def fake_close(handle):
            calls["closed"] = True

        def fake_query(handle):
            return {"journal_id": 5, "first_usn": 10, "next_usn": 99}

        def fake_io(handle, code, in_bytes, out_size):
            calls["n"] += 1
            if calls["n"] == 1:
                current = struct.unpack_from("<Q", in_bytes, 0)[0]
                self.assertEqual(current, 10)
                return struct.pack("<Q", 20) + b"RECORD-A"
            if calls["n"] == 2:
                return struct.pack("<Q", 30) + b"RECORD-B"
            return struct.pack("<Q", 30)

        out = os.path.join(self.dir, "usn.bin")
        meta = collect.capture_usn_journal(
            "C:", out, open_fn=fake_open, close_fn=fake_close, io_fn=fake_io, query_fn=fake_query
        )
        with open(out, "rb") as fh:
            self.assertEqual(fh.read(), b"RECORD-ARECORD-B")
        self.assertEqual(meta["iterations"], 3)
        self.assertEqual(meta["records_bytes_written"], 2 * 8)
        self.assertEqual(meta["last_usn"], 30)
        self.assertTrue(calls["closed"])
        self.assertIn("FSCTL_READ_USN_JOURNAL", meta["note"])


class HelperTests(unittest.TestCase):
    def test_wevtutil_commands(self):
        self.assertEqual(collect.wevtutil_qe_command("Security"), ["wevtutil", "qe", "Security", "/f:xml", "/rd:false"])
        self.assertEqual(
            collect.wevtutil_epl_command("System", "out.evtx"), ["wevtutil", "epl", "System", "out.evtx", "/ow:true"]
        )

    def test_safe_channel_name(self):
        self.assertEqual(collect.safe_channel_name("Microsoft-Windows-TaskScheduler/Operational"), "Microsoft-Windows-TaskScheduler_Operational")
        self.assertEqual(collect.safe_channel_name("System"), "System")

    def test_elevation_gate(self):
        self.assertEqual(collect.elevation_gate(True, True), (True, "requested (--skip flag)"))
        self.assertEqual(collect.elevation_gate(False, False), (True, "not elevated"))
        self.assertEqual(collect.elevation_gate(False, True), (False, None))

    def test_is_elevated_returns_bool(self):
        self.assertIsInstance(collect.is_elevated(), bool)

    def test_machine_info_shape(self):
        info = collect.machine_info("C:")
        self.assertIn("windows", info)
        self.assertIn("product_name", info["windows"])
        self.assertIn("volume", info)
        self.assertEqual(info["volume"]["letter"], "C:")
        json.dumps(info)  # must be JSON-native

    def test_volume_info_c_is_ntfs(self):
        info = collect.volume_info("C:")
        self.assertEqual(info.get("file_system"), "NTFS")
        self.assertGreater(info.get("total_bytes", 0), 0)


class CollectCliTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = self.tmp.name
        self.case = os.path.join(self.dir, "case")

    def tearDown(self):
        self.tmp.cleanup()

    def read_manifest(self):
        with open(os.path.join(self.case, "manifest.json"), encoding="utf-8") as fh:
            return json.load(fh)

    def run_all_skipped(self, *extra):
        rc = collect.main(
            [
                "--case",
                self.case,
                "--skip-registry",
                "--skip-prefetch",
                "--skip-evtx",
                "--skip-mft",
                "--skip-usn",
                "--quiet",
            ]
            + list(extra)
        )
        self.assertEqual(rc, 0)
        return self.read_manifest()

    def test_all_skipped_manifest_shape(self):
        manifest = self.run_all_skipped()
        self.assertEqual(manifest["tool"], "collect")
        self.assertEqual(manifest["schema_version"], 1)
        self.assertEqual(manifest["case"], "case")
        self.assertEqual(manifest["volume"], "C:")
        machine_step = next(s for s in manifest["steps"] if s["step"] == "machine_info")
        self.assertEqual(machine_step["status"], "ok")
        for step in manifest["steps"]:
            self.assertIn("started_at", step)
            self.assertIn("finished_at", step)
            self.assertIn("notes", step)
            if step["step"] != "machine_info":
                self.assertEqual(step["status"], "skipped")
                self.assertIn("requested", step["reason"])
        self.assertEqual(len(manifest["steps"]), 6)
        self.assertEqual(manifest["counts"]["files"], 1)
        file_entry = manifest["files"][0]
        self.assertEqual(file_entry["path"], "machine_info.json")
        self.assertEqual(len(file_entry["sha256"]), 64)
        self.assertEqual(file_entry["step"], "machine_info")
        self.assertIn("not_elevated", manifest["warnings"])

    def test_no_hash_records_null_and_warns(self):
        manifest = self.run_all_skipped("--no-hash")
        self.assertIsNone(manifest["files"][0]["sha256"])
        self.assertIn("hashes_skipped", manifest["warnings"])

    def test_nonempty_case_directory_is_rejected_without_overwriting(self):
        os.makedirs(self.case)
        marker = os.path.join(self.case, "keep.txt")
        with open(marker, "w", encoding="utf-8") as fh:
            fh.write("existing evidence")
        rc = collect.main(["--case", self.case, "--quiet"])
        self.assertEqual(rc, 1)
        with open(marker, encoding="utf-8") as fh:
            self.assertEqual(fh.read(), "existing evidence")
        self.assertFalse(os.path.exists(os.path.join(self.case, "manifest.json")))

    def test_manifest_steps_match_schema_contract(self):
        manifest = self.run_all_skipped()
        schema_path = os.path.join(os.path.dirname(TOOLS_DIR), "schemas", "collect_manifest.schema.json")
        with open(schema_path, encoding="utf-8") as fh:
            schema = json.load(fh)
        step_schema = schema["properties"]["steps"]
        self.assertEqual(len(manifest["steps"]), step_schema["minItems"])
        required = set(step_schema["items"]["required"])
        allowed_steps = set(step_schema["items"]["properties"]["step"]["enum"])
        for step in manifest["steps"]:
            self.assertTrue(required.issubset(step))
            self.assertIn(step["step"], allowed_steps)

    def test_prefetch_copy_with_fake_dir(self):
        pf_dir = os.path.join(self.dir, "fake_prefetch")
        os.makedirs(pf_dir)
        for name in ("ALPHA.EXE-11111111.pf", "BETA.EXE-22222222.pf"):
            with open(os.path.join(pf_dir, name), "wb") as fh:
                fh.write(b"MAM\x04" + b"\x00" * 100)
        with open(os.path.join(pf_dir, "Layout.ini"), "w", encoding="utf-8") as fh:
            fh.write("junk")
        manifest = self.run_all_skipped("--prefetch-dir", pf_dir, "--skip-prefetch", "--no-hash")
        # now run for real (prefetch only)
        case2 = os.path.join(self.dir, "case2")
        rc = collect.main(
            [
                "--case",
                case2,
                "--skip-registry",
                "--skip-evtx",
                "--skip-mft",
                "--skip-usn",
                "--prefetch-dir",
                pf_dir,
                "--quiet",
            ]
        )
        self.assertEqual(rc, 0)
        with open(os.path.join(case2, "manifest.json"), encoding="utf-8") as fh:
            manifest = json.load(fh)
        step = next(s for s in manifest["steps"] if s["step"] == "prefetch")
        self.assertEqual(step["status"], "ok")
        pf_entries = [f for f in manifest["files"] if f["step"] == "prefetch"]
        self.assertEqual(len(pf_entries), 2)
        self.assertEqual(len(pf_entries[0]["sha256"]), 64)
        self.assertTrue(pf_entries[0]["source"].startswith(pf_dir))
        self.assertFalse(any(f["path"].endswith("Layout.ini") for f in manifest["files"]))

    def test_prefetch_missing_dir_marks_step_failed(self):
        rc = collect.main(
            [
                "--case",
                self.case,
                "--skip-registry",
                "--skip-evtx",
                "--skip-mft",
                "--skip-usn",
                "--prefetch-dir",
                os.path.join(self.dir, "nope"),
                "--quiet",
            ]
        )
        self.assertEqual(rc, 0)
        manifest = self.read_manifest()
        step = next(s for s in manifest["steps"] if s["step"] == "prefetch")
        self.assertEqual(step["status"], "failed")
        self.assertIn("not found", step["error"])
        self.assertEqual(manifest["errors"][0]["step"], "prefetch")

    def test_prefetch_copy_errors_mark_step_partial(self):
        pf_dir = os.path.join(self.dir, "fake_prefetch")
        os.makedirs(pf_dir)
        with open(os.path.join(pf_dir, "ALPHA.EXE-11111111.pf"), "wb") as fh:
            fh.write(b"MAM\x04" + b"\x00" * 100)
        with mock.patch.object(collect.shutil, "copy2", side_effect=OSError("copy denied")):
            rc = collect.main(
                ["--case", self.case, "--skip-registry", "--skip-evtx", "--skip-mft",
                 "--skip-usn", "--prefetch-dir", pf_dir, "--quiet"]
            )
        self.assertEqual(rc, 0)
        manifest = self.read_manifest()
        step = next(s for s in manifest["steps"] if s["step"] == "prefetch")
        self.assertEqual(step["status"], "partial")
        self.assertTrue(any(e["step"] == "prefetch" for e in manifest["errors"]))

    def test_registry_step_requires_elevation_or_skip(self):
        manifest = self.run_all_skipped()
        step = next(s for s in manifest["steps"] if s["step"] == "registry")
        self.assertEqual(step["status"], "skipped")

    def test_usage_errors(self):
        with self.assertRaises(SystemExit):
            collect.main([])
        with self.assertRaises(SystemExit):
            collect.main(["--case", self.case, "--mft-max-bytes", "0", "--quiet"])
        with self.assertRaises(SystemExit):
            collect.main(["--case", self.case, "--channels", " ", "--quiet"])

    def test_cli_end_to_end(self):
        proc = subprocess.run(
            [
                sys.executable,
                COLLECT,
                "--case",
                self.case,
                "--skip-registry",
                "--skip-prefetch",
                "--skip-evtx",
                "--skip-mft",
                "--skip-usn",
            ],
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("files=1", proc.stderr)
        self.assertTrue(os.path.isfile(os.path.join(self.case, "manifest.json")))
        self.assertTrue(os.path.isfile(os.path.join(self.case, "machine_info.json")))


if __name__ == "__main__":
    unittest.main()
