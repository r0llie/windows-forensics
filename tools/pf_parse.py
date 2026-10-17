#!/usr/bin/env python3
"""pf_parse.py — honest parser for Windows Prefetch (.pf) files.

Reads a captured .pf file (raw SCCA container or Windows 10+ MAM/XPRESS-Huffman
container) and emits one newline-delimited JSON record conforming to
schemas/pf.schema.json plus a machine-readable report
(schemas/pf_report.schema.json).

Honesty contract (see SKILL.md "The golden rule"):
  * decompression failures and structural problems are declared, never patched
  * section offsets are validated before use; anything unparseable is reported
  * prefetch hash / executable-name vs filename comparisons are observations only
  * run times are FILETIME UTC, converted as-is
  * absence of a .pf file proves nothing (references/prefetch.md section 10)

Structure knowledge: references/prefetch.md — read it before interpreting output.

Usage:
    python tools/pf_parse.py C:\\Windows\\Prefetch\\NOTEPAD.EXE-*.pf --report report.json
    python tools/pf_parse.py C:\\Windows\\Prefetch --min-runs 5 --jsonl out.jsonl
    python tools/pf_parse.py sample.pf --raw --extract-dir extracted

Exit codes: 0 success (even with per-file failures, which are recorded in the
report), 1 fatal error, 2 usage error.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import struct
import sys
from datetime import datetime, timedelta, timezone

TOOL_VERSION = "0.1.0"
SCHEMA_VERSION = 1

MAM_MAGIC = b"MAM"
MAM_SIGNATURE_BYTES = (0x04, 0x84)
SCCA_MAGIC = b"SCCA"

VALID_VERSIONS = (17, 23, 26, 30, 31)
FILE_INFO_OFFSET = 0x54
METRICS_OFFSET_BY_VERSION = {17: 0x98, 23: 0xF0, 26: 0x130, 31: 0x128}
V30_VARIANT1_METRICS_OFFSET = 0x130
V30_VARIANT2_METRICS_OFFSET = 0x128

METRIC_ENTRY_SIZE = {17: 20, 23: 32, 26: 32, 30: 32, 31: 32}
TRACE_CHAIN_ENTRY_SIZE = {17: 12, 23: 12, 26: 12, 30: 8, 31: 8}
VOLUME_ENTRY_SIZE = {17: 40, 23: 104, 26: 104, 30: 96, 31: 96}

MAX_UNCOMPRESSED_SIZE = 256 * 1024 * 1024
MAX_METRICS = 100_000
MAX_TRACE_CHAINS = 1_000_000
MAX_VOLUMES = 64
MAX_FILE_REFERENCES = 100_000
MAX_DIRECTORY_STRINGS = 100_000

METRIC_FLAG_NAMES = {0x1: "do_not_prefetch", 0x2: "load_as_resource", 0x200: "load_as_executable"}
TRACE_FLAG_NAMES = {0x1: "do_not_prefetch", 0x2: "load_as_executable", 0x4: "load_as_resource", 0x8: "must_be_prefetched"}

XPRESS_TABLE_ENTRIES = 1 << 15
XPRESS_BLOCK_OUTPUT = 65536

_FILENAME_RE = re.compile(r"^(?P<exe>.+)-(?P<hash>[0-9A-Fa-f]{8})(?:-(?P<suffix>[0-9A-Fa-f]+))?\.pf$", re.IGNORECASE)

_FT_EPOCH = datetime(1601, 1, 1)


class PfParseError(RuntimeError):
    pass


class XpressError(PfParseError):
    pass


def filetime_to_iso(ft):
    if not ft:
        return None
    try:
        dt = _FT_EPOCH + timedelta(microseconds=ft // 10)
        return dt.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"
    except (OverflowError, OSError, ValueError):
        return None


def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# XPRESS Huffman (MS-XCA) decompression
# ---------------------------------------------------------------------------


def build_huffman_table(table_bytes):
    """Canonical decode table per MS-XCA 2.2.4: sort by (bit length, symbol)."""
    if len(table_bytes) != 256:
        raise XpressError("Huffman table not 256 bytes")
    lengths = [0] * 512
    for i, byte in enumerate(table_bytes):
        lengths[2 * i] = byte & 0x0F
        lengths[2 * i + 1] = byte >> 4
    symbols = [0] * XPRESS_TABLE_ENTRIES
    index = 0
    for bit_length in range(1, 16):
        for symbol in range(512):
            if lengths[symbol] == bit_length:
                count = 1 << (15 - bit_length)
                if index + count > XPRESS_TABLE_ENTRIES:
                    raise XpressError("Huffman table overflow (invalid code lengths)")
                symbols[index : index + count] = [symbol] * count
                index += count
    if index != XPRESS_TABLE_ENTRIES:
        raise XpressError("Huffman table does not fill 2^15 entries (invalid code lengths)")
    return symbols, lengths


def decompress_xpress_huffman(data, expected_size):
    """Decompress an XPRESS-Huffman stream (MS-XCA) to exactly expected_size bytes.

    Faithful to the MS-XCA 2.2.4 pseudocode: 16-bit little-endian chunks in a
    32-bit register consumed MSB-first, one 256-byte canonical Huffman table per
    block, blocks expanding to up to 65536 output bytes, byte-aligned extended
    match lengths, one-byte-at-a-time overlapping copies.

    There is NO end-of-stream symbol: symbol 256 is a legal match (length 3,
    offset 1, i.e. "repeat last byte 3x"). Treating it as EOS corrupts
    multi-chunk streams (see references/prefetch.md, Agent Traps).
    """
    if expected_size < 0 or expected_size > MAX_UNCOMPRESSED_SIZE:
        raise XpressError("implausible uncompressed size: %d" % expected_size)
    out = bytearray()
    pos = 0
    n = len(data)
    while len(out) < expected_size:
        if n - pos < 256:
            raise XpressError("compressed data too small for a Huffman table at offset %d" % pos)
        symbols, lengths = build_huffman_table(data[pos : pos + 256])
        pos += 256
        if pos + 4 > n:
            raise XpressError("compressed data too small for bit stream at offset %d" % pos)
        word0 = int.from_bytes(data[pos : pos + 2], "little")
        word1 = int.from_bytes(data[pos + 2 : pos + 4], "little")
        nextbits = (word0 << 16) | word1
        pos += 4
        bits = 32
        boundary = min(len(out) + XPRESS_BLOCK_OUTPUT, expected_size)
        while len(out) < boundary:
            symbol = symbols[nextbits >> 17]
            code_length = lengths[symbol]
            nextbits = (nextbits << code_length) & 0xFFFFFFFF
            bits -= code_length
            if bits < 16:
                if pos + 2 > n:
                    raise XpressError("truncated bit stream at offset %d" % pos)
                nextbits |= int.from_bytes(data[pos : pos + 2], "little") << (16 - bits)
                bits += 16
                pos += 2
            if symbol < 256:
                out.append(symbol)
                continue
            value = symbol - 256
            match_length = value & 0x0F
            offset_bits = value >> 4
            if match_length == 15:
                if pos >= n:
                    raise XpressError("truncated extended match length at offset %d" % pos)
                match_length = data[pos]
                pos += 1
                if match_length == 255:
                    if pos + 2 > n:
                        raise XpressError("truncated extended match length at offset %d" % pos)
                    match_length = int.from_bytes(data[pos : pos + 2], "little")
                    pos += 2
                    if match_length < 15:
                        raise XpressError("invalid extended match length %d" % match_length)
                else:
                    match_length += 15
            match_length += 3
            if offset_bits:
                raw_offset = nextbits >> (32 - offset_bits)
                nextbits = (nextbits << offset_bits) & 0xFFFFFFFF
                bits -= offset_bits
            else:
                raw_offset = 0
            match_offset = raw_offset + (1 << offset_bits)
            if bits < 16:
                if pos + 2 > n:
                    raise XpressError("truncated bit stream at offset %d" % pos)
                nextbits |= int.from_bytes(data[pos : pos + 2], "little") << (16 - bits)
                bits += 16
                pos += 2
            if match_offset > len(out):
                raise XpressError("match offset %d out of range at output %d" % (match_offset, len(out)))
            if len(out) + match_length > expected_size:
                raise XpressError("match overruns expected output size")
            for _ in range(match_length):
                out.append(out[-match_offset])
    if len(out) != expected_size:
        raise XpressError("decompressed size mismatch")
    return bytes(out)


def unwrap_container(data):
    """Return (container_name, payload, declared_size)."""
    if data[:3] == MAM_MAGIC and len(data) >= 8 and data[3] in MAM_SIGNATURE_BYTES:
        declared = int.from_bytes(data[4:8], "little")
        payload = decompress_xpress_huffman(data[8:], declared)
        return "mam_xpress_huffman", payload, declared
    return "raw_scca", data, None


# ---------------------------------------------------------------------------
# Prefetch structure parsing
# ---------------------------------------------------------------------------


def parse_filename_parts(basename):
    match = _FILENAME_RE.match(basename)
    if not match:
        return {"executable": None, "hash": None, "hash_suffix": None}
    return {
        "executable": match.group("exe"),
        "hash": match.group("hash").upper(),
        "hash_suffix": match.group("suffix").upper() if match.group("suffix") else None,
    }


def read_utf16(buf, offset, chars, warnings=None, reason=None):
    size = chars * 2
    if offset < 0 or offset + size > len(buf):
        if warnings is not None and reason:
            warnings.append(reason)
        return None
    return buf[offset : offset + size].decode("utf-16-le", "replace")


def parse_pf_payload(payload, warnings):
    size = len(payload)
    if size < 84:
        raise PfParseError("file smaller than the 84-byte header (%d bytes)" % size)

    version = struct.unpack_from("<I", payload, 0)[0]
    if version not in VALID_VERSIONS:
        raise PfParseError("unsupported format version %d" % version)
    if payload[4:8] != SCCA_MAGIC:
        raise PfParseError("missing SCCA signature at offset 4")

    header = {
        "format_version": version,
        "signature": payload[4:8].decode("ascii", "replace"),
        "unknown_0x08": struct.unpack_from("<I", payload, 8)[0],
        "file_size": struct.unpack_from("<I", payload, 12)[0],
        "executable": payload[16:76].decode("utf-16-le", "replace").split("\x00", 1)[0],
        "prefetch_hash": struct.unpack_from("<I", payload, 76)[0],
        "flags": struct.unpack_from("<I", payload, 80)[0],
    }

    info = {"file_information_offset": FILE_INFO_OFFSET}
    (
        info["metrics_offset"],
        info["metrics_count"],
        info["trace_chains_offset"],
        info["trace_chains_count"],
        info["filename_strings_offset"],
        info["filename_strings_size"],
        info["volumes_offset"],
        info["volumes_count"],
        info["volumes_size"],
    ) = struct.unpack_from("<9I", payload, FILE_INFO_OFFSET)

    expected_metrics_offset = METRICS_OFFSET_BY_VERSION.get(version)
    layout_variant = None
    if version == 30:
        if info["metrics_offset"] == V30_VARIANT1_METRICS_OFFSET:
            layout_variant = 1
        elif info["metrics_offset"] == V30_VARIANT2_METRICS_OFFSET:
            layout_variant = 2
        else:
            warnings.append("unknown_file_information_layout")
    elif version == 31:
        layout_variant = 2
        warnings.append("version_31_layout_assumed_from_v30_variant_2")
    if expected_metrics_offset is not None and version != 30 and info["metrics_offset"] != expected_metrics_offset:
        warnings.append("metrics_offset_unexpected_value")

    base = FILE_INFO_OFFSET
    run_times = []
    unknown_string = None
    if version == 17:
        last_run = struct.unpack_from("<Q", payload, base + 36)[0]
        run_count = struct.unpack_from("<I", payload, base + 60)[0]
        if last_run:
            run_times = [last_run]
    elif version == 23:
        last_run = struct.unpack_from("<Q", payload, base + 44)[0]
        run_count = struct.unpack_from("<I", payload, base + 68)[0]
        if last_run:
            run_times = [last_run]
    elif version == 26:
        run_times = [t for t in struct.unpack_from("<8Q", payload, base + 44) if t]
        run_count = struct.unpack_from("<I", payload, base + 124)[0]
    elif version == 30 and layout_variant == 1:
        run_times = [t for t in struct.unpack_from("<8Q", payload, base + 44) if t]
        run_count = struct.unpack_from("<I", payload, base + 124)[0]
        us_offset, us_size = struct.unpack_from("<II", payload, base + 136)
        info["unknown_string_offset"] = us_offset
        info["unknown_string_size"] = us_size
        unknown_string = read_utf16(payload, us_offset, us_size // 2, warnings, "unknown_string_out_of_range")
    else:
        run_times = [t for t in struct.unpack_from("<8Q", payload, base + 44) if t]
        run_count = struct.unpack_from("<I", payload, base + 116)[0]
        us_offset, us_size = struct.unpack_from("<II", payload, base + 128)
        info["unknown_string_offset"] = us_offset
        info["unknown_string_size"] = us_size
        unknown_string = read_utf16(payload, us_offset, us_size // 2, warnings, "unknown_string_out_of_range")
    if unknown_string is not None:
        unknown_string = unknown_string.split("\x00", 1)[0]
    if run_count == 0:
        warnings.append("run_count_zero")
    if not run_times:
        warnings.append("no_run_times")

    info["layout_variant"] = layout_variant
    info["run_count"] = run_count
    if unknown_string:
        info["unknown_string"] = unknown_string

    if info["filename_strings_offset"] + info["filename_strings_size"] > size:
        warnings.append("filename_strings_section_out_of_range")

    metrics = parse_metrics(payload, version, info, warnings)
    trace_chains = parse_trace_chains(payload, version, info, warnings)
    volumes = parse_volumes(payload, version, info, warnings)

    return {
        "header": header,
        "file_information": info,
        "run_count": run_count,
        "run_times_filetime": run_times,
        "unknown_string": unknown_string,
        "metrics": metrics,
        "trace_chains": trace_chains,
        "volumes": volumes,
    }


def parse_metrics(payload, version, info, warnings):
    entry_size = METRIC_ENTRY_SIZE[version]
    offset = info["metrics_offset"]
    count = info["metrics_count"]
    metrics = []
    if offset + count * entry_size > len(payload) or count > MAX_METRICS:
        warnings.append("metrics_array_out_of_range")
        return metrics
    strings_start = info["filename_strings_offset"]
    strings_end = strings_start + info["filename_strings_size"]
    for i in range(count):
        entry_offset = offset + i * entry_size
        trace_chain_index, trace_entries = struct.unpack_from("<II", payload, entry_offset)
        if entry_size == 20:
            name_offset, name_chars, flags = struct.unpack_from("<III", payload, entry_offset + 8)
            file_reference = None
            blocks_to_prefetch = None
        else:
            blocks_to_prefetch, name_offset, name_chars, flags = struct.unpack_from("<IIII", payload, entry_offset + 8)
            ref_raw = payload[entry_offset + 24 : entry_offset + 32]
            file_reference = "0x%016x" % (int.from_bytes(ref_raw[:6], "little") | (int.from_bytes(ref_raw[6:8], "little") << 48))
        name = None
        name_abs = strings_start + name_offset
        if name_offset == 0 and name_chars == 0:
            name = ""
        elif name_abs + name_chars * 2 <= min(strings_end, len(payload)):
            name = payload[name_abs : name_abs + name_chars * 2].decode("utf-16-le", "replace")
        else:
            warnings.append("metric_name_out_of_range")
        metrics.append(
            {
                "trace_chain_index": trace_chain_index,
                "trace_chain_entries": trace_entries,
                "blocks_to_prefetch": blocks_to_prefetch,
                "name": name,
                "flags": flags,
                "flags_names": sorted(n for b, n in METRIC_FLAG_NAMES.items() if flags & b),
                "file_reference": file_reference,
            }
        )
    return metrics


def parse_trace_chains(payload, version, info, warnings):
    entry_size = TRACE_CHAIN_ENTRY_SIZE[version]
    offset = info["trace_chains_offset"]
    count = info["trace_chains_count"]
    chains = []
    if offset + count * entry_size > len(payload) or count > MAX_TRACE_CHAINS:
        warnings.append("trace_chains_array_out_of_range")
        return chains
    for i in range(count):
        entry_offset = offset + i * entry_size
        if entry_size == 12:
            next_index = struct.unpack_from("<I", payload, entry_offset)[0]
            block_load_count = struct.unpack_from("<I", payload, entry_offset + 4)[0]
            flags = payload[entry_offset + 8]
            unknown = payload[entry_offset + 9]
            used_bits = payload[entry_offset + 10]
            prefetched_bits = payload[entry_offset + 11]
        else:
            block_load_count = struct.unpack_from("<I", payload, entry_offset)[0]
            flags = payload[entry_offset + 4]
            unknown = payload[entry_offset + 5]
            used_bits = payload[entry_offset + 6]
            prefetched_bits = payload[entry_offset + 7]
            next_index = None
        chains.append(
            {
                "next_index": next_index,
                "block_load_count": block_load_count,
                "flags": flags,
                "flags_names": sorted(n for b, n in TRACE_FLAG_NAMES.items() if flags & b),
                "unknown_09": unknown,
                "used_bits": used_bits,
                "prefetched_bits": prefetched_bits,
            }
        )
    return chains


def parse_volumes(payload, version, info, warnings):
    entry_size = VOLUME_ENTRY_SIZE[version]
    offset = info["volumes_offset"]
    count = info["volumes_count"]
    volumes = []
    if offset + count * entry_size > len(payload) or count > MAX_VOLUMES:
        warnings.append("volumes_array_out_of_range")
        return volumes
    block_end = min(offset + info["volumes_size"], len(payload))
    for i in range(count):
        entry_offset = offset + i * entry_size
        path_offset, path_chars, creation, serial = struct.unpack_from("<IIQI", payload, entry_offset)
        refs_offset, refs_size, dir_offset, dir_count = struct.unpack_from("<4I", payload, entry_offset + 20)
        device_path = read_utf16(
            payload[:block_end], offset + path_offset, path_chars, warnings, "device_path_out_of_range"
        )
        if device_path is not None:
            device_path = device_path.split("\x00")[0]
        volume = {
            "device_path": device_path,
            "volume_creation_filetime": creation,
            "volume_creation_time": filetime_to_iso(creation),
            "volume_serial_number": "%08X" % serial,
            "file_references": [],
            "file_references_count": None,
            "directory_strings": [],
            "directory_strings_count": dir_count,
        }
        if refs_offset and refs_size >= 8:
            refs_abs = offset + refs_offset
            if refs_abs + refs_size <= block_end:
                refs_version = struct.unpack_from("<I", payload, refs_abs)[0]
                refs_count = struct.unpack_from("<I", payload, refs_abs + 4)[0]
                refs_start = refs_abs + (8 if refs_version == 1 else 16)
                volume["file_references_version"] = refs_version
                volume["file_references_count"] = refs_count
                if refs_count <= MAX_FILE_REFERENCES and refs_start + refs_count * 8 <= block_end:
                    volume["file_references"] = [
                        "0x%016x" % struct.unpack_from("<Q", payload, refs_start + j * 8)[0] for j in range(refs_count)
                    ]
                else:
                    warnings.append("file_references_out_of_range")
            else:
                warnings.append("file_references_out_of_range")
        if dir_offset and dir_count:
            pos = offset + dir_offset
            strings = []
            ok = True
            for _ in range(min(dir_count, MAX_DIRECTORY_STRINGS)):
                if pos + 2 > block_end:
                    ok = False
                    break
                chars = struct.unpack_from("<H", payload, pos)[0]
                pos += 2
                if pos + chars * 2 > block_end:
                    ok = False
                    break
                strings.append(payload[pos : pos + chars * 2].decode("utf-16-le", "replace"))
                pos += chars * 2
                if pos + 2 <= block_end and payload[pos : pos + 2] == b"\x00\x00":
                    pos += 2
            volume["directory_strings"] = strings
            if not ok or len(strings) != dir_count:
                warnings.append("directory_string_out_of_range")
        volumes.append(volume)
    return volumes


# ---------------------------------------------------------------------------
# Record assembly
# ---------------------------------------------------------------------------


def build_record(source_path, raw, container, declared_size, payload, warnings):
    if len(raw) == 0:
        raise PfParseError("empty file (0 bytes)")
    if raw.count(0) == len(raw):
        raise PfParseError("file is all 0x00 bytes - not a valid .pf (zero-fill corruption)")
    parsed = parse_pf_payload(payload, warnings)
    header = parsed["header"]
    info = parsed["file_information"]

    basename = os.path.basename(source_path)
    filename_parts = parse_filename_parts(basename)
    filename_hash = filename_parts["hash"]
    filename_exe = filename_parts["executable"]

    header_hash = "%08X" % header["prefetch_hash"]
    hash_matches_filename = None
    if filename_hash is not None:
        hash_matches_filename = header_hash == filename_hash
        if not hash_matches_filename:
            warnings.append("filename_hash_mismatch")

    exe_matches_filename = None
    if filename_exe is not None:
        exe_matches_filename = header["executable"].upper() == filename_exe.upper()
        if not exe_matches_filename:
            exe_matches_filename = header["executable"].upper()[:29] == filename_exe.upper()[:29]
        if not exe_matches_filename:
            warnings.append("exe_filename_mismatch")

    if header["file_size"] != len(payload):
        warnings.append("header_size_mismatch")

    run_times_filetime = parsed["run_times_filetime"]
    if len(run_times_filetime) > 1:
        if any(a < b for a, b in zip(run_times_filetime, run_times_filetime[1:])):
            warnings.append("run_times_not_descending")
    run_times_iso = [filetime_to_iso(t) for t in run_times_filetime]

    record = {
        "tool": "pf_parse",
        "schema_version": SCHEMA_VERSION,
        "artifact": "pf",
        "source_path": source_path,
        "source_sha256": sha256_hex(raw),
        "source_size": len(raw),
        "container": container,
        "decompressed_size": len(payload),
        "decompressed_sha256": sha256_hex(payload),
        "declared_uncompressed_size": declared_size,
        "format_version": header["format_version"],
        "signature": header["signature"],
        "unknown_0x08": header["unknown_0x08"],
        "header_file_size": header["file_size"],
        "executable": header["executable"],
        "prefetch_hash": header_hash,
        "flags": header["flags"],
        "is_boot_prefetch": bool(header["flags"] & 0x01),
        "filename": basename,
        "filename_executable": filename_exe,
        "filename_hash": filename_hash,
        "filename_hash_suffix": filename_parts["hash_suffix"],
        "hash_matches_filename": hash_matches_filename,
        "exe_matches_filename": exe_matches_filename,
        "unknown_string": parsed["unknown_string"],
        "file_information": info,
        "run_count": parsed["run_count"],
        "run_times_filetime": run_times_filetime,
        "run_times": run_times_iso,
        "last_run_time": run_times_iso[0] if run_times_iso else None,
        "metrics": parsed["metrics"],
        "trace_chains": parsed["trace_chains"],
        "volumes": parsed["volumes"],
        "warnings": sorted(set(warnings)),
    }
    return record


def record_matches(record, min_runs, name_contains):
    if min_runs is not None and record["run_count"] < min_runs:
        return False
    if name_contains is not None:
        needle = name_contains.lower()
        haystacks = [record["executable"] or "", record["filename"]]
        if not any(needle in h.lower() for h in haystacks):
            return False
    return True


# ---------------------------------------------------------------------------
# Input handling, report, CLI
# ---------------------------------------------------------------------------


class Stats:
    def __init__(self):
        self.files = 0
        self.parsed = 0
        self.failed = 0
        self.emitted = 0
        self.by_version = {}
        self.errors = []
        self.warning_counts = {}
        self.observation_counts = {
            "hash_matches_filename": {"true": 0, "false": 0, "unknown": 0},
            "exe_matches_filename": {"true": 0, "false": 0, "unknown": 0},
            "boot_prefetch": 0,
        }
        self.total_source_bytes = 0
        self.total_decompressed_bytes = 0
        self.warnings = set()

    def count_warning(self, warning):
        self.warning_counts[warning] = self.warning_counts.get(warning, 0) + 1


def expand_inputs(inputs):
    paths = []
    for item in inputs:
        if os.path.isdir(item):
            names = sorted(
                name for name in os.listdir(item) if name.lower().endswith(".pf")
            )
            full = [os.path.join(item, name) for name in names]
            if not full:
                raise PfParseError("no .pf files in directory: %s" % item)
            paths.extend(full)
        else:
            paths.append(item)
    return paths


def _open_jsonl(path):
    if path == "-":
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(newline="\n")
        return sys.stdout, False
    return open(path, "w", encoding="utf-8", newline="\n"), True


def build_report(stats, args, inputs):
    warnings = set(stats.warnings)
    if stats.files == 0:
        warnings.add("no_input_files")
    if stats.failed:
        warnings.add("files_failed_to_parse")
    if stats.warning_counts.get("filename_hash_mismatch"):
        warnings.add("filename_hash_mismatch_present")
    if stats.warning_counts.get("exe_filename_mismatch"):
        warnings.add("exe_filename_mismatch_present")
    if stats.warning_counts.get("header_size_mismatch"):
        warnings.add("header_size_mismatch_present")
    if stats.warning_counts.get("run_times_not_descending"):
        warnings.add("run_times_not_descending_present")

    return {
        "tool": "pf_parse",
        "tool_version": TOOL_VERSION,
        "schema_version": SCHEMA_VERSION,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "mode": "offline",
        "inputs": inputs,
        "counts": {
            "files": stats.files,
            "parsed": stats.parsed,
            "failed": stats.failed,
            "emitted": stats.emitted,
            "by_version": {str(k): v for k, v in sorted(stats.by_version.items())},
            "total_source_bytes": stats.total_source_bytes,
            "total_decompressed_bytes": stats.total_decompressed_bytes,
        },
        "observations": {
            "hash_matches_filename": stats.observation_counts["hash_matches_filename"],
            "exe_matches_filename": stats.observation_counts["exe_matches_filename"],
            "boot_prefetch_files": stats.observation_counts["boot_prefetch"],
            "note": "observations only, not verdicts — interpretation: references/prefetch.md section 10",
        },
        "warning_counts": dict(sorted(stats.warning_counts.items())),
        "errors": stats.errors,
        "filters": {
            "min_runs": args.min_runs,
            "name_contains": args.name_contains,
            "limit": args.limit,
        },
        "warnings": sorted(warnings),
    }


def _print_summary(report, quiet):
    if quiet:
        return
    counts = report["counts"]
    sys.stderr.write(
        f"[pf_parse] files={counts['files']} parsed={counts['parsed']} failed={counts['failed']} "
        f"emitted={counts['emitted']} by_version={counts['by_version']}\n"
    )
    sys.stderr.write(f"[pf_parse] warnings: {', '.join(report['warnings']) if report['warnings'] else 'none'}\n")


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="pf_parse.py",
        description="Honest parser for Windows Prefetch (.pf) files. Structure knowledge: references/prefetch.md",
    )
    ap.add_argument("inputs", nargs="+", help=".pf file(s) and/or directory(ies) containing .pf files")
    ap.add_argument("--min-runs", type=int, default=None, help="only files with run count >= N")
    ap.add_argument("--name-contains", default=None, help="only files whose executable or filename contains this substring (case-insensitive)")
    ap.add_argument("--jsonl", default="-", help="JSONL output path ('-' = stdout, default)")
    ap.add_argument("--report", default=None, help="write machine-readable JSON report to this path")
    ap.add_argument("--raw", action="store_true", help="include raw on-disk bytes as hex (raw_hex)")
    ap.add_argument("--extract-dir", default=None, help="write each decompressed payload to this directory as <name>.raw.pf")
    ap.add_argument("--limit", type=int, default=None, help="stop after N emitted records")
    ap.add_argument("--quiet", action="store_true", help="suppress the stderr summary")
    args = ap.parse_args(argv)

    if args.min_runs is not None and args.min_runs < 0:
        ap.error("--min-runs must be >= 0")
    if args.limit is not None and args.limit <= 0:
        ap.error("--limit must be positive")

    try:
        paths = expand_inputs(args.inputs)
    except (PfParseError, OSError) as exc:
        sys.stderr.write(f"[pf_parse] fatal: {exc}\n")
        return 1

    if args.extract_dir is not None:
        try:
            os.makedirs(args.extract_dir, exist_ok=True)
        except OSError as exc:
            sys.stderr.write(f"[pf_parse] fatal: cannot create extract dir: {exc}\n")
            return 1

    stats = Stats()
    fh, should_close = _open_jsonl(args.jsonl)
    try:
        for path in paths:
            stats.files += 1
            try:
                with open(path, "rb") as handle:
                    raw = handle.read()
            except OSError as exc:
                stats.failed += 1
                stats.errors.append({"path": path, "error": "cannot_read: %s" % exc})
                continue
            warnings = []
            try:
                container, payload, declared_size = unwrap_container(raw)
                record = build_record(path, raw, container, declared_size, payload, warnings)
            except PfParseError as exc:
                stats.failed += 1
                stats.errors.append({"path": path, "error": str(exc)})
                continue
            except Exception as exc:  # never attribute output to an unexpected failure
                stats.failed += 1
                stats.errors.append({"path": path, "error": "unexpected: %r" % exc})
                continue

            stats.parsed += 1
            stats.by_version[record["format_version"]] = stats.by_version.get(record["format_version"], 0) + 1
            stats.total_source_bytes += record["source_size"]
            stats.total_decompressed_bytes += record["decompressed_size"]
            for warning in record["warnings"]:
                stats.count_warning(warning)
            for key in ("hash_matches_filename", "exe_matches_filename"):
                value = record[key]
                bucket = "unknown" if value is None else ("true" if value else "false")
                stats.observation_counts[key][bucket] += 1
            if record["is_boot_prefetch"]:
                stats.observation_counts["boot_prefetch"] += 1

            if args.extract_dir is not None:
                out_path = os.path.join(args.extract_dir, os.path.basename(path) + ".raw.pf")
                with open(out_path, "wb") as out_handle:
                    out_handle.write(payload)

            if not record_matches(record, args.min_runs, args.name_contains):
                continue
            if args.raw:
                record["raw_hex"] = raw.hex()
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")
            stats.emitted += 1
            if args.limit is not None and stats.emitted >= args.limit:
                stats.warnings.add("stopped_early_by_limit")
                break
    finally:
        if should_close:
            fh.close()

    report = build_report(stats, args, args.inputs)
    if args.report:
        try:
            with open(args.report, "w", encoding="utf-8", newline="\n") as report_handle:
                json.dump(report, report_handle, indent=2, ensure_ascii=False)
                report_handle.write("\n")
        except OSError as exc:
            sys.stderr.write(f"[pf_parse] fatal: cannot write report: {exc}\n")
            return 1
    _print_summary(report, args.quiet)
    return 0


if __name__ == "__main__":
    sys.exit(main())
