#!/usr/bin/env python3
"""Honest parser for Windows registry hive files (regf format) and common artifacts.

Structure knowledge: references/registry.md (Structure Card). The tool parses
the regf container (header, hbins, cells, nk/vk/lf/lh/li/ri, db big-data
segments) and extracts artifact records from anchored key paths:

  appcompatcache, amcache, bam (bam+dam), userassist, muicache, runmru,
  typedpaths, appcompatflags_layers, pending_file_rename_operations

Usage:
  python reg_parse.py HIVE [HIVE ...] [--artifact NAME ...] [--jsonl OUT]

Exit codes: 0 = tool ran (per-file/per-artifact errors inside the report),
1 = fatal (inputs unreadable / output not writable), 2 = usage error.
"""

import argparse
import hashlib
import json
import os
import re
import sys
from collections import Counter
from datetime import datetime, timedelta, timezone

TOOL_VERSION = "0.1.0"
SCHEMA_VERSION = 1

BIG_DATA_THRESHOLD = 0x3FD8  # 16344 bytes
AMCACHE_GUID = "{11517B7C-E79D-4e20-961B-75A811715ADD}"

VALUE_TYPE_NAMES = {
    1: "REG_SZ",
    2: "REG_EXPAND_SZ",
    3: "REG_BINARY",
    4: "REG_DWORD",
    5: "REG_DWORD_BIG_ENDIAN",
    6: "REG_LINK",
    7: "REG_MULTI_SZ",
    8: "REG_RESOURCE_LIST",
    9: "REG_FULL_RESOURCE_DESCRIPTOR",
    10: "REG_RESOURCE_REQUIREMENTS_LIST",
    11: "REG_QWORD",
}


class RegToolError(RuntimeError):
    pass


class RegfError(RegToolError):
    pass


# ---------------------------------------------------------------------------
# small helpers
# ---------------------------------------------------------------------------

def u16(buf, off):
    return int.from_bytes(buf[off:off + 2], "little")


def u32(buf, off):
    return int.from_bytes(buf[off:off + 4], "little")


def i32(buf, off):
    return int.from_bytes(buf[off:off + 4], "little", signed=True)


def u64(buf, off):
    return int.from_bytes(buf[off:off + 8], "little")


def filetime_to_iso(ft, warnings=None, what="FILETIME"):
    if not ft:
        return None
    try:
        dt = datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=ft // 10)
    except (OverflowError, ValueError):
        if warnings is not None:
            warnings.append("%s value %d is out of convertible range" % (what, ft))
        return None
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def posix_to_iso(ts, warnings=None, what="POSIX time"):
    if not ts:
        return None
    if ts > 4102444800:  # year 2100
        if warnings is not None:
            warnings.append("%s %d is implausible (after year 2100)" % (what, ts))
        return None
    try:
        dt = datetime.fromtimestamp(ts, tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        if warnings is not None:
            warnings.append("%s %d is not convertible" % (what, ts))
        return None
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def amcache_link_date_to_iso(raw, warnings=None):
    """Amcache InventoryApplicationFile 'LinkDate' is a REG_SZ PE linker
    timestamp in the CRT format MM/DD/YYYY HH:MM:SS (always US-style, the
    appraiser agent writes it, not the user locale). Normalized to ISO 8601 UTC.
    Values outside 1990..2038-01-19T03:14:07Z (the signed 32-bit PE-stamp
    ceiling) get a warning and None: reproducible-build toolchains (/Brepro)
    and packers write hash-derived or forged stamps (1986, 2039, 2060, 2083,
    2098 seen live, plus MS binaries at 2038-03..11) that are not host-event
    times; the raw string stays in link_date either way."""
    if not raw or not isinstance(raw, str):
        return None
    try:
        dt = datetime.strptime(raw.strip(), "%m/%d/%Y %H:%M:%S")
    except ValueError:
        if warnings is not None:
            warnings.append("LinkDate %r does not match MM/DD/YYYY HH:MM:SS" % raw)
        return None
    if dt < datetime(1990, 1, 1) or dt > datetime(2038, 1, 19, 3, 14, 7):
        if warnings is not None:
            warnings.append(
                "LinkDate %r is implausible as a host-event time (outside 1990..2038-01-19, the signed 32-bit "
                "PE-stamp ceiling; hash-derived or forged stamps are common); link_date_ts left null" % raw
            )
        return None
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


_ROT13 = str.maketrans(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
    "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm",
)


def rot13(text):
    return text.translate(_ROT13)


def decode_utf16(data, warnings=None, what="UTF-16 string"):
    if warnings is not None and len(data) % 2:
        warnings.append("%s has odd byte length (%d)" % (what, len(data)))
    text = data.decode("utf-16le", errors="replace")
    if warnings is not None and "\ufffd" in text:
        warnings.append("%s contains replacement characters (invalid UTF-16)" % what)
    return text


def decode_reg_string(data, warnings=None, what="string value"):
    text = decode_utf16(data, warnings, what)
    return text.split("\x00", 1)[0]


def decode_multi_string(data, warnings=None, what="multi-string value"):
    text = decode_utf16(data, warnings, what)
    parts = text.split("\x00")
    if text.endswith("\x00\x00"):
        # properly terminated: drop the list terminator pair, keep a trailing
        # empty element (it is meaningful, e.g. PendingFileRenameOperations delete marker)
        parts = parts[:-2]
    else:
        if parts and parts[-1] == "":
            parts = parts[:-1]
        if warnings is not None and parts:
            warnings.append(
                "%s is not terminated by an empty string (single trailing NUL or none)" % what
            )
    return parts


def binary_summary(data, prefix_bytes=64):
    return {
        "size": len(data),
        "hex_prefix": data[:prefix_bytes].hex(),
        "truncated": len(data) > prefix_bytes,
    }


def normalize_fileid(raw, warnings):
    """Amcache FileId = '0000' + SHA-1 (40 hex chars). Returns the SHA-1 part."""
    if raw is None:
        return None
    s = str(raw).strip().lower()
    if re.fullmatch(r"0{4}[0-9a-f]{40}", s):
        return s[4:]
    if re.fullmatch(r"[0-9a-f]{40}", s):
        warnings.append("file id lacks the expected '0000' prefix")
        return s
    warnings.append("file id %r does not match the '0000'+SHA1 pattern" % raw)
    return None


def normalize_sha1(raw, warnings):
    if raw is None:
        return None
    s = str(raw).strip().lower()
    if re.fullmatch(r"0{4}[0-9a-f]{40}", s):
        return s[4:]
    if re.fullmatch(r"[0-9a-f]{40}", s):
        return s
    warnings.append("SHA-1 value %r does not match expected pattern" % raw)
    return None


# ---------------------------------------------------------------------------
# regf container
# ---------------------------------------------------------------------------

class Hive:
    def __init__(self, data, name):
        self.data = data
        self.name = name
        self.warnings = []
        self._nk_cache = {}
        self._bytes_read = 0
        if len(data) < 4096:
            raise RegfError("file smaller than one 4096-byte header block (%d bytes)" % len(data))
        if data[:4] != b"regf":
            raise RegfError("bad magic %r (not a registry hive; transaction logs use HvLE)" % data[:4])
        self.primary_seq = u32(data, 4)
        self.secondary_seq = u32(data, 8)
        if self.primary_seq != self.secondary_seq:
            self.warnings.append(
                "hive appears dirty: primary sequence %d != secondary sequence %d "
                "(transaction logs not fully applied; recent changes may be missing)"
                % (self.primary_seq, self.secondary_seq)
            )
        self.last_written = filetime_to_iso(u64(data, 12), self.warnings, "hive last written")
        self.major = u32(data, 20)
        self.minor = u32(data, 24)
        self.version = "%d.%d" % (self.major, self.minor)
        self.file_type = u32(data, 28)
        if self.file_type != 0:
            raise RegfError(
                "file type %d is a registry transaction log, not a primary hive" % self.file_type
            )
        self.root_offset = u32(data, 36)
        self.bin_size = u32(data, 40)
        checksum_stored = u32(data, 508)
        checksum_calc = 0
        for i in range(0, 508, 4):
            checksum_calc ^= u32(data, i)
        if checksum_calc != checksum_stored:
            self.warnings.append(
                "header checksum mismatch (stored 0x%08x, computed 0x%08x)" % (checksum_stored, checksum_calc)
            )
        self.bins_base = 4096
        data_end = min(len(self.data), self.bins_base + self.bin_size) if self.bin_size else len(self.data)
        self.data_end = data_end

    # -- cells ---------------------------------------------------------------

    def cell(self, offset, expect=None):
        abs_off = self.bins_base + offset
        if offset < 0 or abs_off + 4 > self.data_end:
            raise RegfError("cell offset 0x%x out of hive bin bounds" % offset)
        size = i32(self.data, abs_off)
        if size == 0:
            raise RegfError("cell at 0x%x has zero size" % offset)
        length = abs(size)
        if length < 8 or length % 8:
            raise RegfError("cell at 0x%x has invalid size %d (must be >= 8 and 8-aligned)" % (offset, size))
        if abs_off + length > self.data_end:
            raise RegfError(
                "cell at 0x%x (size %d) exceeds hive bin data area (0x%x)" % (offset, length, self.data_end)
            )
        payload = self.data[abs_off + 4:abs_off + length]
        if expect is not None and payload[:len(expect)] != expect:
            kind = "free" if size > 0 else "allocated"
            raise RegfError(
                "expected %r at cell 0x%x, found %r (%s cell)" % (expect, offset, payload[:len(expect)], kind)
            )
        self._bytes_read += length
        return payload

    # -- keys ----------------------------------------------------------------

    def read_nk(self, offset):
        cached = self._nk_cache.get(offset)
        if cached is not None:
            return cached
        payload = self.cell(offset, expect=b"nk")
        if len(payload) < 76:
            raise RegfError("nk cell at 0x%x is too small (%d bytes)" % (offset, len(payload)))
        flags = u16(payload, 2)
        lwt = u64(payload, 4)
        name_size = u16(payload, 72)
        if name_size == 0:
            raise RegfError("nk cell at 0x%x has a zero-length name" % offset)
        if 76 + name_size > len(payload):
            raise RegfError(
                "nk cell at 0x%x: name size %d exceeds cell size %d (unsupported pre-1.2 layout?)"
                % (offset, name_size, len(payload))
            )
        name_raw = payload[76:76 + name_size]
        if flags & 0x20:
            name = name_raw.decode("latin-1")
        else:
            name = decode_utf16(name_raw, self.warnings, "key name at 0x%x" % offset)
        info = {
            "offset": offset,
            "name": name,
            "flags": flags,
            "last_write_time": filetime_to_iso(lwt, self.warnings, "key last-written"),
            "parent": u32(payload, 16),
            "n_subkeys": u32(payload, 20),
            "subkey_list_offset": u32(payload, 28),
            "n_values": u32(payload, 36),
            "values_list_offset": u32(payload, 40),
        }
        self._nk_cache[offset] = info
        return info

    def root(self):
        return self.read_nk(self.root_offset)

    def _list_cell_offsets(self, list_offset, depth=0, seen=None):
        if depth > 8:
            raise RegfError("subkey list nesting deeper than 8 at 0x%x" % list_offset)
        if seen is None:
            seen = set()
        if list_offset in seen:
            raise RegfError("subkey list loop detected at 0x%x" % list_offset)
        seen.add(list_offset)
        payload = self.cell(list_offset)
        sig = payload[:2]
        count = u16(payload, 2)
        out = []
        if sig in (b"lf", b"lh"):
            if 4 + count * 8 > len(payload):
                raise RegfError("subkey list at 0x%x: %d entries exceed cell size" % (list_offset, count))
            for i in range(count):
                out.append(u32(payload, 4 + i * 8))
        elif sig == b"li":
            if 4 + count * 4 > len(payload):
                raise RegfError("subkey list at 0x%x: %d entries exceed cell size" % (list_offset, count))
            for i in range(count):
                out.append(u32(payload, 4 + i * 4))
        elif sig == b"ri":
            if 4 + count * 4 > len(payload):
                raise RegfError("subkey list at 0x%x: %d entries exceed cell size" % (list_offset, count))
            for i in range(count):
                out.extend(self._list_cell_offsets(u32(payload, 4 + i * 4), depth + 1, seen))
        else:
            raise RegfError("unknown subkey list signature %r at 0x%x" % (sig, list_offset))
        return out

    def subkeys(self, nk):
        if nk["n_subkeys"] == 0:
            return []
        if nk["subkey_list_offset"] == 0xFFFFFFFF:
            self.warnings.append(
                "key %r reports %d subkeys but no subkey list offset" % (nk["name"], nk["n_subkeys"])
            )
            return []
        offsets = self._list_cell_offsets(nk["subkey_list_offset"])
        if len(offsets) != nk["n_subkeys"]:
            self.warnings.append(
                "key %r reports %d subkeys but list resolved %d"
                % (nk["name"], nk["n_subkeys"], len(offsets))
            )
        return [self.read_nk(off) for off in offsets]

    def find_key(self, path):
        nk = self.root()
        if path in ("", ".", "\\"):
            return nk
        for part in [p for p in path.split("\\") if p]:
            found = None
            for child in self.subkeys(nk):
                if child["name"].lower() == part.lower():
                    found = child
                    break
            if found is None:
                return None
            nk = found
        return nk

    # -- values --------------------------------------------------------------

    def read_vk(self, offset):
        payload = self.cell(offset, expect=b"vk")
        if len(payload) < 20:
            raise RegfError("vk cell at 0x%x is too small (%d bytes)" % (offset, len(payload)))
        name_size = u16(payload, 2)
        data_size_raw = u32(payload, 4)
        data_offset = u32(payload, 8)
        vtype = u32(payload, 12)
        flags = u16(payload, 16)
        if 20 + name_size > len(payload):
            raise RegfError("vk cell at 0x%x: name size %d exceeds cell size %d" % (offset, name_size, len(payload)))
        name_raw = payload[20:20 + name_size]
        if name_size == 0:
            name = "(Default)"
        elif flags & 0x1:
            name = name_raw.decode("latin-1")
        else:
            name = decode_utf16(name_raw, self.warnings, "value name at 0x%x" % offset)
        inline = bool(data_size_raw & 0x80000000)
        size = data_size_raw & 0x7FFFFFFF if inline else data_size_raw
        vk = {
            "offset": offset,
            "name": name,
            "type": vtype,
            "type_name": VALUE_TYPE_NAMES.get(vtype, "REG_UNKNOWN_%d" % vtype),
            "size": size,
            "inline": inline,
            "data_offset": data_offset,
            "flags": flags,
        }
        if inline:
            if size > 4:
                raise RegfError("inline value %r declares %d bytes (max 4)" % (name, size))
            vk["inline_data"] = payload[8:8 + size]
        return vk

    def value_data(self, vk, warnings=None):
        size = vk["size"]
        if size == 0:
            return b""
        if vk["inline"]:
            return bytes(vk.get("inline_data", b""))
        payload = self.cell(vk["data_offset"])
        if size > BIG_DATA_THRESHOLD:
            if payload[:2] != b"db":
                raise RegfError(
                    "value %r declares %d bytes (> %d big-data threshold) but the cell at 0x%x "
                    "is not a 'db' data block (found %r)"
                    % (vk["name"], size, BIG_DATA_THRESHOLD, vk["data_offset"], payload[:2])
                )
            n_segments = u16(payload, 2)
            segment_list_offset = u32(payload, 4)
            list_payload = self.cell(segment_list_offset)
            if 4 * n_segments > len(list_payload):
                raise RegfError(
                    "value %r: data block declares %d segments but the segment list cell holds %d entries"
                    % (vk["name"], n_segments, len(list_payload) // 4)
                )
            data = bytearray()
            for i in range(n_segments):
                if len(data) >= size:
                    break
                segment_offset = u32(list_payload, 4 * i)
                segment = self.cell(segment_offset)
                remaining = size - len(data)
                data += segment[: min(len(segment), remaining, BIG_DATA_THRESHOLD)]
            if len(data) < size and warnings is not None:
                warnings.append(
                    "value %r: big data assembled %d of %d declared bytes" % (vk["name"], len(data), size)
                )
            return bytes(data[:size])
        if len(payload) < size:
            raise RegfError(
                "value %r declares %d bytes but its cell at 0x%x holds only %d"
                % (vk["name"], size, vk["data_offset"], len(payload))
            )
        return payload[:size]

    def values(self, nk):
        if nk["n_values"] == 0:
            return []
        if nk["values_list_offset"] == 0xFFFFFFFF:
            return []
        payload = self.cell(nk["values_list_offset"])
        if 4 * nk["n_values"] > len(payload):
            raise RegfError(
                "key %r reports %d values but list cell holds %d entries"
                % (nk["name"], nk["n_values"], len(payload) // 4)
            )
        return [self.read_vk(u32(payload, 4 * i)) for i in range(nk["n_values"])]

    def get_value(self, nk, name, warnings=None):
        target = name.lower()
        for vk in self.values(nk):
            if vk["name"].lower() == target:
                return vk, self.value_data(vk, warnings)
        return None, None


def decode_value(vk, data, warnings, stats=None):
    """Decode a value's data to a JSON-safe representation (generic view)."""
    t = vk["type"]
    if t in (1, 2, 6):
        return decode_reg_string(data, warnings, "value %r" % vk["name"])
    if t == 4:
        if len(data) < 4:
            warnings.append("REG_DWORD value %r has %d bytes (<4)" % (vk["name"], len(data)))
            return None
        return u32(data, 0)
    if t == 5:
        if len(data) < 4:
            warnings.append("REG_DWORD_BE value %r has %d bytes (<4)" % (vk["name"], len(data)))
            return None
        return int.from_bytes(data[:4], "big")
    if t == 11:
        if len(data) < 8:
            warnings.append("REG_QWORD value %r has %d bytes (<8)" % (vk["name"], len(data)))
            return None
        return u64(data, 0)
    if t == 7:
        return decode_multi_string(data, warnings, "value %r" % vk["name"])
    if stats is not None and t not in VALUE_TYPE_NAMES:
        stats.unknown_value_types[t] += 1
    return binary_summary(data)


# ---------------------------------------------------------------------------
# artifact extractors
# ---------------------------------------------------------------------------

def control_sets(hive):
    out = []
    try:
        children = hive.subkeys(hive.root())
    except RegfError:
        return out
    for nk in children:
        if re.fullmatch(r"(?i)ControlSet\d{3}", nk["name"]):
            out.append(nk)
    return sorted(out, key=lambda k: k["name"].lower())


def base_record(hive, sha, artifact, key_path, key_lwt):
    return {
        "tool": "reg_parse.py",
        "schema_version": SCHEMA_VERSION,
        "artifact": artifact,
        "hive": hive.name,
        "hive_sha256": sha,
        "key_path": key_path,
        "key_last_write_time": key_lwt,
        "warnings": [],
    }


# -- appcompatcache ---------------------------------------------------------

def parse_win10_entry(data, off, warnings):
    end = off + 12 + u32(data, off + 8)
    if end > len(data):
        raise RegfError("AppCompatCache entry at 0x%x declares data beyond value end" % off)
    path_size = u16(data, off + 12)
    path_end = off + 14 + path_size
    if path_end > end:
        raise RegfError("AppCompatCache entry at 0x%x: path size %d exceeds entry size" % (off, path_size))
    entry = {"signature": "10ts", "offset": off}
    entry["path"] = decode_utf16(data[off + 14:path_end], warnings, "AppCompatCache path")
    p = path_end
    if p + 8 <= end:
        entry["last_modification_time"] = filetime_to_iso(u64(data, p), warnings, "AppCompatCache mtime")
        p += 8
    else:
        warnings.append("AppCompatCache entry at 0x%x lacks the modification FILETIME" % off)
    if p + 4 <= end:
        dsize = u32(data, p)
        p += 4
        entry["data_size"] = dsize
        entry["data"] = data[p:p + dsize] if p + dsize <= end else data[p:end]
        if p + dsize > end:
            warnings.append("AppCompatCache entry at 0x%x: data size %d exceeds entry" % (off, dsize))
    else:
        entry["data_size"] = None
        entry["data"] = b""
        warnings.append("AppCompatCache entry at 0x%x lacks the data size field" % off)
    return entry, end


def parse_win8_entry(data, off, warnings):
    end = off + 12 + u32(data, off + 8)
    if end > len(data):
        raise RegfError("AppCompatCache entry at 0x%x declares data beyond value end" % off)
    path_size = u16(data, off + 12)
    path_end = off + 14 + path_size
    if path_end > end:
        raise RegfError("AppCompatCache entry at 0x%x: path size %d exceeds entry size" % (off, path_size))
    sig = data[off:off + 4].decode("ascii")
    entry = {"signature": sig, "offset": off}
    entry["path"] = decode_utf16(data[off + 14:path_end], warnings, "AppCompatCache path")
    p = path_end
    if p + 4 <= end:
        entry["unknown1"] = u32(data, p)
        p += 4
    if p + 4 <= end:
        entry["unknown2"] = u32(data, p)
        p += 4
    if sig == "10ts" and p + 2 <= end:
        entry["unknown3"] = u16(data, p)
        p += 2
    if p + 8 <= end:
        entry["last_modification_time"] = filetime_to_iso(u64(data, p), warnings, "AppCompatCache mtime")
        p += 8
    else:
        warnings.append("AppCompatCache entry at 0x%x lacks the modification FILETIME" % off)
    if p + 4 <= end:
        dsize = u32(data, p)
        p += 4
        entry["data_size"] = dsize
        entry["data"] = data[p:p + dsize] if p + dsize <= end else data[p:end]
    else:
        entry["data_size"] = None
        entry["data"] = b""
    return entry, end


def parse_appcompatcache_blob(data, warnings, notes=None):
    if len(data) < 4:
        raise RegfError("AppCompatCache value is smaller than 4 bytes")
    sig = u32(data, 0)
    if sig in (0xDEADBEEF, 0xBADC0FFE, 0xBADC0FEE):
        raise RegfError(
            "legacy AppCompatCache format (signature 0x%08X, pre-Windows 8) detected but not parsed by this tool"
            % sig
        )
    if sig == 0x80:
        entries = []
        off = 0x80
        while off + 12 <= len(data):
            esig = data[off:off + 4]
            if esig not in (b"00ts", b"10ts"):
                warnings.append(
                    "unexpected AppCompatCache entry signature %r at 0x%x; stopping" % (esig, off)
                )
                break
            try:
                entry, off = parse_win8_entry(data, off, warnings)
            except RegfError as exc:
                warnings.append("malformed AppCompatCache entry at 0x%x (%s); stopping" % (off, exc))
                break
            entries.append(entry)
        if not entries:
            raise RegfError("Windows 8 AppCompatCache detected but no entries could be parsed")
        return entries
    if sig in (0x30, 0x34):
        if len(data) < sig:
            raise RegfError("AppCompatCache header size %d exceeds value size %d" % (sig, len(data)))
        count_offset = 36 if sig == 0x30 else 40
        n_entries = u32(data, count_offset)
        entries = []
        off = sig
        stopped_early = False
        while off + 12 <= len(data):
            if data[off:off + 4] != b"10ts":
                warnings.append(
                    "AppCompatCache entry %d at 0x%x: expected '10ts', found %r; stopping (%d of %d declared parsed)"
                    % (len(entries), off, data[off:off + 4], len(entries), n_entries)
                )
                stopped_early = True
                break
            try:
                entry, off = parse_win10_entry(data, off, warnings)
            except RegfError as exc:
                warnings.append(
                    "malformed AppCompatCache entry %d at 0x%x (%s); stopping (%d of %d declared parsed)"
                    % (len(entries), off, exc, len(entries), n_entries)
                )
                stopped_early = True
                break
            entries.append(entry)
        if not stopped_early and entries and n_entries != len(entries):
            message = (
                "AppCompatCache header declares %d entries but the value holds %d "
                "(the header count field is a lifetime counter, not the current entry count; walk-to-end used)"
                % (n_entries, len(entries))
            )
            if notes is not None:
                notes.append(message)
            else:
                warnings.append(message)
        return entries
    raise RegfError(
        "unknown AppCompatCache signature 0x%08X (expected 0x30/0x34/0x80 or legacy)" % sig
    )


def extract_appcompatcache(hive, sha, include_raw, stats, explicit):
    found = False
    for cs in control_sets(hive):
        key_path = "%s\\Control\\Session Manager\\AppCompatCache" % cs["name"]
        nk = hive.find_key(key_path)
        if nk is None:
            continue
        found = True
        warnings = []
        vk, data = hive.get_value(nk, "AppCompatCache", warnings)
        if vk is None:
            stats.notes.append("AppCompatCache key exists in %s but the value is missing (cleared?)" % key_path)
            continue
        try:
            entries = parse_appcompatcache_blob(data, warnings, stats.notes)
        except RegfError as exc:
            stats.errors.append(
                {"hive": hive.name, "artifact": "appcompatcache", "key_path": key_path, "error": str(exc)}
            )
            continue
        for e in entries:
            rec = base_record(hive, sha, "appcompatcache", key_path, nk["last_write_time"])
            rec.update(
                {
                    "control_set": cs["name"],
                    "path": e["path"],
                    "last_modification_time": e.get("last_modification_time"),
                    "entry_signature": e["signature"],
                    "data_size": e.get("data_size"),
                }
            )
            if "unknown1" in e:
                rec["unknown_flag_1"] = e["unknown1"]
            if "unknown2" in e:
                rec["unknown_flag_2"] = e["unknown2"]
            if include_raw and e.get("data"):
                rec["data_hex"] = e["data"][:256].hex()
                if len(e["data"]) > 256:
                    rec["data_hex_truncated"] = True
            yield rec
        stats.count_warning_for(warnings)
    if explicit and not found:
        stats.errors.append(
            {"hive": hive.name, "artifact": "appcompatcache", "error": "anchor key not found (expected ControlSet00N\\Control\\Session Manager\\AppCompatCache)"}
        )


# -- amcache ----------------------------------------------------------------

AMCACHE_IAF_MAP = {
    "fileid": ("file_id_raw", "str"),
    "programid": ("program_id", "str"),
    "lowercaselongpath": ("path", "str"),
    "name": ("name", "str"),
    "publisher": ("publisher", "str"),
    "productname": ("product_name", "str"),
    "productversion": ("product_version", "str"),
    "binfileversion": ("bin_file_version", "str"),
    "binproductversion": ("bin_product_version", "str"),
    "version": ("version", "str"),
    "binarytype": ("binary_type", "str"),
    "linkdate": ("link_date", "str"),
    "longpathhash": ("long_path_hash", "str"),
    "size": ("size", "int"),
    "language": ("language", "int"),
    "usn": ("usn", "int"),
    "ispefile": ("is_pe_file", "int"),
    "isoscomponent": ("is_os_component", "int"),
}

AMCACHE_IA_MAP = {
    "name": ("name", "str"),
    "publisher": ("publisher", "str"),
    "version": ("version", "str"),
    "rootdirpath": ("root_dir_path", "str"),
    "installdate": ("install_date", "str"),
    "source": ("source", "str"),
    "uninstallstring": ("uninstall_string", "str"),
    "registrykeypath": ("registry_key_path", "str"),
    "msipackagecode": ("msi_package_code", "str"),
    "msiproductcode": ("msi_product_code", "str"),
}

AMCACHE_FILE_MAP = {
    "0": ("name", "str"),
    "1": ("company", "str"),
    "2": ("version", "str"),
    "3": ("language", "int"),
    "6": ("file_size", "int"),
    "7": ("pe_image_size", "int"),
    "9": ("checksum", "int"),
    "c": ("description", "str"),
    "d": ("image_version", "str"),
    "f": ("link_date_ts", "posix"),
    "11": ("modification_time", "ft"),
    "12": ("creation_time", "ft"),
    "15": ("path", "str"),
    "100": ("program_id", "str"),
    "101": ("sha1_raw", "str"),
}

AMCACHE_PROGRAMS_MAP = {
    "0": ("name", "str"),
    "1": ("version", "str"),
    "2": ("publisher", "str"),
    "6": ("source", "str"),
    "7": ("uninstall", "str"),
    "d": ("install_dirs", "multi"),
    "a": ("install_time_ts", "posix"),
    "b": ("uninstall_time_ts", "posix"),
}


def _apply_map(rec, values, mapping, warnings, leftovers):
    for lower_name, (json_name, kind) in mapping.items():
        item = values.get(lower_name)
        if item is None:
            continue
        vk, data = item
        if kind == "str":
            rec[json_name] = decode_reg_string(data, warnings, "value %r" % vk["name"])
        elif kind == "int":
            if len(data) >= 4:
                rec[json_name] = u32(data, 0)
            else:
                warnings.append("value %r too small for %s" % (vk["name"], json_name))
        elif kind == "multi":
            rec[json_name] = decode_multi_string(data, warnings, "value %r" % vk["name"])
        elif kind == "ft":
            rec[json_name] = filetime_to_iso(u64(data, 0), warnings, json_name) if len(data) >= 8 else None
        elif kind == "posix":
            rec[json_name] = posix_to_iso(u32(data, 0), warnings, json_name) if len(data) >= 4 else None
        leftovers.pop(lower_name, None)
    for lower_name, (vk, data) in sorted(leftovers.items()):
        rec.setdefault("other_values", {})[vk["name"]] = decode_value(vk, data, warnings)


def _extract_amcache_key(hive, sha, nk, artifact, mapping, stats, include_raw):
    warnings = []
    values = {}
    try:
        for vk in hive.values(nk):
            values[vk["name"].lower()] = (vk, hive.value_data(vk, warnings))
    except RegfError as exc:
        stats.errors.append({"hive": hive.name, "artifact": artifact, "key_path": nk["name"], "error": str(exc)})
        return None
    rec = base_record(hive, sha, artifact, nk["name"], nk["last_write_time"])
    rec["key_name"] = nk["name"]
    _apply_map(rec, values, mapping, warnings, values)
    rec["warnings"].extend(warnings)
    stats.count_warning_for(warnings)
    return rec


def extract_amcache(hive, sha, include_raw, stats, explicit):
    root = hive.find_key("Root")
    if root is None:
        if explicit:
            stats.errors.append({"hive": hive.name, "artifact": "amcache", "error": "Amcache anchor key 'Root' not found"})
        return
    found_any = False

    iaf = hive.find_key("Root\\InventoryApplicationFile")
    if iaf is not None:
        found_any = True
        for ch in hive.subkeys(iaf):
            rec = _extract_amcache_key(hive, sha, ch, "amcache_inventory_application_file", AMCACHE_IAF_MAP, stats, include_raw)
            if rec is None:
                continue
            rec["key_path"] = "Root\\InventoryApplicationFile\\%s" % ch["name"]
            ld_warnings = []
            rec["link_date_ts"] = amcache_link_date_to_iso(rec.get("link_date"), ld_warnings)
            if ld_warnings:
                rec["warnings"].extend(ld_warnings)
                stats.count_warning_for(ld_warnings)
            fw = rec.get("warnings", [])
            rec["sha1"] = normalize_fileid(rec.get("file_id_raw"), fw)
            yield rec

    ia = hive.find_key("Root\\InventoryApplication")
    if ia is not None:
        found_any = True
        scan_vk, scan_data = hive.get_value(ia, "LastScanTime")
        scan_time = filetime_to_iso(u64(scan_data, 0)) if scan_vk is not None and len(scan_data) >= 8 else None
        for ch in hive.subkeys(ia):
            rec = _extract_amcache_key(hive, sha, ch, "amcache_inventory_application", AMCACHE_IA_MAP, stats, include_raw)
            if rec is None:
                continue
            rec["key_path"] = "Root\\InventoryApplication\\%s" % ch["name"]
            rec["inventory_last_scan_time"] = scan_time
            yield rec

    fk = hive.find_key("Root\\File")
    if fk is not None:
        found_any = True
        for vol in hive.subkeys(fk):
            for ident in hive.subkeys(vol):
                rec = _extract_amcache_key(hive, sha, ident, "amcache_file", AMCACHE_FILE_MAP, stats, include_raw)
                if rec is None:
                    continue
                rec["key_path"] = "Root\\File\\%s\\%s" % (vol["name"], ident["name"])
                rec["volume"] = vol["name"]
                rec["identifier"] = ident["name"]
                m = re.fullmatch(r"(?i)([0-9a-f]+)0000([0-9a-f]+)", ident["name"])
                rec["file_reference_sequence"] = int(m.group(1), 16) if m else None
                rec["file_reference_mft_entry"] = int(m.group(2), 16) if m else None
                if not m:
                    rec["warnings"].append("identifier %r does not match %%SEQ%%0000%%MFT%% pattern" % ident["name"])
                rec["sha1"] = normalize_sha1(rec.pop("sha1_raw", None), rec["warnings"])
                yield rec

    prog = hive.find_key("Root\\Programs")
    if prog is not None:
        found_any = True
        for ch in hive.subkeys(prog):
            rec = _extract_amcache_key(hive, sha, ch, "amcache_programs", AMCACHE_PROGRAMS_MAP, stats, include_raw)
            if rec is None:
                continue
            rec["key_path"] = "Root\\Programs\\%s" % ch["name"]
            yield rec

    if explicit and not found_any:
        stats.errors.append(
            {
                "hive": hive.name,
                "artifact": "amcache",
                "error": "no Amcache anchors found (expected Root\\InventoryApplicationFile / Root\\File ...)",
            }
        )


# -- bam / dam --------------------------------------------------------------

def extract_bam(hive, sha, include_raw, stats, explicit):
    found = False
    candidates = [
        ("bam", "%s\\Services\\bam\\State\\UserSettings"),
        ("bam", "%s\\Services\\bam\\UserSettings"),
        ("dam", "%s\\Services\\dam\\State\\UserSettings"),
        ("dam", "%s\\Services\\dam\\UserSettings"),
    ]
    for cs in control_sets(hive):
        for artifact, pattern in candidates:
            key_path = pattern % cs["name"]
            nk = hive.find_key(key_path)
            if nk is None:
                continue
            found = True
            for sid_nk in hive.subkeys(nk):
                if not sid_nk["name"].upper().startswith("S-"):
                    stats.notes.append(
                        "BAM/DAM subkey %r under %s does not look like a SID; parsed anyway"
                        % (sid_nk["name"], key_path)
                    )
                try:
                    vks = hive.values(sid_nk)
                except RegfError as exc:
                    stats.errors.append(
                        {"hive": hive.name, "artifact": artifact, "key_path": key_path, "error": str(exc)}
                    )
                    continue
                for vk in vks:
                    if vk["name"].lower() in ("version", "sequencenumber"):
                        continue
                    warnings = []
                    data = hive.value_data(vk, warnings)
                    rec = base_record(hive, sha, artifact, "%s\\%s" % (key_path, sid_nk["name"]), sid_nk["last_write_time"])
                    rec.update(
                        {
                            "control_set": cs["name"],
                            "user_sid": sid_nk["name"],
                            "path": vk["name"],
                            "value_size": len(data),
                        }
                    )
                    if len(data) >= 8:
                        rec["execution_time"] = filetime_to_iso(u64(data, 0), warnings, "BAM execution time")
                    else:
                        rec["execution_time"] = None
                        warnings.append("value %r too small for an execution FILETIME" % vk["name"])
                    rec["windows_app_flag"] = u32(data, 16) if len(data) >= 20 else None
                    if include_raw:
                        rec["data_hex"] = data[:64].hex()
                    rec["warnings"].extend(warnings)
                    if warnings:
                        for w in warnings:
                            stats.count_warning(w)
                    yield rec
    if explicit and not found:
        stats.errors.append(
            {"hive": hive.name, "artifact": "bam", "error": "anchor keys not found (expected ControlSet00N\\Services\\bam[...])"}
        )


# -- userassist -------------------------------------------------------------

UA_BASE = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist"


def extract_userassist(hive, sha, include_raw, stats, explicit):
    base = hive.find_key(UA_BASE)
    if base is None:
        if explicit:
            stats.errors.append({"hive": hive.name, "artifact": "userassist", "error": "anchor key not found"})
        return
    for guid_nk in hive.subkeys(base):
        ver_vk, ver_data = hive.get_value(guid_nk, "Version")
        version = u32(ver_data, 0) if ver_vk is not None and len(ver_data) >= 4 else None
        count_nk = None
        for ch in hive.subkeys(guid_nk):
            if ch["name"].lower() == "count":
                count_nk = ch
                break
        if count_nk is None:
            stats.notes.append("UserAssist GUID %s has no Count subkey" % guid_nk["name"])
            continue
        for vk in hive.values(count_nk):
            vw = []
            data = hive.value_data(vk, vw)
            decoded = rot13(vk["name"])
            if decoded.upper().startswith("UEME_CTLSESSION"):
                stats.notes.append("skipped UEME_CTLSESSION entry in %s" % guid_nk["name"])
                continue
            kind = None
            target = None
            if decoded.upper().startswith("UEME_") and ":" in decoded:
                kind, target = decoded.split(":", 1)
            rec = base_record(hive, sha, "userassist", "%s\\%s\\Count" % (UA_BASE, guid_nk["name"]), count_nk["last_write_time"])
            rec.update(
                {
                    "guid": guid_nk["name"],
                    "version": version,
                    "value_name_raw": vk["name"],
                    "name": decoded,
                    "kind": kind,
                    "target": target,
                    "entry_size": len(data),
                    "session_id": None,
                    "run_count": None,
                    "focus_count": None,
                    "focus_time_ms": None,
                    "last_run_time": None,
                }
            )
            eff_version = version
            if version not in (3, 5):
                if version is not None:
                    vw.append("unexpected UserAssist version %r; parsed by entry size" % version)
                eff_version = 3 if len(data) < 72 else 5
            if eff_version == 3:
                if len(data) >= 12:
                    rec["session_id"] = u32(data, 0)
                    rec["run_count"] = u32(data, 4)
                if len(data) >= 16:
                    rec["last_run_time"] = filetime_to_iso(u64(data, 8), vw, "UserAssist last run")
                if len(data) != 16:
                    vw.append("v3 entry has %d bytes (expected 16)" % len(data))
            else:
                if len(data) >= 8:
                    rec["run_count"] = u32(data, 4)
                if len(data) >= 12:
                    rec["focus_count"] = u32(data, 8)
                if len(data) >= 16:
                    rec["focus_time_ms"] = i32(data, 12)
                if len(data) >= 68:
                    rec["last_run_time"] = filetime_to_iso(u64(data, 60), vw, "UserAssist last run")
                if len(data) != 72:
                    vw.append("v5 entry has %d bytes (expected 72)" % len(data))
            if include_raw:
                rec["data_hex"] = data[:128].hex()
            rec["warnings"].extend(vw)
            for w in vw:
                stats.count_warning(w)
            yield rec


# -- muicache ---------------------------------------------------------------

MUICACHE_PATHS = [
    "Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\MuiCache",
    "Local Settings\\Software\\Microsoft\\Windows\\Shell\\MuiCache",
    "Software\\Microsoft\\Windows\\ShellNoRoam\\MUICache",
]


def extract_muicache(hive, sha, include_raw, stats, explicit):
    found = False
    for path in MUICACHE_PATHS:
        nk = hive.find_key(path)
        if nk is None:
            continue
        found = True
        for vk in hive.values(nk):
            warnings = []
            data = hive.value_data(vk, warnings)
            name = vk["name"]
            suffix = None
            executable = name
            for s in (".FriendlyAppName", ".NoExt"):
                if name.endswith(s):
                    executable = name[: -len(s)]
                    suffix = s[1:]
                    break
            rec = base_record(hive, sha, "muicache", path, nk["last_write_time"])
            rec.update(
                {
                    "executable_path": executable,
                    "value_name_suffix": suffix,
                    "display_name": decode_reg_string(data, warnings, "MUICache value"),
                    "value_name_raw": name,
                }
            )
            rec["warnings"].extend(warnings)
            stats.count_warning_for(warnings)
            yield rec
    if explicit and not found:
        stats.errors.append({"hive": hive.name, "artifact": "muicache", "error": "anchor keys not found"})


# -- runmru -----------------------------------------------------------------

RUNMRU_PATH = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU"
TYPEDPATHS_PATH = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths"


def extract_runmru(hive, sha, include_raw, stats, explicit):
    nk = hive.find_key(RUNMRU_PATH)
    if nk is None:
        if explicit:
            stats.errors.append({"hive": hive.name, "artifact": "runmru", "error": "anchor key not found"})
        return
    warnings = []
    mru_vk, mru_data = hive.get_value(nk, "MRUList", warnings)
    mru_list = decode_reg_string(mru_data, warnings, "MRUList") if mru_vk is not None else ""
    stats.count_warning_for(warnings)
    order = list(mru_list)
    letters = {}
    for vk in hive.values(nk):
        if vk["name"].lower() == "mrulist":
            continue
        if len(vk["name"]) == 1:
            letters[vk["name"]] = vk
    for i, letter in enumerate(order):
        vk = letters.pop(letter, None)
        if vk is None:
            stats.notes.append("MRUList references %r but no such value exists" % letter)
            continue
        cw = []
        data = hive.value_data(vk, cw)
        rec = base_record(hive, sha, "runmru", RUNMRU_PATH, nk["last_write_time"])
        rec.update(
            {
                "command": decode_reg_string(data, cw, "RunMRU command"),
                "slot": letter,
                "position": i,
                "is_most_recent": i == 0,
            }
        )
        rec["warnings"].extend(cw)
        stats.count_warning_for(cw)
        yield rec
    for letter, vk in sorted(letters.items()):
        cw = []
        data = hive.value_data(vk, cw)
        stats.notes.append("RunMRU value %r not referenced by MRUList" % letter)
        rec = base_record(hive, sha, "runmru", RUNMRU_PATH, nk["last_write_time"])
        rec.update(
            {
                "command": decode_reg_string(data, cw, "RunMRU command"),
                "slot": letter,
                "position": None,
                "is_most_recent": False,
            }
        )
        rec["warnings"].extend(cw)
        stats.count_warning_for(cw)
        yield rec


# -- typedpaths -------------------------------------------------------------

def extract_typedpaths(hive, sha, include_raw, stats, explicit):
    nk = hive.find_key(TYPEDPATHS_PATH)
    if nk is None:
        if explicit:
            stats.errors.append({"hive": hive.name, "artifact": "typedpaths", "error": "anchor key not found"})
        return
    entries = []
    for vk in hive.values(nk):
        m = re.fullmatch(r"(?i)url(\d+)", vk["name"])
        if not m:
            stats.notes.append("TypedPaths: value %r does not match url<N>" % vk["name"])
            continue
        warnings = []
        data = hive.value_data(vk, warnings)
        entries.append((int(m.group(1)), vk, data, warnings))
    for num, vk, data, warnings in sorted(entries, key=lambda e: e[0]):
        rec = base_record(hive, sha, "typedpaths", TYPEDPATHS_PATH, nk["last_write_time"])
        rec.update(
            {
                "slot": vk["name"],
                "path": decode_reg_string(data, warnings, "TypedPaths value"),
                "position": num,
            }
        )
        rec["warnings"].extend(warnings)
        stats.count_warning_for(warnings)
        yield rec


# -- appcompatflags layers --------------------------------------------------

LAYERS_PATHS = [
    ("user", "Software\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Layers"),
    ("user_wow64", "Software\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Layers"),
    ("machine", "Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Layers"),
    ("machine_wow64", "Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Layers"),
]


def extract_layers(hive, sha, include_raw, stats, explicit):
    found = False
    for scope, path in LAYERS_PATHS:
        nk = hive.find_key(path)
        if nk is None:
            continue
        found = True
        for vk in hive.values(nk):
            warnings = []
            data = hive.value_data(vk, warnings)
            layers = decode_reg_string(data, warnings, "Layers value")
            rec = base_record(hive, sha, "appcompatflags_layers", path, nk["last_write_time"])
            rec.update(
                {
                    "scope": scope,
                    "executable_path": vk["name"],
                    "layers": layers,
                    "layer_flags": [f for f in layers.replace("~", " ").split() if f],
                    "run_as_admin": "RUNASADMIN" in layers.upper(),
                }
            )
            rec["warnings"].extend(warnings)
            stats.count_warning_for(warnings)
            yield rec
    if explicit and not found:
        stats.errors.append({"hive": hive.name, "artifact": "appcompatflags_layers", "error": "anchor keys not found"})


# -- pending file rename operations -----------------------------------------

def extract_pending_renames(hive, sha, include_raw, stats, explicit):
    found = False
    for cs in control_sets(hive):
        key_path = "%s\\Control\\Session Manager" % cs["name"]
        nk = hive.find_key(key_path)
        if nk is None:
            continue
        warnings = []
        vk, data = hive.get_value(nk, "PendingFileRenameOperations", warnings)
        if vk is None:
            continue
        found = True
        strings = decode_multi_string(data, warnings, "PendingFileRenameOperations")
        i = 0
        while i < len(strings):
            src = strings[i]
            dst = strings[i + 1] if i + 1 < len(strings) else None
            rec = base_record(hive, sha, "pending_file_rename_operations", key_path, nk["last_write_time"])
            rec["control_set"] = cs["name"]
            src_display = src[4:] if src.upper().startswith("\\??\\") else src
            rec["source"] = src
            rec["source_display"] = src_display
            if dst is None:
                rec["operation"] = "malformed"
                rec["destination"] = None
                rec["warnings"].append(
                    "odd number of strings: final entry %r has no destination (malformed value)" % src
                )
            elif dst == "":
                rec["operation"] = "delete"
                rec["destination"] = None
            else:
                dst_display = dst[4:] if dst.upper().startswith("\\??\\") else dst
                rec["operation"] = "rename"
                rec["destination"] = dst
                rec["destination_display"] = dst_display
            rec["value_size"] = len(data)
            if include_raw:
                rec["data_hex"] = data[:256].hex()
            yield rec
            i += 2
        for w in warnings:
            stats.count_warning(w)
    if explicit and not found:
        stats.errors.append(
            {"hive": hive.name, "artifact": "pending_file_rename_operations", "error": "value not present in any ControlSet00N\\Control\\Session Manager"}
        )


EXTRACTORS = {
    "appcompatcache": extract_appcompatcache,
    "amcache": extract_amcache,
    "bam": extract_bam,
    "userassist": extract_userassist,
    "muicache": extract_muicache,
    "runmru": extract_runmru,
    "typedpaths": extract_typedpaths,
    "appcompatflags_layers": extract_layers,
    "pending_file_rename_operations": extract_pending_renames,
}

ARTIFACT_ALIASES = {
    "shimcache": "appcompatcache",
    "appcompatcache": "appcompatcache",
    "amcache": "amcache",
    "bam": "bam",
    "dam": "bam",
    "userassist": "userassist",
    "muicache": "muicache",
    "runmru": "runmru",
    "typedpaths": "typedpaths",
    "layers": "appcompatflags_layers",
    "appcompatflags_layers": "appcompatflags_layers",
    "pending": "pending_file_rename_operations",
    "pending_file_rename_operations": "pending_file_rename_operations",
}


# ---------------------------------------------------------------------------
# stats, report, CLI
# ---------------------------------------------------------------------------

class Stats:
    def __init__(self):
        self.hives_total = 0
        self.hives_parsed = 0
        self.hives_failed = 0
        self.emitted = 0
        self.by_artifact = Counter()
        self.warning_counts = Counter()
        self.unknown_value_types = Counter()
        self.errors = []
        self.notes = []
        self.warnings = set()
        self.total_bytes_read = 0

    def count_warning(self, message):
        self.warning_counts[message] += 1

    def count_warning_for(self, messages):
        for m in messages:
            self.warning_counts[m] += 1


def expand_inputs(inputs):
    paths = []
    for item in inputs:
        if os.path.isdir(item):
            names = []
            for name in sorted(os.listdir(item)):
                low = name.lower()
                if low.endswith((".log1", ".log2")):
                    continue
                if low == "collect_reg.json":
                    continue
                full = os.path.join(item, name)
                if os.path.isfile(full):
                    names.append(full)
            if not names:
                raise RegToolError("no candidate hive files in directory: %s" % item)
            paths.extend(names)
        else:
            paths.append(item)
    return paths


def _open_jsonl(path):
    if path == "-":
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(newline="\n")
        return sys.stdout, False
    return open(path, "w", encoding="utf-8", newline="\n"), True


def run_extractors(hive, sha, selected, explicit, stats, include_raw):
    for name in selected:
        extractor = EXTRACTORS[name]
        for rec in extractor(hive, sha, include_raw, stats, explicit):
            yield rec


def build_report(stats, args, inputs):
    warnings = set(stats.warnings)
    if stats.hives_failed:
        warnings.add("hives_failed_to_parse")
    if stats.emitted == 0:
        warnings.add("no_records_emitted")
    if stats.warning_counts and any("dirty" in w for w in stats.warning_counts):
        warnings.add("dirty_hives_present")
    if stats.unknown_value_types:
        warnings.add("unknown_value_type_present")
    return {
        "tool": "reg_parse",
        "tool_version": TOOL_VERSION,
        "schema_version": SCHEMA_VERSION,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "mode": "offline",
        "inputs": inputs,
        "counts": {
            "hives": stats.hives_total,
            "parsed": stats.hives_parsed,
            "failed": stats.hives_failed,
            "emitted": stats.emitted,
            "by_artifact": dict(sorted(stats.by_artifact.items())),
            "total_cell_bytes_read": stats.total_bytes_read,
        },
        "warning_counts": dict(sorted(stats.warning_counts.items())),
        "unknown_value_types": {"%d" % k: v for k, v in sorted(stats.unknown_value_types.items())},
        "notes": stats.notes,
        "errors": stats.errors,
        "filters": {
            "artifacts": args.artifact if args.artifact else ["auto"],
            "limit": args.limit,
            "raw": bool(args.raw),
        },
        "warnings": sorted(warnings),
    }


def _print_summary(report, quiet):
    if quiet:
        return
    counts = report["counts"]
    sys.stderr.write(
        "[reg_parse] hives=%d parsed=%d failed=%d emitted=%d by_artifact=%s\n"
        % (counts["hives"], counts["parsed"], counts["failed"], counts["emitted"], counts["by_artifact"])
    )
    sys.stderr.write(
        "[reg_parse] warnings: %s\n" % (", ".join(report["warnings"]) if report["warnings"] else "none")
    )


def print_key_listing(hive, path, depth, limit):
    def show(nk, level):
        indent = "  " * level
        print(
            "%s%s  [lwt=%s subkeys=%d values=%d]"
            % (indent, nk["name"], nk["last_write_time"], nk["n_subkeys"], nk["n_values"])
        )
        if level >= depth:
            return
        children = hive.subkeys(nk)
        for child in children[:limit]:
            show(child, level + 1)
        if len(children) > limit:
            print("%s  ... and %d more subkeys" % (indent, len(children) - limit))
        for vk in hive.values(nk)[:limit]:
            try:
                data = hive.value_data(vk, None)
                preview = data[:48].hex()
            except RegfError as exc:
                preview = "<error: %s>" % exc
            print(
                "%s  * %s : %s (%d bytes) %s"
                % (indent, vk["name"], vk["type_name"], vk["size"], preview)
            )

    nk = hive.find_key(path) if path else hive.root()
    if nk is None:
        print("key not found: %s" % path)
        return
    show(nk, 0)


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="reg_parse.py",
        description="Honest parser for Windows registry hive files. Structure knowledge: references/registry.md",
    )
    ap.add_argument("inputs", nargs="+", help="hive file(s) and/or directory(ies) containing hives")
    ap.add_argument(
        "--artifact",
        action="append",
        default=None,
        help="artifact(s) to extract (repeatable / comma-separated). Default: auto (all). "
        "Names: %s" % ", ".join(sorted(set(ARTIFACT_ALIASES))),
    )
    ap.add_argument("--jsonl", default="-", help="JSONL output path ('-' = stdout, default)")
    ap.add_argument("--report", default=None, help="write machine-readable JSON report to this path")
    ap.add_argument("--raw", action="store_true", help="include raw value/entry bytes as hex (capped)")
    ap.add_argument("--limit", type=int, default=None, help="stop after N emitted records")
    ap.add_argument("--list", dest="list_path", default=None, help="debug: print a key listing rooted at PATH (default root)")
    ap.add_argument("--list-depth", type=int, default=1, help="debug: listing depth (default 1)")
    ap.add_argument("--list-limit", type=int, default=50, help="debug: max children/values shown per key")
    ap.add_argument("--quiet", action="store_true", help="suppress the stderr summary")
    args = ap.parse_args(argv)

    if args.limit is not None and args.limit <= 0:
        ap.error("--limit must be positive")

    selected = []
    explicit = args.artifact is not None
    if explicit:
        for item in args.artifact:
            for token in item.split(","):
                token = token.strip().lower()
                if not token:
                    continue
                if token not in ARTIFACT_ALIASES:
                    ap.error("unknown artifact %r; valid: %s" % (token, ", ".join(sorted(set(ARTIFACT_ALIASES)))))
                selected.append(ARTIFACT_ALIASES[token])
        seen = set()
        selected = [a for a in selected if not (a in seen or seen.add(a))]
    else:
        selected = list(EXTRACTORS)

    try:
        paths = expand_inputs(args.inputs)
    except (RegToolError, OSError) as exc:
        sys.stderr.write("[reg_parse] fatal: %s\n" % exc)
        return 1

    stats = Stats()
    inputs_meta = []
    fh, should_close = _open_jsonl(args.jsonl)
    try:
        for path in paths:
            stats.hives_total += 1
            try:
                with open(path, "rb") as handle:
                    raw = handle.read()
            except OSError as exc:
                stats.hives_failed += 1
                stats.errors.append({"path": path, "error": "cannot_read: %s" % exc})
                continue
            sha = sha256_bytes(raw)
            inputs_meta.append({"path": os.path.basename(path), "size": len(raw), "sha256": sha})
            try:
                hive = Hive(raw, os.path.basename(path))
            except RegfError as exc:
                stats.hives_failed += 1
                stats.errors.append({"path": path, "error": str(exc)})
                continue
            except Exception as exc:  # noqa: BLE001
                stats.hives_failed += 1
                stats.errors.append({"path": path, "error": "unexpected: %r" % exc})
                continue

            if args.list_path is not None:
                print("== %s (version %s, last written %s, root %r)" % (path, hive.version, hive.last_written, hive.root()["name"]))
                print_key_listing(hive, args.list_path, args.list_depth, args.list_limit)

            stats.hives_parsed += 1
            for w in hive.warnings:
                stats.count_warning(w)
            emitted_before = stats.emitted
            try:
                for rec in run_extractors(hive, sha, selected, explicit, stats, args.raw):
                    fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
                    stats.emitted += 1
                    stats.by_artifact[rec["artifact"]] += 1
                    if args.limit is not None and stats.emitted >= args.limit:
                        stats.warnings.add("stopped_early_by_limit")
                        break
            except RegfError as exc:
                stats.errors.append({"path": path, "error": "regf: %s" % exc})
            except Exception as exc:  # noqa: BLE001
                stats.errors.append({"path": path, "error": "unexpected: %r" % exc})
            if not explicit and stats.emitted == emitted_before:
                stats.errors.append({"path": path, "error": "no supported registry artifact detected in this hive"})
            stats.total_bytes_read += hive._bytes_read
            if args.limit is not None and stats.emitted >= args.limit:
                break
    finally:
        if should_close:
            fh.close()

    report = build_report(stats, args, inputs_meta)
    if args.report:
        try:
            with open(args.report, "w", encoding="utf-8", newline="\n") as report_handle:
                json.dump(report, report_handle, indent=2, ensure_ascii=False)
                report_handle.write("\n")
        except OSError as exc:
            sys.stderr.write("[reg_parse] fatal: cannot write report: %s\n" % exc)
            return 1
    _print_summary(report, args.quiet)
    return 0


if __name__ == "__main__":
    sys.exit(main())
