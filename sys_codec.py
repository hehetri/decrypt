#!/usr/bin/env python3
"""Codec helper for old-game ftinfo.sys and bulinfo.sys files.

The reverse-engineered game code opens these files as text, reads them line by
line, and tokenizes each useful line with strtok using comma and semicolon as
separators.  Some releases/mods may store the same text with a small binary
header, a single-byte XOR pass, or a common compression wrapper; this tool tries
those variants and picks the most plausible decoded text.
"""

from __future__ import annotations

import argparse
import gzip
import lzma
import re
import shutil
import sys
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional

HEADER_SCAN_LIMIT = 256
SCORE_SAMPLE_LIMIT = 512
PRINTABLE_BYTES = set(range(0x20, 0x7F)) | {0x09, 0x0A, 0x0D}
XOR_TABLES = tuple(bytes(byte ^ key for byte in range(256)) for key in range(256))
COMMON_WORDS = (
    "effect",
    "name",
    "bullet",
    "fire",
    "normal",
    "none",
    "null",
    "id",
    "base",
)


@dataclass(frozen=True)
class DecodeCandidate:
    """A possible interpretation of an input file."""

    method: str
    score: float
    text: str
    payload: bytes
    header: bytes = b""
    key: Optional[int] = None
    compression: Optional[str] = None

    def describe(self) -> str:
        parts = [f"method={self.method}"]
        if self.key is not None:
            parts.append(f"key=0x{self.key:02X}")
        if self.header:
            parts.append(f"header_size={len(self.header)}")
        if self.compression:
            parts.append(f"compression={self.compression}")
        parts.append(f"score={self.score:.2f}")
        return ", ".join(parts)


def xor_bytes(data: bytes, key: int) -> bytes:
    """Return *data* XORed by a single byte key."""

    return data.translate(XOR_TABLES[key & 0xFF])


def decode_text_lossy(data: bytes) -> str:
    """Decode bytes to text while preserving as much old 8-bit data as possible."""

    for encoding in ("utf-8-sig", "cp1252", "latin-1"):
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            continue
    return data.decode("latin-1", errors="replace")


def score_text(text: str, payload: bytes) -> float:
    """Score how likely *text* is to be a comma/semicolon-delimited sys file.

    The heuristic rewards printable text, line breaks, delimiters, numeric fields,
    and common words seen in game data.  It penalizes NUL/control-heavy output and
    mojibake/replacement characters.  Only the first SCORE_SAMPLE_LIMIT bytes are
    scored so that exhaustive XOR/header scans stay fast on large files.
    """

    if not payload:
        return float("-inf")

    sample = payload[:SCORE_SAMPLE_LIMIT]
    sample_text = text[:SCORE_SAMPLE_LIMIT]
    printable = sum(byte in PRINTABLE_BYTES or byte >= 0x80 for byte in sample)
    printable_ratio = printable / len(sample)
    controls = sum(byte < 0x20 and byte not in (0x09, 0x0A, 0x0D) for byte in sample)
    nul_count = sample.count(0)

    delimiter_count = sample_text.count(",") + sample_text.count(";")
    newline_count = sample_text.count("\n") + sample_text.count("\r")
    digit_count = sum(char.isdigit() for char in sample_text)
    word_count = sum(sample_text.lower().count(word) for word in COMMON_WORDS)

    tokenized_lines = 0
    for line in sample_text.splitlines()[:200]:
        stripped = line.strip()
        if not stripped or stripped.startswith(";"):
            continue
        if (line.count(",") + line.count(";")) >= 4:
            tokenized_lines += 1

    score = 0.0
    score += printable_ratio * 100.0
    score += min(newline_count, 200) * 0.35
    score += min(delimiter_count, 1000) * 0.20
    score += min(digit_count, 2000) * 0.08
    score += min(word_count, 100) * 0.80
    score += tokenized_lines * 3.0
    score -= controls * 2.5
    score -= nul_count * 4.0
    score -= sample_text.count("\ufffd") * 10.0

    # Very short header fragments can be printable by accident. Prefer text that
    # contains the delimiters used by the real parser.
    if sample_text.strip() and delimiter_count == 0:
        score -= 25.0
    return score

def split_sys_fields(line: str) -> list[str]:
    """Split a sys line like C strtok(line, ``,;'') would do.

    Empty tokens are discarded, matching strtok behavior.
    """

    if "," in line or ";" in line:
        return [field.strip() for field in re.split(r"[,;]", line) if field.strip()]
    # Some extracted files in the wild are tab-separated even though the game
    # tokenizer seen in Ghidra uses comma/semicolon.  This fallback keeps inspect
    # useful for those files without changing comma/semicolon behavior.
    return [field.strip() for field in line.split("\t") if field.strip()]


def parse_int(value: str) -> int:
    """Parse decimal or 0x-prefixed integer fields.

    Python's int(value, 0) rejects old-style leading-zero decimals such as
    ``0300``.  The game data appears to use those as decimal strings, so only
    explicit 0x prefixes are treated as hexadecimal.
    """

    cleaned = value.strip()
    if cleaned.lower().startswith(("0x", "+0x", "-0x")):
        return int(cleaned, 16)
    return int(cleaned, 10)


def parse_ftinfo(text: str) -> list[dict[str, int]]:
    """Parse ftinfo.sys text into dictionaries matching the 0x14-byte struct.

    Invalid lines are skipped and reported on stderr.
    """

    rows: list[dict[str, int]] = []
    for line_no, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith(";"):
            continue
        fields = split_sys_fields(raw_line)
        if len(fields) < 6:
            warn(f"ftinfo line {line_no}: expected at least 6 fields, got {len(fields)}")
            continue
        try:
            rows.append(
                {
                    "id_base": parse_int(fields[0]),
                    "value1": parse_int(fields[2]),
                    "value2": parse_int(fields[3]),
                    "value3": parse_int(fields[4]),
                    "value4": parse_int(fields[5]),
                }
            )
        except ValueError as exc:
            warn(f"ftinfo line {line_no}: invalid integer ({exc})")
    return rows


def parse_bulinfo(text: str) -> list[dict[str, int | str]]:
    """Parse bulinfo.sys text into dictionaries matching the 0x4c-byte struct.

    The effect_index is generated from unique effect_name values in first-seen
    order, matching a typical unique-effect table built while parsing.
    """

    rows: list[dict[str, int | str]] = []
    effect_indexes: dict[str, int] = {}
    for line_no, raw_line in enumerate(text.splitlines(), start=1):
        if raw_line.startswith((";", "\n", "\r")) or not raw_line.strip():
            continue
        fields = split_sys_fields(raw_line)
        if len(fields) < 5:
            warn(f"bulinfo line {line_no}: expected at least 5 fields, got {len(fields)}")
            continue
        name = fields[1]
        effect_name = fields[3]
        if len(name.encode("cp1252", errors="replace")) > 64:
            warn(f"bulinfo line {line_no}: name is longer than probable 64-byte buffer")
        if effect_name not in effect_indexes:
            effect_indexes[effect_name] = len(effect_indexes)
        try:
            rows.append(
                {
                    "name": name,
                    "value1": parse_int(fields[2]),
                    "effect_name": effect_name,
                    "effect_index": effect_indexes[effect_name],
                    "value2": parse_int(fields[4]),
                }
            )
        except ValueError as exc:
            warn(f"bulinfo line {line_no}: invalid integer ({exc})")
    return rows


def warn(message: str) -> None:
    """Print a warning in a PowerShell-friendly way."""

    print(f"warning: {message}", file=sys.stderr)


def compression_candidates(data: bytes) -> Iterable[tuple[str, bytes]]:
    """Yield successful zlib/gzip/lzma decompressions for *data*.

    Decompressors are only attempted when the payload has a plausible signature.
    That still tests the requested formats while avoiding very slow failed lzma
    probes for every possible header offset.
    """

    if data.startswith(b"\x1f\x8b"):
        try:
            yield "gzip", gzip.decompress(data)
        except Exception:
            pass
    if data.startswith((b"\x78\x01", b"\x78\x5e", b"\x78\x9c", b"\x78\xda")):
        try:
            yield "zlib", zlib.decompress(data)
        except Exception:
            pass
    if data.startswith(b"\xfd7zXZ\x00"):
        try:
            yield "lzma", lzma.decompress(data)
        except Exception:
            pass


def candidate_from_payload(
    *,
    method: str,
    payload: bytes,
    header: bytes = b"",
    key: Optional[int] = None,
    compression: Optional[str] = None,
) -> DecodeCandidate:
    sample_payload = payload[:SCORE_SAMPLE_LIMIT]
    sample_text = decode_text_lossy(sample_payload)
    return DecodeCandidate(
        method=method,
        score=score_text(sample_text, sample_payload),
        text=sample_text,
        payload=payload,
        header=header,
        key=key,
        compression=compression,
    )


def materialize_candidate(data: bytes, candidate: DecodeCandidate) -> DecodeCandidate:
    """Rebuild a full-payload candidate from its compact scored form."""

    body = data[len(candidate.header) :]
    if candidate.method == "xor":
        if candidate.key is None:
            raise ValueError("XOR candidate without key")
        payload = xor_bytes(body, candidate.key)
    elif candidate.method == "compressed":
        matches = [
            decompressed
            for name, decompressed in compression_candidates(body)
            if name == candidate.compression
        ]
        payload = matches[0] if matches else candidate.payload
    else:
        payload = body
    return DecodeCandidate(
        method=candidate.method,
        score=candidate.score,
        text=decode_text_lossy(payload),
        payload=payload,
        header=candidate.header,
        key=candidate.key,
        compression=candidate.compression,
    )

def find_decode_candidates(data: bytes) -> list[DecodeCandidate]:
    """Try plain text, all single-byte XOR keys, headers, and compression."""

    candidates: list[DecodeCandidate] = []
    max_header = min(HEADER_SCAN_LIMIT, len(data))

    for header_size in range(max_header + 1):
        header = data[:header_size]
        body = data[header_size:]
        body_sample = body[:SCORE_SAMPLE_LIMIT]
        candidates.append(candidate_from_payload(method="plain", payload=body_sample, header=header))

        # This loop includes key 0x00 and 0xFF, satisfying both the exhaustive
        # single-byte search and the explicit XOR-0xFF requirement.
        for key in range(0x100):
            decoded_sample = xor_bytes(body_sample, key)
            candidates.append(
                candidate_from_payload(method="xor", payload=decoded_sample, header=header, key=key)
            )

        for comp_name, decompressed in compression_candidates(body):
            candidates.append(
                candidate_from_payload(
                    method="compressed",
                    payload=decompressed,
                    header=header,
                    compression=comp_name,
                )
            )

    candidates.sort(key=lambda candidate: candidate.score, reverse=True)
    for index in range(min(20, len(candidates))):
        candidates[index] = materialize_candidate(data, candidates[index])
    return candidates

def detect_kind(path: Path, text: str) -> str:
    """Guess which parser should be demonstrated for inspect output."""

    name = path.name.lower()
    if "ftinfo" in name:
        return "ftinfo"
    if "bulinfo" in name:
        return "bulinfo"

    ft_rows = parse_ftinfo(text)
    bul_rows = parse_bulinfo(text)
    if len(ft_rows) >= len(bul_rows):
        return "ftinfo"
    return "bulinfo"


def best_candidate(path: Path) -> DecodeCandidate:
    data = path.read_bytes()
    if not data:
        raise SystemExit(f"error: empty input file: {path}")
    return find_decode_candidates(data)[0]


def backup_if_needed(path: Path) -> None:
    """Create a .bak copy before overwriting an existing file."""

    if path.exists():
        backup = path.with_name(path.name + ".bak")
        shutil.copy2(path, backup)
        print(f"backup: {backup}")


def ensure_can_write(path: Path, force: bool) -> None:
    """Refuse overwrites unless --force was supplied."""

    if path.exists() and not force:
        raise SystemExit(f"error: output exists: {path} (use --force to overwrite)")
    if force:
        backup_if_needed(path)


def write_text_output(path: Path, text: str, force: bool) -> None:
    ensure_can_write(path, force)
    path.write_text(text, encoding="utf-8", newline="")


def encode_bytes(
    text: str, method: str, key: int, header_size: int, header_bytes: bytes | None = None
) -> bytes:
    """Encode text with optional zero-filled header and XOR."""

    if header_bytes is not None:
        header_size = len(header_bytes)
    if not 0 <= header_size <= HEADER_SCAN_LIMIT:
        raise SystemExit(f"error: --header-size must be between 0 and {HEADER_SCAN_LIMIT}")
    payload = text.encode("utf-8")
    if method == "plain":
        encoded = payload
    elif method == "xor":
        encoded = xor_bytes(payload, key)
    else:
        raise SystemExit(f"error: unsupported method: {method}")
    header = header_bytes if header_bytes is not None else (b"\x00" * header_size)
    return header + encoded


def parse_key(value: str) -> int:
    key = int(value, 0)
    if not 0 <= key <= 0xFF:
        raise argparse.ArgumentTypeError("key must be between 0x00 and 0xFF")
    return key


def command_inspect(args: argparse.Namespace) -> None:
    path = Path(args.input)
    candidates = find_decode_candidates(path.read_bytes())
    if not candidates:
        raise SystemExit("error: no decode candidates generated")

    print(f"input: {path}")
    print(f"size: {path.stat().st_size} bytes")
    print("best candidates:")
    for index, candidate in enumerate(candidates[: args.top], start=1):
        preview = candidate.text[:120].replace("\r", "\\r").replace("\n", "\\n")
        print(f"  {index:02d}. {candidate.describe()} preview={preview!r}")

    best = candidates[0]
    kind = detect_kind(path, best.text)
    rows = parse_ftinfo(best.text) if kind == "ftinfo" else parse_bulinfo(best.text)
    print(f"detected_kind: {kind}")
    print(f"parsed_rows: {len(rows)}")


def command_decode(args: argparse.Namespace) -> None:
    candidate = best_candidate(Path(args.input))
    write_text_output(Path(args.output), candidate.text, args.force)
    print(f"decoded: {candidate.describe()}")
    print(f"wrote: {args.output}")


def command_encode(args: argparse.Namespace) -> None:
    input_path = Path(args.input)
    output_path = Path(args.output)
    text = input_path.read_text(encoding="utf-8-sig")
    data = encode_bytes(text, args.method, args.key, args.header_size)
    ensure_can_write(output_path, args.force)
    output_path.write_bytes(data)
    print(
        f"encoded: method={args.method}, key=0x{args.key:02X}, "
        f"header_size={args.header_size}"
    )
    print(f"wrote: {output_path}")


def command_roundtrip(args: argparse.Namespace) -> None:
    input_path = Path(args.input)
    output_path = Path(args.output)
    candidate = best_candidate(input_path)
    key = candidate.key if candidate.key is not None else args.key
    method = "xor" if candidate.method == "xor" else "plain"
    if candidate.method == "xor":
        data = candidate.header + xor_bytes(candidate.payload, key)
    elif candidate.method == "plain":
        data = candidate.header + candidate.payload
    else:
        # Compression is detected for decode/inspect, but the command-line
        # encoder intentionally supports only plain and XOR.  Fall back to a
        # plain text output for rare compressed inputs.
        data = encode_bytes(candidate.text, "plain", key, len(candidate.header), candidate.header)
    ensure_can_write(output_path, args.force)
    output_path.write_bytes(data)
    print(f"decoded: {candidate.describe()}")
    print(f"roundtrip_encoded: method={method}, key=0x{key:02X}, header_size={len(candidate.header)}")
    print(f"wrote: {output_path}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Inspect, decode, encode, and roundtrip ftinfo.sys/bulinfo.sys text data."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    inspect_parser = subparsers.add_parser("inspect", help="show likely decode methods and parser stats")
    inspect_parser.add_argument("input", metavar="arquivo.sys")
    inspect_parser.add_argument("--top", type=int, default=5, help="number of candidates to display")
    inspect_parser.set_defaults(func=command_inspect)

    decode_parser = subparsers.add_parser("decode", help="decode a sys file to UTF-8 text")
    decode_parser.add_argument("input", metavar="arquivo.sys")
    decode_parser.add_argument("output", metavar="saida.txt")
    decode_parser.add_argument("--force", action="store_true", help="overwrite output and create .bak")
    decode_parser.set_defaults(func=command_decode)

    encode_parser = subparsers.add_parser("encode", help="encode UTF-8 text to a sys file")
    encode_parser.add_argument("input", metavar="entrada.txt")
    encode_parser.add_argument("output", metavar="saida.sys")
    encode_parser.add_argument("--method", choices=("plain", "xor"), default="plain")
    encode_parser.add_argument("--key", type=parse_key, default=0xFF, help="XOR key, e.g. 0xFF")
    encode_parser.add_argument("--header-size", type=int, default=0, help="zero-filled header bytes")
    encode_parser.add_argument("--force", action="store_true", help="overwrite output and create .bak")
    encode_parser.set_defaults(func=command_encode)

    roundtrip_parser = subparsers.add_parser("roundtrip", help="decode and re-encode using the detected method")
    roundtrip_parser.add_argument("input", metavar="arquivo.sys")
    roundtrip_parser.add_argument("output", metavar="teste.sys")
    roundtrip_parser.add_argument("--key", type=parse_key, default=0xFF, help="fallback XOR key")
    roundtrip_parser.add_argument("--force", action="store_true", help="overwrite output and create .bak")
    roundtrip_parser.set_defaults(func=command_roundtrip)

    return parser


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    args.func(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
