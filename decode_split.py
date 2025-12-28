#!/usr/bin/env python3
"""
Decode a Base64-encoded, XOR-obfuscated blob, then split it into:
  1) full decrypted buffer (decrypted.bin)
  2) stub (loader shellcode) (stub.bin)
  3) payload (embedded PE, typically a DLL) (payload.bin / payload.dll)

Decoding steps:
  - read text file (Base64; whitespace/newlines allowed)
  - base64-decode to bytes
  - XOR every byte with key 0x5A
Splitting logic:
  - by default, find the first "MZ" header *after* some offset (search_start)
    and split at that position (stub = [0:pos], payload = [pos:])
  - alternatively, you can force a stub size (e.g., 1023) with --stub-size

Usage example:
python3 decode_split.py 170-x64-2.txt --outdir out --prefix sample --overwrite
This will create three files in out/:
    - sample_decrypted.bin (entire decoded buffer)
    - sample_stub.bin (everything before the embedded PE)
    - sample_payload.dll (embedded PE starting at "MZ")

If the stub size is known in advance:
python3 decode_split.py 170-x64-2.txt --stub-size 1023 --outdir out --prefix sample --overwrite
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import os
from pathlib import Path
from typing import Optional, Tuple


DEFAULT_XOR_KEY = 0x5A


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def md5_hex(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


def read_b64_text(path: Path) -> str:
    # Read as text, keep all chars; base64 decoder will ignore whitespace if validate=False
    return path.read_text(encoding="utf-8", errors="ignore")


def b64_decode_relaxed(b64_text: str) -> bytes:
    # Remove obvious whitespace; base64.b64decode can handle whitespace too, but stripping improves resilience.
    cleaned = "".join(b64_text.split())
    try:
        return base64.b64decode(cleaned, validate=False)
    except (binascii.Error, ValueError) as e:
        raise ValueError(f"Base64 decode failed: {e}") from e


def xor_bytes(buf: bytes, key: int) -> bytes:
    if not (0 <= key <= 255):
        raise ValueError("XOR key must be a single byte (0..255).")
    b = bytearray(buf)
    for i in range(len(b)):
        b[i] ^= key
    return bytes(b)


def find_payload_offset_by_mz(decrypted: bytes, search_start: int = 0) -> Optional[int]:
    """
    Find the first occurrence of b'MZ' (PE header signature) after search_start.
    Returns the index, or None if not found.
    """
    if search_start < 0:
        search_start = 0
    idx = decrypted.find(b"MZ", search_start)
    return idx if idx != -1 else None


def split_stub_payload(
    decrypted: bytes,
    stub_size: Optional[int],
    search_start: int,
) -> Tuple[bytes, bytes, int]:
    """
    Split decrypted data into (stub, payload, offset).

    If stub_size is provided, split at that exact size.
    Otherwise, search for 'MZ' after search_start and split at that position.
    """
    if stub_size is not None:
        if stub_size <= 0 or stub_size >= len(decrypted):
            raise ValueError(f"--stub-size must be between 1 and {len(decrypted)-1}.")
        offset = stub_size
        return decrypted[:offset], decrypted[offset:], offset

    mz_off = find_payload_offset_by_mz(decrypted, search_start=search_start)
    if mz_off is None:
        raise ValueError(
            "Could not find 'MZ' signature in decrypted buffer. "
            "Try specifying --stub-size explicitly, or adjust --search-start."
        )
    if mz_off == 0:
        raise ValueError(
            "Found 'MZ' at offset 0 (decrypted buffer begins with a PE). "
            "In that case, stub would be empty; use --stub-size if you expect a stub."
        )
    return decrypted[:mz_off], decrypted[mz_off:], mz_off


def write_file(path: Path, data: bytes, overwrite: bool) -> None:
    if path.exists() and not overwrite:
        raise FileExistsError(f"Refusing to overwrite existing file: {path} (use --overwrite)")
    path.write_bytes(data)


def guess_payload_extension(payload: bytes) -> str:
    """
    Very lightweight heuristic: if payload starts with 'MZ' we can call it .dll or .exe.
    PE is not fully parsed here; default to .dll since for this case, it is typically a DLL.
    """
    if payload.startswith(b"MZ"):
        return ".dll"
    return ".bin"


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Decode Base64+XOR blob and split into decrypted/stub/payload files."
    )
    ap.add_argument("input", type=Path, help="Path to input Base64 text file (e.g., 170-x64-2.txt)")
    ap.add_argument(
        "-k",
        "--key",
        type=lambda s: int(s, 0),
        default=DEFAULT_XOR_KEY,
        help="XOR key byte (default: 0x5A). Accepts decimal or 0x.. hex.",
    )
    ap.add_argument(
        "-o",
        "--outdir",
        type=Path,
        default=Path("."),
        help="Output directory (default: current directory).",
    )
    ap.add_argument(
        "--prefix",
        type=str,
        default="decoded",
        help="Output filename prefix (default: decoded).",
    )
    ap.add_argument(
        "--stub-size",
        type=int,
        default=None,
        help="Force stub size in bytes (if you already know it). If omitted, script searches for 'MZ'.",
    )
    ap.add_argument(
        "--search-start",
        type=lambda s: int(s, 0),
        default=256,
        help="When auto-splitting, start searching for 'MZ' at this offset (default: 256).",
    )
    ap.add_argument(
        "--overwrite",
        action="store_true",
        help="Overwrite output files if they already exist.",
    )
    args = ap.parse_args()

    args.outdir.mkdir(parents=True, exist_ok=True)

    # 1) Read + Base64 decode
    b64_text = read_b64_text(args.input)
    encoded = b64_decode_relaxed(b64_text)

    # 2) XOR decode
    decrypted = xor_bytes(encoded, args.key)

    # 3) Split stub/payload
    stub, payload, off = split_stub_payload(
        decrypted,
        stub_size=args.stub_size,
        search_start=args.search_start,
    )

    # 4) Decide payload extension (mostly cosmetic)
    payload_ext = guess_payload_extension(payload)

    # 5) Write outputs
    full_path = args.outdir / f"{args.prefix}_decrypted.bin"
    stub_path = args.outdir / f"{args.prefix}_stub.bin"
    payload_path = args.outdir / f"{args.prefix}_payload{payload_ext}"

    write_file(full_path, decrypted, args.overwrite)
    write_file(stub_path, stub, args.overwrite)
    write_file(payload_path, payload, args.overwrite)

    # 6) Print a useful summary for forensics notes
    print("=== Decode + Split Summary ===")
    print(f"Input file:            {args.input}")
    print(f"Output directory:      {args.outdir.resolve()}")
    print(f"XOR key:               0x{args.key:02X} ({args.key})")
    print("")
    print(f"Base64 decoded size:   {len(encoded):,} bytes")
    print(f"Decrypted size:        {len(decrypted):,} bytes")
    print(f"Split offset:          {off:,} (0x{off:X})")
    print(f"Stub size:             {len(stub):,} bytes")
    print(f"Payload size:          {len(payload):,} bytes")
    print("")
    print("Files written:")
    print(f"  - {full_path}  (SHA-256: {sha256_hex(decrypted)})")
    print(f"  - {stub_path}  (SHA-256: {sha256_hex(stub)})")
    print(f"  - {payload_path}  (SHA-256: {sha256_hex(payload)}, MD5: {md5_hex(payload)})")

    # Basic sanity hint: if payload is a PE, it should start with MZ
    if payload.startswith(b"MZ"):
        print("\nSanity check: payload begins with 'MZ' (looks like a PE file).")
    else:
        print("\nSanity check: payload does NOT begin with 'MZ'. If you expected a PE, try --stub-size or --search-start.")

    return 0

if __name__ == "__main__":
    raise SystemExit(main())
