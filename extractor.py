#!/usr/bin/env python3
import re
import os
import sys
import json
import gzip
import base64
import hashlib
from pathlib import Path

PRINTABLE_MIN = 4

def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def sha1(data: bytes) -> str:
    return hashlib.sha1(data).hexdigest()

def md5(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()

def hexdump(data: bytes, width: int = 16, limit: int = 256) -> str:
    lines = []
    chunk = data[:limit]
    for i in range(0, len(chunk), width):
        row = chunk[i:i+width]
        hexpart = " ".join(f"{b:02x}" for b in row)
        asciipart = "".join(chr(b) if 32 <= b <= 126 else "." for b in row)
        lines.append(f"{i:08x}  {hexpart:<{width*3}}  {asciipart}")
    return "\n".join(lines)

def extract_strings(data: bytes, min_len: int = PRINTABLE_MIN):
    cur = []
    out = []
    for b in data:
        if 32 <= b <= 126:
            cur.append(chr(b))
        else:
            if len(cur) >= min_len:
                out.append("".join(cur))
            cur = []
    if len(cur) >= min_len:
        out.append("".join(cur))
    return out

def fail(msg: str):
    print(f"[!] {msg}", file=sys.stderr)
    sys.exit(1)

def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <input.txt> <output_dir>")
        sys.exit(1)

    input_path = Path(sys.argv[1])
    out_dir = Path(sys.argv[2])
    out_dir.mkdir(parents=True, exist_ok=True)

    raw_text = input_path.read_text(encoding="utf-8", errors="ignore")

    # Stage 0: pull -encodedcommand blob
    m = re.search(r'-encodedcommand\s+([A-Za-z0-9+/=]+)', raw_text, re.IGNORECASE)
    if not m:
        fail("Could not find -encodedcommand blob")

    outer_b64 = m.group(1)

    # Stage 1: decode UTF-16LE PowerShell
    try:
        stage1 = base64.b64decode(outer_b64).decode("utf-16le", errors="strict")
    except Exception as e:
        fail(f"Failed to decode outer EncodedCommand: {e}")

    (out_dir / "stage1.ps1").write_text(stage1, encoding="utf-8")

    # Stage 2: find embedded gzip/base64 payload
    m = re.search(r'FromBase64String\("([^"]+)"\)', stage1)
    if not m:
        fail("Could not find stage2 base64+gzip blob in stage1")

    inner_b64 = m.group(1)
    try:
        stage2_gz = base64.b64decode(inner_b64)
        stage2 = gzip.decompress(stage2_gz).decode("utf-8", errors="ignore")
    except Exception as e:
        fail(f"Failed to decode/decompress stage2: {e}")

    (out_dir / "stage2.ps1").write_text(stage2, encoding="utf-8")

    # Stage 3: find shellcode container
    m = re.search(r"\$var_code\s*=\s*\[System\.Convert\]::FromBase64String\('([^']+)'\)", stage2)
    if not m:
        fail("Could not find shellcode base64 blob in stage2")

    shellcode_b64 = m.group(1)
    try:
        encoded_shellcode = base64.b64decode(shellcode_b64)
    except Exception as e:
        fail(f"Failed to base64-decode shellcode blob: {e}")

    # XOR decode with key 0x23
    shellcode = bytes(b ^ 0x23 for b in encoded_shellcode)

    # Save payload artifacts
    (out_dir / "shellcode.bin").write_bytes(shellcode)
    (out_dir / "shellcode.hex.txt").write_text(hexdump(shellcode, limit=len(shellcode)), encoding="utf-8")

    strings = extract_strings(shellcode)
    (out_dir / "shellcode.strings.txt").write_text("\n".join(strings), encoding="utf-8")

    metadata = {
        "input_file": str(input_path),
        "stage1_length": len(stage1),
        "stage2_length": len(stage2),
        "shellcode_size": len(shellcode),
        "shellcode_sha256": sha256(shellcode),
        "shellcode_sha1": sha1(shellcode),
        "shellcode_md5": md5(shellcode),
        "first_32_bytes_hex": shellcode[:32].hex(),
        "possible_iocs": [s for s in strings if "." in s or "Mozilla" in s or "MSIE" in s][:50],
        "note": "This script only decodes and writes artifacts. It never executes the payload."
    }
    (out_dir / "metadata.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")

    print("[+] Wrote:")
    print(f"    {out_dir / 'stage1.ps1'}")
    print(f"    {out_dir / 'stage2.ps1'}")
    print(f"    {out_dir / 'shellcode.bin'}")
    print(f"    {out_dir / 'shellcode.hex.txt'}")
    print(f"    {out_dir / 'shellcode.strings.txt'}")
    print(f"    {out_dir / 'metadata.json'}")
    print()
    print("[+] Preview:")
    print(hexdump(shellcode, limit=128))
    print()
    print("[+] Top printable strings:")
    for s in strings[:20]:
        print(f"    {s}")

if __name__ == "__main__":
    main()
