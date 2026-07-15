#!/usr/bin/env python3
"""
Cisco Type 7 password decoder.

Cisco 'Type 7' passwords use a fixed Vigenere key and are trivially
reversible (they are obfuscation, not encryption). This decodes them
back to cleartext.

Usage:
    ./cisco7_decode.py                          # decode the built-in sample list
    ./cisco7_decode.py 08014249001C254641585B   # decode one or more hashes
    ./cisco7_decode.py -f config.txt            # extract & decode all Type 7 strings in a file

The Type 7 format: first 2 chars = salt/offset index into the key,
remaining chars = hex byte pairs XORed against key[(salt + i) % len(key)].
"""

import argparse
import re
import sys

# Cisco's hardcoded Type 7 key (spells "dsfd;kfoA,.iyewrkldJKD..." etc.)
KEY = [
    0x64, 0x73, 0x66, 0x64, 0x3b, 0x6b, 0x66, 0x6f, 0x41, 0x2c, 0x2e,
    0x69, 0x79, 0x65, 0x77, 0x72, 0x6b, 0x6c, 0x64, 0x4a, 0x4b, 0x44,
    0x48, 0x53, 0x55, 0x42, 0x73, 0x67, 0x76, 0x63, 0x61, 0x36, 0x39,
    0x38, 0x33, 0x34, 0x6e, 0x63, 0x78, 0x76, 0x39, 0x38, 0x37, 0x33,
    0x32, 0x35, 0x34, 0x6b, 0x3b, 0x66, 0x67, 0x38, 0x37,
]


def decode(h):
    """Decode a single Cisco Type 7 hash string to cleartext."""
    try:
        salt = int(h[:2])
    except ValueError:
        return None
    out = ""
    for i in range(2, len(h), 2):
        try:
            byte = int(h[i:i + 2], 16)
        except ValueError:
            return None
        out += chr(byte ^ KEY[(salt + (i - 2) // 2) % len(KEY)])
    return out


# Type 7 strings look like: even length, first two chars are a small
# decimal salt (00-15), the rest hex.
TYPE7_RE = re.compile(r'\b(0[0-9]|1[0-5])([0-9A-Fa-f]{2,})\b')


def extract_from_file(path):
    """Pull candidate Type 7 strings out of a config file."""
    found = []
    with open(path, 'r', errors='ignore') as f:
        for line in f:
            for m in TYPE7_RE.finditer(line):
                candidate = m.group(0)
                if len(candidate) % 2 == 0:
                    found.append(candidate)
    return found


# Sample list (replace or pass your own via args / -f).
SAMPLE = [
    "08014249001C254641585B",
    "022C2455582B2F2F",
    "082B45420539091E1801",
    "023F544E280701607F1D5A1456",
    "023557581C4C048634837442426392C107A19",
    "02345457074701",
    "08116C5A0C15",
]


def main():
    parser = argparse.ArgumentParser(description="Cisco Type 7 password decoder.")
    parser.add_argument("hashes", nargs="*", help="Type 7 hash string(s) to decode.")
    parser.add_argument("-f", "--file", help="Extract and decode all Type 7 strings from a config file.")
    args = parser.parse_args()

    targets = []
    if args.file:
        targets = extract_from_file(args.file)
        if not targets:
            print("No Type 7 strings found in file.", file=sys.stderr)
            sys.exit(1)
    elif args.hashes:
        targets = args.hashes
    else:
        targets = SAMPLE

    for h in targets:
        result = decode(h)
        if result is None:
            print(f"{h} -> [decode error]")
        else:
            print(f"{h} -> {result}")


if __name__ == "__main__":
    main()
