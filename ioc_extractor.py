#!/usr/bin/env python3
"""
IOC Extractor - Extract Indicators of Compromise from log files or text input.

Extracts IPv4, IPv6, domain names, URLs, and MD5/SHA1/SHA256 hashes,
then outputs results in MISP-compatible JSON format.

Example usage:
    # From a log file
    python ioc_extractor.py -f /var/log/syslog -o iocs.json

    # From stdin
    cat suspicious.log | python ioc_extractor.py --stdin

    # From a text string
    python ioc_extractor.py -t "Suspicious connection from 192.168.1.100 to malware.example.com"

    # Filter by IOC type
    python ioc_extractor.py -f access.log --types ip domain
"""

import re
import json
import argparse
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


PATTERNS: dict[str, re.Pattern] = {
    "ipv4": re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
        r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
    ),
    "ipv6": re.compile(
        r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b"
        r"|\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b"
        r"|\b::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}\b"
        r"|\b(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}\b"
    ),
    "url": re.compile(
        r"\bhttps?://[^\s\"'<>\]\[(){},;]+",
        re.IGNORECASE,
    ),
    "domain": re.compile(
        r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
        r"(?:com|net|org|edu|gov|mil|int|io|co|info|biz|me|tv|cc|us|uk|de|fr|ru|cn"
        r"|xyz|top|site|online|shop|app|dev|cloud|tech|ai)\b",
        re.IGNORECASE,
    ),
    "md5": re.compile(r"\b[0-9a-fA-F]{32}\b"),
    "sha1": re.compile(r"\b[0-9a-fA-F]{40}\b"),
    "sha256": re.compile(r"\b[0-9a-fA-F]{64}\b"),
}

# Private/reserved IPv4 ranges to optionally filter
PRIVATE_IP_PREFIXES = (
    "10.", "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
    "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
    "172.30.", "172.31.", "192.168.", "127.", "0.", "169.254.",
)

# MISP attribute type mapping
MISP_TYPE_MAP: dict[str, str] = {
    "ipv4": "ip-dst",
    "ipv6": "ip-dst",
    "url": "url",
    "domain": "domain",
    "md5": "md5",
    "sha1": "sha1",
    "sha256": "sha256",
}

MISP_CATEGORY_MAP: dict[str, str] = {
    "ipv4": "Network activity",
    "ipv6": "Network activity",
    "url": "Network activity",
    "domain": "Network activity",
    "md5": "Payload delivery",
    "sha1": "Payload delivery",
    "sha256": "Payload delivery",
}


def extract_iocs(text: str, types: Optional[list[str]] = None, exclude_private: bool = True) -> dict[str, list[str]]:
    """Extract all IOC types from text, returning deduplicated results per type."""
    active_types = types if types else list(PATTERNS.keys())
    results: dict[str, list[str]] = {t: [] for t in active_types}

    # Extract SHA256 first, then SHA1, then MD5 to avoid substring collisions
    found_hashes: set[str] = set()

    for ioc_type in ["sha256", "sha1", "md5"]:
        if ioc_type not in active_types:
            continue
        for match in PATTERNS[ioc_type].finditer(text):
            val = match.group(0).lower()
            if val not in found_hashes:
                found_hashes.add(val)
                results[ioc_type].append(val)

    # Remove hash strings before scanning for other types to reduce false positives
    cleaned = text
    for h in found_hashes:
        cleaned = cleaned.replace(h, " ")

    for ioc_type in active_types:
        if ioc_type in ("sha256", "sha1", "md5"):
            continue
        seen: set[str] = set()
        for match in PATTERNS[ioc_type].finditer(cleaned):
            val = match.group(0)
            # Strip URLs that are already captured from domain matches
            if ioc_type == "domain":
                if any(val in url for url in results.get("url", [])):
                    continue
            if ioc_type in ("ipv4",) and exclude_private:
                if any(val.startswith(pfx) for pfx in PRIVATE_IP_PREFIXES):
                    continue
            if val not in seen:
                seen.add(val)
                results[ioc_type].append(val)

    return {k: v for k, v in results.items() if v}


def to_misp_event(iocs: dict[str, list[str]], source: str = "ioc_extractor") -> dict:
    """Wrap extracted IOCs in a MISP-compatible event envelope."""
    attributes = []
    for ioc_type, values in iocs.items():
        misp_type = MISP_TYPE_MAP.get(ioc_type, ioc_type)
        category = MISP_CATEGORY_MAP.get(ioc_type, "External analysis")
        for value in values:
            attributes.append({
                "uuid": str(uuid.uuid4()),
                "type": misp_type,
                "category": category,
                "value": value,
                "to_ids": ioc_type not in ("url",),
                "comment": f"Extracted by ioc_extractor from {source}",
                "timestamp": int(datetime.now(timezone.utc).timestamp()),
            })

    return {
        "Event": {
            "uuid": str(uuid.uuid4()),
            "info": f"IOCs extracted from {source}",
            "date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
            "threat_level_id": "3",
            "analysis": "0",
            "distribution": "0",
            "Attribute": attributes,
        }
    }


def read_input(args: argparse.Namespace) -> tuple[str, str]:
    """Return (text, source_label) based on CLI arguments."""
    if args.stdin:
        return sys.stdin.read(), "stdin"
    if args.text:
        return args.text, "cli-text"
    if args.file:
        path = Path(args.file)
        return path.read_text(errors="replace"), path.name
    raise ValueError("No input provided. Use -f, -t, or --stdin.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Extract IOCs from log files or text and output MISP-compatible JSON.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    src = parser.add_mutually_exclusive_group()
    src.add_argument("-f", "--file", metavar="PATH", help="Path to log file")
    src.add_argument("-t", "--text", metavar="TEXT", help="Inline text to parse")
    src.add_argument("--stdin", action="store_true", help="Read from stdin")

    parser.add_argument(
        "-o", "--output", metavar="PATH",
        help="Write JSON output to file (default: stdout)",
    )
    parser.add_argument(
        "--types", nargs="+",
        choices=list(PATTERNS.keys()),
        metavar="TYPE",
        help="Limit extraction to these IOC types (default: all)",
    )
    parser.add_argument(
        "--include-private", action="store_true",
        help="Include RFC-1918 / loopback IP addresses",
    )
    parser.add_argument(
        "--raw", action="store_true",
        help="Output raw IOC dict instead of MISP event envelope",
    )
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if not any([args.file, args.text, args.stdin]):
        parser.print_help()
        sys.exit(1)

    try:
        text, source = read_input(args)
    except (ValueError, OSError) as exc:
        print(f"Error reading input: {exc}", file=sys.stderr)
        sys.exit(1)

    iocs = extract_iocs(
        text,
        types=args.types,
        exclude_private=not args.include_private,
    )

    total = sum(len(v) for v in iocs.values())
    print(f"Extracted {total} IOC(s) from {source}", file=sys.stderr)
    for ioc_type, values in iocs.items():
        print(f"  {ioc_type}: {len(values)}", file=sys.stderr)

    output = iocs if args.raw else to_misp_event(iocs, source)
    json_out = json.dumps(output, indent=2)

    if args.output:
        Path(args.output).write_text(json_out)
        print(f"Saved to {args.output}", file=sys.stderr)
    else:
        print(json_out)


if __name__ == "__main__":
    main()
