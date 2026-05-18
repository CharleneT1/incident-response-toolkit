#!/usr/bin/env python3
"""
Phishing Analyzer - Analyze email headers for phishing indicators.

Checks SPF, DKIM, and DMARC DNS records, flags header anomalies,
mismatched sender domains, and suspicious routing patterns.
Outputs a structured risk report with a scored verdict.

Example usage:
    # Analyze a raw .eml file
    python phishing_analyzer.py -f suspicious.eml

    # Pipe raw headers from stdin
    cat email_headers.txt | python phishing_analyzer.py --stdin

    # Save JSON report
    python phishing_analyzer.py -f suspicious.eml -o report.json

Sample header block (minimal):
    From: "Bank Support" <support@bank-secure-login.com>
    To: victim@example.com
    Reply-To: attacker@gmail.com
    Received: from unknown (1.2.3.4) by mail.example.com
    Message-ID: <abc123@bank-secure-login.com>
    Subject: Urgent: Verify your account
    DKIM-Signature: v=1; a=rsa-sha256; d=bank-secure-login.com; ...
"""

import re
import json
import argparse
import sys
from dataclasses import dataclass, field, asdict
from email import message_from_string
from email.headerregistry import Address
from pathlib import Path
from typing import Optional

try:
    import dns.resolver
    import dns.exception
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    severity: str          # "high" | "medium" | "low" | "info"
    category: str
    detail: str
    score: int             # risk points contributed


@dataclass
class DnsCheckResult:
    record_type: str
    queried: str
    found: bool
    value: Optional[str] = None
    error: Optional[str] = None


@dataclass
class PhishingReport:
    subject: str = ""
    from_address: str = ""
    reply_to: Optional[str] = None
    message_id: Optional[str] = None
    received_chain: list[str] = field(default_factory=list)
    dns_checks: list[DnsCheckResult] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    risk_score: int = 0
    verdict: str = "unknown"   # "clean" | "suspicious" | "likely_phishing"

    def add_finding(self, severity: str, category: str, detail: str, score: int) -> None:
        self.findings.append(Finding(severity, category, detail, score))
        self.risk_score += score

    def finalize_verdict(self) -> None:
        if self.risk_score >= 60:
            self.verdict = "likely_phishing"
        elif self.risk_score >= 25:
            self.verdict = "suspicious"
        else:
            self.verdict = "clean"


# ---------------------------------------------------------------------------
# DNS helpers
# ---------------------------------------------------------------------------

def _query_txt(domain: str, prefix: str = "") -> DnsCheckResult:
    target = f"{prefix}{domain}" if prefix else domain
    result = DnsCheckResult(record_type="TXT", queried=target, found=False)
    if not DNS_AVAILABLE:
        result.error = "dnspython not installed"
        return result
    try:
        answers = dns.resolver.resolve(target, "TXT", lifetime=5)
        txts = [b.decode() for rdata in answers for b in rdata.strings]
        result.found = bool(txts)
        result.value = "; ".join(txts)
    except dns.resolver.NXDOMAIN:
        result.error = "NXDOMAIN"
    except dns.resolver.NoAnswer:
        result.error = "No TXT record"
    except dns.exception.DNSException as exc:
        result.error = str(exc)
    return result


def check_spf(domain: str) -> DnsCheckResult:
    result = _query_txt(domain)
    result.record_type = "SPF"
    if result.value:
        spf_records = [r for r in result.value.split("; ") if r.startswith("v=spf1")]
        result.found = bool(spf_records)
        result.value = spf_records[0] if spf_records else None
        if not result.found:
            result.error = "No SPF record in TXT responses"
    return result


def check_dmarc(domain: str) -> DnsCheckResult:
    result = _query_txt(domain, prefix="_dmarc.")
    result.record_type = "DMARC"
    if result.value:
        dmarc = [r for r in result.value.split("; ") if "v=DMARC1" in r]
        result.found = bool(dmarc)
        result.value = dmarc[0] if dmarc else result.value
    return result


def check_dkim(domain: str, selector: str = "default") -> DnsCheckResult:
    result = _query_txt(domain, prefix=f"{selector}._domainkey.")
    result.record_type = "DKIM"
    if result.value:
        result.found = "p=" in result.value
    return result


# ---------------------------------------------------------------------------
# Header parsing helpers
# ---------------------------------------------------------------------------

_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_RECEIVED_FROM_RE = re.compile(r"from\s+(\S+)\s+\(([^)]+)\)", re.IGNORECASE)

FREE_MAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
    "protonmail.com", "aol.com", "icloud.com", "mail.com",
}

SUSPICIOUS_KEYWORDS = re.compile(
    r"urgent|verify|suspend|account|login|secure|click here|confirm|update|alert|limited",
    re.IGNORECASE,
)

LOOKALIKE_TLDS = re.compile(r"\.(xyz|top|tk|ml|ga|cf|click|download|zip|mov)$", re.IGNORECASE)


def _extract_domain(address: str) -> Optional[str]:
    """Pull the domain part from an email address string."""
    match = re.search(r"@([\w.\-]+)", address)
    return match.group(1).lower() if match else None


def _parse_dkim_selector(headers: dict[str, str]) -> Optional[str]:
    dkim = headers.get("dkim-signature", "")
    m = re.search(r"\bs=([^;\s]+)", dkim)
    return m.group(1) if m else None


def _extract_received_ips(received_headers: list[str]) -> list[str]:
    ips = []
    for hdr in received_headers:
        ips.extend(_IP_RE.findall(hdr))
    # Deduplicate while preserving order
    seen: set[str] = set()
    return [ip for ip in ips if not (ip in seen or seen.add(ip))]  # type: ignore[func-returns-value]


# ---------------------------------------------------------------------------
# Analysis logic
# ---------------------------------------------------------------------------

def analyze_headers(raw: str) -> PhishingReport:
    msg = message_from_string(raw)
    report = PhishingReport()

    # --- Basic fields ---
    report.subject = msg.get("Subject", "")
    report.from_address = msg.get("From", "")
    report.reply_to = msg.get("Reply-To")
    report.message_id = msg.get("Message-ID")
    report.received_chain = msg.get_all("Received") or []

    headers_lower = {k.lower(): v for k, v in msg.items()}
    from_domain = _extract_domain(report.from_address)
    reply_domain = _extract_domain(report.reply_to) if report.reply_to else None

    # --- DNS checks ---
    if from_domain:
        spf = check_spf(from_domain)
        report.dns_checks.append(spf)

        dmarc = check_dmarc(from_domain)
        report.dns_checks.append(dmarc)

        selector = _parse_dkim_selector(headers_lower) or "default"
        dkim = check_dkim(from_domain, selector)
        report.dns_checks.append(dkim)

        if not spf.found:
            report.add_finding("high", "SPF", f"No SPF record for {from_domain}", 25)

        if not dmarc.found:
            report.add_finding("medium", "DMARC", f"No DMARC record for {from_domain}", 15)

        if not dkim.found:
            report.add_finding("medium", "DKIM", f"DKIM lookup failed for {from_domain} (selector={selector})", 15)

    # --- Reply-To mismatch ---
    if reply_domain and from_domain and reply_domain != from_domain:
        score = 30 if reply_domain in FREE_MAIL_DOMAINS else 20
        report.add_finding(
            "high", "Header anomaly",
            f"Reply-To domain ({reply_domain}) differs from From domain ({from_domain})",
            score,
        )

    # --- Suspicious subject ---
    if SUSPICIOUS_KEYWORDS.search(report.subject):
        report.add_finding("medium", "Subject", f"Subject contains phishing keywords: {report.subject!r}", 10)

    # --- Lookalike TLD ---
    if from_domain and LOOKALIKE_TLDS.search(from_domain):
        report.add_finding("high", "Domain", f"From domain uses suspicious TLD: {from_domain}", 20)

    # --- Message-ID domain mismatch ---
    if report.message_id and from_domain:
        mid_domain = _extract_domain(report.message_id.strip("<>"))
        if mid_domain and mid_domain != from_domain:
            report.add_finding(
                "medium", "Header anomaly",
                f"Message-ID domain ({mid_domain}) doesn't match From domain ({from_domain})",
                10,
            )

    # --- Received chain analysis ---
    received_ips = _extract_received_ips(report.received_chain)
    if received_ips:
        report.add_finding(
            "info", "Network",
            f"Routing IPs in Received chain: {', '.join(received_ips)}",
            0,
        )

    if len(report.received_chain) > 6:
        report.add_finding("medium", "Network", "Unusually long Received chain (>6 hops) — possible relay abuse", 10)

    # --- X-Originating-IP check ---
    orig_ip = headers_lower.get("x-originating-ip", "").strip()
    if orig_ip:
        report.add_finding("info", "Network", f"X-Originating-IP: {orig_ip}", 0)

    # --- Authentication-Results ---
    auth_results = headers_lower.get("authentication-results", "")
    if auth_results:
        if "spf=fail" in auth_results.lower():
            report.add_finding("high", "SPF", "Authentication-Results reports SPF fail", 25)
        if "dkim=fail" in auth_results.lower():
            report.add_finding("high", "DKIM", "Authentication-Results reports DKIM fail", 20)
        if "dmarc=fail" in auth_results.lower():
            report.add_finding("high", "DMARC", "Authentication-Results reports DMARC fail", 20)

    report.finalize_verdict()
    return report


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def read_input(args: argparse.Namespace) -> str:
    if args.stdin:
        return sys.stdin.read()
    if args.file:
        return Path(args.file).read_text(errors="replace")
    raise ValueError("No input provided. Use -f or --stdin.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Analyze email headers for phishing indicators.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    src = parser.add_mutually_exclusive_group()
    src.add_argument("-f", "--file", metavar="PATH", help="Path to .eml or header file")
    src.add_argument("--stdin", action="store_true", help="Read from stdin")
    parser.add_argument("-o", "--output", metavar="PATH", help="Write JSON report to file")
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if not (args.file or args.stdin):
        parser.print_help()
        sys.exit(1)

    if not DNS_AVAILABLE:
        print("Warning: dnspython not installed — DNS checks disabled. Run: pip install dnspython", file=sys.stderr)

    try:
        raw = read_input(args)
    except OSError as exc:
        print(f"Error reading input: {exc}", file=sys.stderr)
        sys.exit(1)

    report = analyze_headers(raw)

    print(f"\nVerdict : {report.verdict.upper()}", file=sys.stderr)
    print(f"Risk score: {report.risk_score}/100+", file=sys.stderr)
    print(f"Findings  : {len(report.findings)}", file=sys.stderr)
    for f in report.findings:
        print(f"  [{f.severity.upper():6s}] {f.category}: {f.detail}", file=sys.stderr)

    output = json.dumps(asdict(report), indent=2)
    if args.output:
        Path(args.output).write_text(output)
        print(f"\nReport saved to {args.output}", file=sys.stderr)
    else:
        print(output)


if __name__ == "__main__":
    main()
