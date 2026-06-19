#!/usr/bin/env python3
"""
APK Triage - Static first-look triage of Android applications.

Designed for the early "is this worth a deeper look?" step of mobile incident
response, before a full reverse-engineering pass. It:

  * Parses AndroidManifest.xml -- both the binary AXML form found inside a real
    .apk and the plaintext form produced by decompilers (jadx / apktool).
  * Flags dangerous permissions and maps them to MITRE ATT&CK (Mobile) where a
    confident mapping exists.
  * Highlights suspicious permission combinations (e.g. SMS + INTERNET) that are
    common in spyware / banker / premium-fraud families.
  * Flags exported components reachable without permission protection.
  * Extracts embedded URLs / domains / IPs and file hashes as IOCs, reusing the
    ioc_extractor module, and emits a MISP-compatible event.

This is a triage aid, not a verdict engine. ATT&CK mappings are indicative.

Example usage:
    # Real packaged app
    python apk_triage.py -f sample.apk

    # Decompiled / source manifest
    python apk_triage.py -f AndroidManifest.xml

    # Save the JSON report (and the MISP event alongside)
    python apk_triage.py -f sample.apk -o triage.json --misp iocs.json
"""

import argparse
import hashlib
import json
import re
import sys
import zipfile
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional

# Reuse the existing IOC extractor for string-derived indicators.
try:
    from ioc_extractor import extract_iocs, to_misp_event
    IOC_AVAILABLE = True
except ImportError:
    IOC_AVAILABLE = False


# ---------------------------------------------------------------------------
# Knowledge base
# ---------------------------------------------------------------------------

# Dangerous permission -> (ATT&CK Mobile technique id, technique name).
# Only mappings we are reasonably confident about are listed here; other
# dangerous permissions are still flagged, just without a forced technique id.
PERMISSION_ATTACK_MAP: dict[str, tuple[str, str]] = {
    "android.permission.SEND_SMS": ("T1582", "SMS Control"),
    "android.permission.READ_SMS": ("T1636.004", "Protected User Data: SMS Messages"),
    "android.permission.RECEIVE_SMS": ("T1636.004", "Protected User Data: SMS Messages"),
    "android.permission.READ_CONTACTS": ("T1636.003", "Protected User Data: Contact List"),
    "android.permission.READ_CALL_LOG": ("T1636.002", "Protected User Data: Call Log"),
    "android.permission.ACCESS_FINE_LOCATION": ("T1430", "Location Tracking"),
    "android.permission.ACCESS_COARSE_LOCATION": ("T1430", "Location Tracking"),
    "android.permission.ACCESS_BACKGROUND_LOCATION": ("T1430", "Location Tracking"),
    "android.permission.RECORD_AUDIO": ("T1429", "Audio Capture"),
    "android.permission.CAMERA": ("T1512", "Video Capture"),
    "android.permission.READ_PHONE_STATE": ("T1426", "System Information Discovery"),
    "android.permission.RECEIVE_BOOT_COMPLETED": ("T1624.001", "Event Triggered Execution: Broadcast Receivers"),
    "android.permission.SYSTEM_ALERT_WINDOW": ("T1417.002", "Input Capture: GUI Input Capture"),
    "android.permission.BIND_DEVICE_ADMIN": ("T1626", "Abuse Elevation Control Mechanism"),
}

# Dangerous permissions without a confident single-technique mapping.
OTHER_DANGEROUS_PERMISSIONS: set[str] = {
    "android.permission.WRITE_SETTINGS",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.GET_ACCOUNTS",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.CALL_PHONE",
    "android.permission.PROCESS_OUTGOING_CALLS",
    "android.permission.DISABLE_KEYGUARD",
    "android.permission.WAKE_LOCK",
}

# Permission combinations that frequently indicate a specific abuse pattern.
# Each entry: (required permissions, description, extra risk points).
SUSPICIOUS_COMBOS: list[tuple[set[str], str, int]] = [
    ({"android.permission.READ_SMS", "android.permission.INTERNET"},
     "SMS read + network access -> potential SMS/2FA exfiltration", 25),
    ({"android.permission.RECEIVE_SMS", "android.permission.INTERNET"},
     "SMS interception + network access -> potential 2FA theft / OTP relay", 25),
    ({"android.permission.SEND_SMS", "android.permission.INTERNET"},
     "Outbound SMS + network access -> potential premium-SMS fraud", 20),
    ({"android.permission.RECORD_AUDIO", "android.permission.INTERNET"},
     "Microphone + network access -> potential audio surveillance", 20),
    ({"android.permission.ACCESS_FINE_LOCATION", "android.permission.INTERNET"},
     "Precise location + network access -> potential location tracking", 15),
    ({"android.permission.READ_CONTACTS", "android.permission.INTERNET"},
     "Contacts + network access -> potential contact-list exfiltration", 15),
    ({"android.permission.SYSTEM_ALERT_WINDOW", "android.permission.RECEIVE_BOOT_COMPLETED"},
     "Overlay + boot persistence -> common banker/overlay-trojan pattern", 20),
]

COMPONENT_TAGS = ("activity", "service", "receiver", "provider")

# Minimum sensible minSdkVersion. Below this the app installs on Android
# releases that predate modern platform mitigations (scoped storage, stricter
# exported defaults, cleartext-blocked-by-default networking).
MIN_SAFE_SDK = 24

# launchMode values (string form from decompilers, integer form from binary
# AXML: 2=singleTask, 3=singleInstance) that, with a shared/empty taskAffinity,
# open a task-hijacking / overlay (StrandHogg) surface.
TASK_HIJACK_LAUNCH_MODES = {"singleTask", "singleInstance", "2", "3"}

# protectionLevel values that make a custom permission no real guard -- any app
# can request and hold them. String form from decompilers, integer form from
# binary AXML (0=normal, 1=dangerous; 2=signature is the safe one).
WEAK_PROTECTION_LEVELS = {"normal", "dangerous", "0", "1"}

# Intent actions that, when a component is registered for them, indicate auto-start
# persistence rather than mere permission declaration.
PERSISTENCE_ACTIONS = {
    "android.intent.action.BOOT_COMPLETED",
    "android.intent.action.LOCKED_BOOT_COMPLETED",
    "android.intent.action.QUICKBOOT_POWERON",
}

# Dangerous permission -> the hardware feature it implies. If the permission is
# requested while the feature is declared android:required="false", the app is
# widening its install base on devices that lack the hardware -- a known Play
# Store filtering bypass that maximises attack surface.
PERMISSION_FEATURE_MAP: dict[str, str] = {
    "android.permission.CAMERA": "android.hardware.camera",
    "android.permission.ACCESS_FINE_LOCATION": "android.hardware.location.gps",
    "android.permission.ACCESS_COARSE_LOCATION": "android.hardware.location.network",
    "android.permission.RECORD_AUDIO": "android.hardware.microphone",
}

# Behavioural indicators recovered from DEX strings. These catch techniques that
# need no suspicious manifest permission at all (e.g. clipboard theft, covert
# local logging, exfiltration to request-capture services).
#
# Each entry carries a `kind` that records how obfuscation-resistant it is, so
# the output can be honest about confidence:
#   API_REF  -> a framework class/method reference. R8/ProGuard cannot rename or
#               encrypt it without breaking the call, so it survives obfuscation.
#   DATA_STR -> a literal string constant. Plaintext under plain R8, but defeated
#               by string encryption (DexGuard etc.) -- treat as a soft signal.
API_REF = "api-ref"
DATA_STR = "data-string"

_ROBUSTNESS_NOTE = {
    API_REF: "obfuscation-resistant: framework API reference",
    DATA_STR: "soft signal: plaintext string, defeated by string encryption",
}

# Entries: (pattern, severity, category, description, points, kind).
# `severity` (risk) and `kind` (obfuscation-robustness) are orthogonal: a finding
# can be high-risk yet only a soft signal, or robust yet low-risk -- so they are
# recorded separately rather than derived from one another.
SUSPICIOUS_STRING_INDICATORS: list[tuple[re.Pattern, str, str, str, int, str]] = [
    # --- Behavioural indicators (need no suspicious manifest permission) ---
    (re.compile(r"getPrimaryClip|Landroid/content/ClipboardManager;"),
     "high", "Behavioral indicator", "clipboard access API in code -> possible clipboard hijacking (T1414)", 12, API_REF),
    (re.compile(r"webhook\.site", re.I),
     "medium", "Behavioral indicator", "webhook.site reference -> common data-exfil / capture endpoint", 15, DATA_STR),
    (re.compile(r"requestbin|pipedream\.net|burpcollaborator|interactsh|\boast\b", re.I),
     "medium", "Behavioral indicator", "request-capture service reference -> possible exfil endpoint", 15, DATA_STR),
    (re.compile(r"/\.\w+/\.[\w.]*log\b", re.I),
     "medium", "Behavioral indicator", "hidden dotfile log path -> possible covert local logging / staging", 8, DATA_STR),

    # --- WebView misconfiguration (OWASP MASVS-PLATFORM / MASVS-NETWORK) ---
    (re.compile(r"addJavascriptInterface"),
     "high", "WebView", "addJavascriptInterface -> JS-to-native bridge; RCE surface if exposed to untrusted content (MASTG-TEST-0031)", 15, API_REF),
    (re.compile(r"setAllowFileAccessFromFileURLs|setAllowUniversalAccessFromFileURLs|setAllowFileAccess\b"),
     "medium", "WebView", "WebView local file access enabled -> can read local files / cross-origin from file:// (MASVS-PLATFORM)", 8, API_REF),
    (re.compile(r"onReceivedSslError"),
     "high", "WebView", "custom onReceivedSslError handler -> may call proceed() and bypass TLS validation (MASTG-TEST-0034)", 15, API_REF),

    # --- Weak cryptography (OWASP MASVS-CRYPTO) ---
    (re.compile(r'"DES"|"DESede"|/ECB/|"AES/ECB|"RC4"'),
     "medium", "Crypto", "weak/ECB cipher (DES, RC4, or ECB mode) -> insecure encryption (MASTG-TEST-0014)", 10, DATA_STR),
    (re.compile(r'"MD5"|"MD4"|"SHA-1"|"SHA1"'),
     "low", "Crypto", "broken hash (MD5/SHA-1) referenced -> not collision-resistant (MASVS-CRYPTO)", 6, DATA_STR),
    (re.compile(r"Ljava/util/Random;"),
     "low", "Crypto", "java.util.Random -> not cryptographically secure; use SecureRandom for keys/tokens (MASVS-CRYPTO)", 5, API_REF),

    # --- Dynamic code execution (OWASP MASVS-CODE / MASVS-RESILIENCE) ---
    (re.compile(r"Ldalvik/system/(Dex|Path|InMemoryDex)ClassLoader;|Ldalvik/system/DexFile;"),
     "high", "Code loading", "dynamic dex/class loading -> can run code absent at install/scan time (MASVS-CODE)", 15, API_REF),
    (re.compile(r"Ljava/lang/Runtime;|Ljava/lang/ProcessBuilder;"),
     "medium", "Code loading", "native command execution API (Runtime.exec / ProcessBuilder) (MASVS-CODE)", 8, API_REF),

    # --- Anti-analysis / environment awareness (OWASP MASVS-RESILIENCE) ---
    (re.compile(r"/system/(xbin|bin|sbin)/su\b|Superuser\.apk|com\.noshufou\.android\.su|eu\.chainfire|\bmagisk\b", re.I),
     "medium", "Anti-analysis", "root-detection / root-artifact strings -> environment-aware behaviour (MASVS-RESILIENCE)", 8, DATA_STR),
    (re.compile(r"\bfrida\b|frida-server|gum-js-loop|\bxposed\b|de\.robv\.android\.xposed|libsubstrate", re.I),
     "medium", "Anti-analysis", "anti-instrumentation references (Frida/Xposed/Substrate) -> anti-analysis (MASVS-RESILIENCE)", 8, DATA_STR),
]


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    severity: str          # "high" | "medium" | "low" | "info"
    category: str
    detail: str
    score: int
    attack: Optional[str] = None   # ATT&CK technique id, when applicable


@dataclass
class TriageReport:
    source: str = ""
    package: Optional[str] = None
    apk_sha256: Optional[str] = None
    dex_sha256: list[str] = field(default_factory=list)
    permissions: list[str] = field(default_factory=list)
    exported_components: list[str] = field(default_factory=list)
    iocs: dict[str, list[str]] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    risk_score: int = 0
    verdict: str = "unknown"   # "low_risk" | "review" | "high_risk"

    def add_finding(self, severity: str, category: str, detail: str,
                    score: int, attack: Optional[str] = None) -> None:
        self.findings.append(Finding(severity, category, detail, score, attack))
        self.risk_score += score

    def finalize_verdict(self) -> None:
        if self.risk_score >= 60:
            self.verdict = "high_risk"
        elif self.risk_score >= 25:
            self.verdict = "review"
        else:
            self.verdict = "low_risk"


# ---------------------------------------------------------------------------
# Binary AndroidManifest (AXML) parser
# ---------------------------------------------------------------------------
#
# AXML is Android's compiled binary XML format. We implement just enough of it
# to recover element tags and their attributes -- no external dependency.

_AXML_MAGIC = b"\x03\x00\x08\x00"

_RES_STRING_POOL = 0x0001
_RES_XML_START_ELEMENT = 0x0102
_UTF8_FLAG = 0x0100

# Res_value data types we care about.
_TYPE_STRING = 0x03
_TYPE_INT_BOOLEAN = 0x12


def _u16(data: bytes, off: int) -> int:
    return int.from_bytes(data[off:off + 2], "little")


def _u32(data: bytes, off: int) -> int:
    return int.from_bytes(data[off:off + 4], "little")


def _parse_string_pool(data: bytes, start: int) -> list[str]:
    """Parse a RES_STRING_POOL chunk located at `start`, return its strings."""
    string_count = _u32(data, start + 8)
    flags = _u32(data, start + 16)
    strings_start = _u32(data, start + 20)
    is_utf8 = bool(flags & _UTF8_FLAG)

    offsets = [_u32(data, start + 28 + i * 4) for i in range(string_count)]
    base = start + strings_start
    out: list[str] = []
    for off in offsets:
        pos = base + off
        try:
            if is_utf8:
                # Two varint-style lengths (char count, then byte count).
                pos += 1 if not (data[pos] & 0x80) else 2
                byte_len = data[pos]
                if byte_len & 0x80:
                    byte_len = ((byte_len & 0x7F) << 8) | data[pos + 1]
                    pos += 2
                else:
                    pos += 1
                out.append(data[pos:pos + byte_len].decode("utf-8", "replace"))
            else:
                char_len = _u16(data, pos)
                pos += 2
                if char_len & 0x8000:
                    char_len = ((char_len & 0x7FFF) << 16) | _u16(data, pos)
                    pos += 2
                out.append(data[pos:pos + char_len * 2].decode("utf-16-le", "replace"))
        except (IndexError, UnicodeDecodeError):
            out.append("")
    return out


def _resolve_attr_value(data: bytes, attr_off: int, pool: list[str]) -> str:
    raw_value = _u32(data, attr_off + 8)
    data_type = data[attr_off + 15]
    typed_data = _u32(data, attr_off + 16)

    def pool_get(i: int) -> str:
        return pool[i] if 0 <= i < len(pool) else ""

    if raw_value != 0xFFFFFFFF and pool_get(raw_value):
        return pool_get(raw_value)
    if data_type == _TYPE_STRING:
        return pool_get(typed_data)
    if data_type == _TYPE_INT_BOOLEAN:
        return "true" if typed_data not in (0,) else "false"
    return str(typed_data)


def parse_axml(data: bytes) -> list[tuple[str, dict[str, str]]]:
    """Parse binary AXML, return [(tag, {attr_local_name: value}), ...]."""
    if data[:4] != _AXML_MAGIC:
        raise ValueError("not a binary AXML manifest")

    # Locate the string pool (first chunk after the 8-byte file header).
    pool: list[str] = []
    off = 8
    if _u16(data, off) == _RES_STRING_POOL:
        pool = _parse_string_pool(data, off)

    elements: list[tuple[str, dict[str, str]]] = []
    off = 8
    n = len(data)
    while off + 8 <= n:
        chunk_type = _u16(data, off)
        chunk_size = _u32(data, off + 4)
        if chunk_size <= 0:
            break
        if chunk_type == _RES_XML_START_ELEMENT:
            name_idx = _u32(data, off + 20)
            tag = pool[name_idx] if 0 <= name_idx < len(pool) else ""
            attr_start = _u16(data, off + 24)
            attr_count = _u16(data, off + 28)
            attrs: dict[str, str] = {}
            base = off + 16 + attr_start  # attrExt begins after the 16-byte node header
            for i in range(attr_count):
                a = base + i * 20
                if a + 20 > n:
                    break
                name_i = _u32(data, a + 4)
                attr_name = pool[name_i] if 0 <= name_i < len(pool) else ""
                attrs[attr_name] = _resolve_attr_value(data, a, pool)
            elements.append((tag, attrs))
        off += chunk_size
    return elements


# ---------------------------------------------------------------------------
# Plaintext manifest parser (decompiled output)
# ---------------------------------------------------------------------------

_ANDROID_NS = "{http://schemas.android.com/apk/res/android}"


def parse_text_manifest(text: str) -> list[tuple[str, dict[str, str]]]:
    """Parse a plaintext AndroidManifest.xml (jadx/apktool output)."""
    import xml.etree.ElementTree as ET

    root = ET.fromstring(text)
    elements: list[tuple[str, dict[str, str]]] = []
    for el in root.iter():
        attrs = {k.replace(_ANDROID_NS, ""): v for k, v in el.attrib.items()}
        # The root <manifest> carries package as a plain (non-android) attr.
        elements.append((el.tag, attrs))
    return elements


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------

def _sha256(blob: bytes) -> str:
    return hashlib.sha256(blob).hexdigest()


_PRINTABLE = re.compile(rb"[\x20-\x7e]{6,}")


def _extract_strings(blob: bytes) -> str:
    return "\n".join(m.group().decode("ascii", "ignore") for m in _PRINTABLE.finditer(blob))


# Reverse-DNS roots that mark a token as a Java/Kotlin package name rather than a
# network domain. A real hostname is read TLD-last (evil.example.com); a package
# is read root-first (com.example.evil), so a token whose *leftmost* label is one
# of these is a package, not a domain -- even though it ends in a valid TLD.
_PACKAGE_DOMAIN_ROOTS = frozenset({
    "com", "org", "net", "io", "edu", "gov", "mil", "biz", "info",
    "android", "androidx", "kotlin", "kotlinx", "java", "javax", "dalvik",
    "sun", "jdk", "okhttp3", "okio", "retrofit2", "reactivex", "rx", "dagger",
    "junit", "gnu", "scala", "groovy", "kotlinpoet",
})


# URL hosts that are XML/spec namespace or schema identifiers, not network
# endpoints. They appear throughout DEX strings as namespace URIs (manifest
# attributes, ID3/TTML/XMP parsers) and are never C2/exfil indicators.
_NAMESPACE_URL_HOSTS = frozenset({
    "schemas.android.com", "schemas.microsoft.com", "www.w3.org",
    "ns.adobe.com", "www.id3.org", "xmlpull.org", "java.sun.com",
    "purl.org", "iptc.org",
})

# Reserved / placeholder TLDs (RFC 2606 + common sentinels). A host ending in
# one of these is never a real network endpoint (default.url, foo.invalid).
# A denylist is used deliberately: an allowlist of valid TLDs would risk
# dropping real exfil hosts on newer TLDs (t.me, *.vercel.app).
_PLACEHOLDER_TLDS = frozenset({
    "url", "invalid", "example", "test", "local", "localhost", "lan", "internal",
})


def _is_noise_url(url: str) -> bool:
    """True if a URL-shaped token is not a real network endpoint.

    DEX strings carry XML/spec namespace URIs (http://schemas.android.com/...,
    http://www.w3.org/ns/...) and truncated placeholders (https://x) that match
    the URL regex but are never C2/exfil indicators. This drops them so the URL
    list reflects reviewable network endpoints, mirroring _is_package_like for
    the domain list.
    """
    from urllib.parse import urlparse

    host = (urlparse(url).hostname or "").lower()
    if host in _NAMESPACE_URL_HOSTS:
        return True
    # No dot in the host -> not a routable FQDN (https://x, http://localhost).
    if "." not in host:
        return True
    # A reserved/placeholder TLD marks a sentinel host (default.url, foo.invalid)
    # rather than a real domain.
    if host.rsplit(".", 1)[-1] in _PLACEHOLDER_TLDS:
        return True
    return False


def _is_package_like(domain: str) -> bool:
    """True if a domain-shaped token is really a package name / mangled identifier.

    DEX strings are full of reverse-DNS package names (com.foo.bar,
    androidx.appcompat.app, io.ktor.utils.io) and R8-mangled identifiers (f.Tv)
    that match the domain regex but are not network indicators. This drops them;
    the URL list remains the reliable source of network IOCs from a DEX.
    """
    labels = domain.split(".")
    first = labels[0].lower()
    # Leftmost label is a reverse-DNS/package root (also after stripping a
    # length-prefix digit artifact, e.g. "9com.mardous.booming" -> "com...").
    if first in _PACKAGE_DOMAIN_ROOTS or first.lstrip("0123456789") in _PACKAGE_DOMAIN_ROOTS:
        return True
    # Any uppercase letter -> a mangled class/identifier (f.Tv), not a hostname,
    # which in DEX strings is consistently lowercase.
    if any(c.isupper() for c in domain):
        return True
    return False


def analyze_manifest(elements: list[tuple[str, dict[str, str]]], report: TriageReport) -> None:
    permissions: list[str] = []
    actions: set[str] = set()
    not_required_features: set[str] = set()
    exported_providers: list[str] = []
    app_attrs: dict[str, str] = {}
    has_application = False
    min_sdk: Optional[str] = None
    custom_perms: list[tuple[str, str]] = []
    hijackable: list[str] = []
    for tag, attrs in elements:
        if tag == "manifest" and attrs.get("package"):
            report.package = attrs["package"]
        elif tag == "uses-permission":
            name = attrs.get("name")
            if name:
                permissions.append(name)
        elif tag == "uses-feature":
            name = attrs.get("name")
            if name and attrs.get("required", "true").lower() == "false":
                not_required_features.add(name)
        elif tag == "uses-sdk":
            if attrs.get("minSdkVersion"):
                min_sdk = attrs["minSdkVersion"]
        elif tag == "application":
            has_application = True
            app_attrs = attrs
        elif tag == "permission":
            name = attrs.get("name")
            if name:
                custom_perms.append((name, attrs.get("protectionLevel", "normal")))
        elif tag == "action":
            name = attrs.get("name")
            if name:
                actions.add(name)
        elif tag in COMPONENT_TAGS:
            comp_name = attrs.get("name", "<unnamed>")
            exported = attrs.get("exported", "").lower() == "true"
            has_permission = bool(attrs.get("permission"))
            if exported and not has_permission:
                report.exported_components.append(f"{tag}:{comp_name}")
                if tag == "provider":
                    exported_providers.append(comp_name)
            if tag == "activity" and (
                attrs.get("launchMode") in TASK_HIJACK_LAUNCH_MODES
                or attrs.get("taskAffinity") == ""  # explicitly empty affinity
            ):
                hijackable.append(comp_name)

    report.permissions = sorted(set(permissions))
    perm_set = set(report.permissions)

    # Per-permission findings.
    for perm in report.permissions:
        if perm in PERMISSION_ATTACK_MAP:
            tid, tname = PERMISSION_ATTACK_MAP[perm]
            report.add_finding(
                "high", "Permission",
                f"{perm} -> {tid} ({tname})", 10, attack=tid,
            )
        elif perm in OTHER_DANGEROUS_PERMISSIONS:
            report.add_finding("medium", "Permission", f"Dangerous permission: {perm}", 5)

    # Suspicious combinations.
    for required, desc, points in SUSPICIOUS_COMBOS:
        if required.issubset(perm_set):
            report.add_finding("high", "Permission combo", desc, points)

    # Boot persistence: a component actually registered for a boot broadcast,
    # confirming auto-start intent beyond the permission declaration alone.
    boot_actions = actions & PERSISTENCE_ACTIONS
    if boot_actions:
        report.add_finding(
            "high", "Persistence",
            "Component registered for "
            + ", ".join(sorted(a.rsplit(".", 1)[-1] for a in boot_actions))
            + " -> auto-starts after reboot without user interaction",
            10, attack="T1624.001",
        )

    # Permission / hardware-feature mismatch (Play Store filtering bypass): a
    # dangerous permission requested while its hardware feature is optional.
    for perm, feature in PERMISSION_FEATURE_MAP.items():
        if perm in perm_set and feature in not_required_features:
            report.add_finding(
                "medium", "Distribution",
                f"{perm} requested but {feature} marked required=false "
                "-> widens install base / Play Store filtering bypass",
                10,
            )

    # Exported content providers are a direct, queryable data-leak surface.
    if exported_providers:
        report.add_finding(
            "high", "Component",
            "Exported content provider(s) without permission guard -> "
            "data queryable by any app: " + ", ".join(exported_providers[:6]),
            20,
        )

    # Other exported components without permission protection.
    other_exported = [c for c in report.exported_components if not c.startswith("provider:")]
    if other_exported:
        report.add_finding(
            "medium", "Component",
            f"{len(other_exported)} exported component(s) without permission guard: "
            + ", ".join(other_exported[:6]),
            10,
        )

    # --- App-level hardening flags (OWASP MASVS / MASTG static checks) ---
    # These read clear-text manifest attributes Android must honour, so they
    # hold up even on a fully obfuscated APK.

    # Debuggable build -> runtime inspection and memory dumps.
    if app_attrs.get("debuggable", "").lower() == "true":
        report.add_finding(
            "high", "Hardening",
            "android:debuggable=true -> app is debuggable; allows runtime "
            "inspection and memory dumps (MASVS-RESILIENCE)",
            15,
        )

    # Backup allowed -> app data extractable over adb without root. Absent
    # defaults to enabled below Android 12, so call that out too (softly).
    backup = app_attrs.get("allowBackup")
    if backup is not None and backup.lower() == "true":
        report.add_finding(
            "medium", "Hardening",
            "android:allowBackup=true -> app data extractable via `adb backup` "
            "(MASVS-STORAGE)",
            8,
        )
    elif backup is None and has_application:
        report.add_finding(
            "low", "Hardening",
            "android:allowBackup not set -> defaults to enabled below Android 12; "
            "app data may be extractable via `adb backup` (MASVS-STORAGE)",
            3,
        )

    # Cleartext HTTP permitted -> MITM exposure.
    if app_attrs.get("usesCleartextTraffic", "").lower() == "true":
        report.add_finding(
            "medium", "Network",
            "android:usesCleartextTraffic=true -> plain HTTP permitted; "
            "MITM exposure (MASVS-NETWORK)",
            8,
        )

    # A network security config can relax TLS (cleartext-permitted, user CA
    # trust). We can't resolve the referenced resource from the manifest alone,
    # so flag it for manual review rather than scoring it.
    if app_attrs.get("networkSecurityConfig"):
        report.add_finding(
            "info", "Network",
            "networkSecurityConfig declared -> review for cleartextTrafficPermitted "
            "and user-added CA trust (MASVS-NETWORK)",
            0,
        )

    # Old minSdk -> installs onto Android versions missing modern mitigations.
    if min_sdk and min_sdk.isdigit() and int(min_sdk) < MIN_SAFE_SDK:
        report.add_finding(
            "low", "Platform",
            f"minSdkVersion={min_sdk} (<{MIN_SAFE_SDK}) -> runs on Android releases "
            "lacking modern platform mitigations (MASVS-PLATFORM)",
            5,
        )

    # Custom permissions that any app can hold are not a real guard.
    weak_perms = [n for n, lvl in custom_perms if lvl.lower() in WEAK_PROTECTION_LEVELS]
    if weak_perms:
        report.add_finding(
            "medium", "Platform",
            "Custom permission(s) with weak protectionLevel (normal/dangerous) -> "
            "any app can hold them; not a real guard: " + ", ".join(weak_perms[:6]),
            8,
        )

    # Task-hijacking / overlay (StrandHogg) surface. Legitimate apps use these
    # too, so keep it low and frame it as a review item.
    if hijackable:
        report.add_finding(
            "low", "Platform",
            "Activity with singleTask/singleInstance launchMode or empty "
            "taskAffinity -> task-hijacking / overlay (StrandHogg) surface; "
            "review: " + ", ".join(hijackable[:6]),
            5,
        )


def analyze_strings(text: str, report: TriageReport) -> None:
    """Flag behavioural indicators (clipboard theft, exfil services, covert logs)
    recovered from extracted code strings. Catches techniques that need no
    suspicious manifest permission."""
    for pattern, severity, category, desc, points, kind in SUSPICIOUS_STRING_INDICATORS:
        if pattern.search(text):
            report.add_finding(severity, category, f"{desc} [{_ROBUSTNESS_NOTE[kind]}]", points)


def analyze_apk(path: Path, report: TriageReport) -> None:
    raw = path.read_bytes()
    report.apk_sha256 = _sha256(raw)

    with zipfile.ZipFile(path) as zf:
        names = zf.namelist()

        if "AndroidManifest.xml" in names:
            manifest_bytes = zf.read("AndroidManifest.xml")
            try:
                elements = parse_axml(manifest_bytes)
            except ValueError:
                elements = parse_text_manifest(manifest_bytes.decode("utf-8", "replace"))
            analyze_manifest(elements, report)
        else:
            report.add_finding("medium", "Structure", "No AndroidManifest.xml in archive", 10)

        # DEX hashes + string-derived IOCs.
        all_strings: list[str] = []
        for name in names:
            if name.endswith(".dex"):
                blob = zf.read(name)
                report.dex_sha256.append(_sha256(blob))
                all_strings.append(_extract_strings(blob))

        combined_strings = "\n".join(all_strings)
        if combined_strings:
            analyze_strings(combined_strings, report)

        if all_strings and IOC_AVAILABLE:
            iocs = extract_iocs(combined_strings, exclude_private=True)
            report.iocs = {k: v for k, v in iocs.items() if k in ("url", "ipv4", "ipv6", "domain")}
            # Domains in DEX strings are dominated by reverse-DNS package names
            # that the regex mistakes for hostnames -- drop those package-shaped
            # tokens so the domain list reflects real network indicators.
            if report.iocs.get("domain"):
                report.iocs["domain"] = [
                    d for d in report.iocs["domain"] if not _is_package_like(d)
                ]
                if not report.iocs["domain"]:
                    del report.iocs["domain"]
            # URLs in DEX strings are padded with XML/spec namespace URIs and
            # placeholder hosts that match the regex but are not endpoints --
            # drop them so the list reflects reviewable network indicators.
            if report.iocs.get("url"):
                report.iocs["url"] = [
                    u for u in report.iocs["url"] if not _is_noise_url(u)
                ]
                if not report.iocs["url"]:
                    del report.iocs["url"]
            if report.iocs.get("url"):
                report.add_finding(
                    "info", "IOC",
                    f"{len(report.iocs['url'])} URL(s) embedded in DEX (review for C2 / exfil endpoints)",
                    0,
                )


def triage(path: Path) -> TriageReport:
    report = TriageReport(source=path.name)
    suffix = path.suffix.lower()

    if suffix == ".apk" or zipfile.is_zipfile(path):
        analyze_apk(path, report)
    else:
        text = path.read_text(errors="replace")
        elements = parse_text_manifest(text)
        analyze_manifest(elements, report)

    report.finalize_verdict()
    return report


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Static triage of an Android APK or AndroidManifest.xml. "
            "This is a fast, dependency-free FIRST-PASS FILTER -- it tells you which "
            "APKs deserve a full tool (MobSF/androguard) and a dynamic pass, not a "
            "complete audit. It reads the manifest and DEX strings only; it does not "
            "run the app, and string indicators degrade under obfuscation."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("-f", "--file", required=True, metavar="PATH",
                        help="Path to .apk or AndroidManifest.xml")
    parser.add_argument("-o", "--output", metavar="PATH", help="Write JSON report to file")
    parser.add_argument("--misp", metavar="PATH",
                        help="Write a MISP-compatible event of extracted IOCs to file")
    return parser


def main() -> None:
    args = build_parser().parse_args()
    path = Path(args.file)
    if not path.exists():
        print(f"Error: {path} not found", file=sys.stderr)
        sys.exit(1)

    report = triage(path)

    print(f"\nSource  : {report.source}", file=sys.stderr)
    if report.package:
        print(f"Package : {report.package}", file=sys.stderr)
    print(f"Verdict : {report.verdict.upper()}  (risk score {report.risk_score})", file=sys.stderr)
    print(f"Findings: {len(report.findings)}", file=sys.stderr)
    for f in report.findings:
        tag = f" [{f.attack}]" if f.attack else ""
        print(f"  [{f.severity.upper():6s}] {f.category}: {f.detail}{tag}", file=sys.stderr)

    if args.misp:
        if not (IOC_AVAILABLE and report.iocs):
            print("No IOCs to export (or ioc_extractor unavailable).", file=sys.stderr)
        else:
            event = to_misp_event(report.iocs, source=report.source)
            Path(args.misp).write_text(json.dumps(event, indent=2))
            print(f"MISP event saved to {args.misp}", file=sys.stderr)

    output = json.dumps(asdict(report), indent=2)
    if args.output:
        Path(args.output).write_text(output)
        print(f"Report saved to {args.output}", file=sys.stderr)
    else:
        print(output)


if __name__ == "__main__":
    main()
