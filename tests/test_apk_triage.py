"""Tests for apk_triage static analysis (manifest parsing + scoring)."""

from pathlib import Path

import apk_triage

SAMPLE = Path(__file__).resolve().parent.parent / "sample_data" / "AndroidManifest.xml"


def _report():
    return apk_triage.triage(SAMPLE)


def _analyze(manifest_xml: str) -> apk_triage.TriageReport:
    """Run manifest analysis on an inline manifest string."""
    report = apk_triage.TriageReport(source="synthetic")
    elements = apk_triage.parse_text_manifest(manifest_xml)
    apk_triage.analyze_manifest(elements, report)
    return report


_NS = 'xmlns:android="http://schemas.android.com/apk/res/android"'


def test_sample_manifest_parses_package():
    assert _report().package == "com.example.flashlight.pro"


def test_dangerous_permissions_flagged():
    report = _report()
    assert "android.permission.READ_SMS" in report.permissions
    assert "android.permission.SEND_SMS" in report.permissions


def test_attack_mapping_present():
    report = _report()
    attack_ids = {f.attack for f in report.findings if f.attack}
    # READ_SMS -> T1636.004, SYSTEM_ALERT_WINDOW -> T1417.002
    assert "T1636.004" in attack_ids
    assert "T1417.002" in attack_ids


def test_suspicious_combo_detected():
    report = _report()
    combo_findings = [f for f in report.findings if f.category == "Permission combo"]
    assert combo_findings, "expected at least one suspicious permission combo"


def test_exported_components_flagged():
    report = _report()
    assert any("SmsRelayService" in c for c in report.exported_components)


def test_boot_persistence_detected():
    report = _report()
    persistence = [f for f in report.findings if f.category == "Persistence"]
    assert persistence, "expected a boot-persistence finding"
    assert any(f.attack == "T1624.001" for f in persistence)


def test_exported_provider_flagged_specifically():
    report = _report()
    assert any("AppDataProvider" in c for c in report.exported_components)
    provider_findings = [
        f for f in report.findings
        if f.category == "Component" and "content provider" in f.detail.lower()
    ]
    assert provider_findings, "expected a dedicated exported content provider finding"


def test_permission_feature_mismatch_detected():
    report = _report()
    mismatch = [f for f in report.findings if f.category == "Distribution"]
    assert mismatch, "expected a permission/hardware-feature mismatch finding"
    assert any("required=false" in f.detail for f in mismatch)


def test_behavioral_string_indicators():
    # Techniques that need no suspicious manifest permission: clipboard theft and
    # exfiltration to a request-capture service, recovered from code strings.
    report = apk_triage.TriageReport(source="synthetic")
    blob = (
        "Landroid/content/ClipboardManager; getPrimaryClip "
        "https://webhook.site/b9d274bf-a327-419e-b49b-db43a7337992 "
        "files/.cache/.analytics/.metrics.log"
    )
    apk_triage.analyze_strings(blob, report)
    details = " ".join(f.detail for f in report.findings)
    assert "clipboard" in details.lower()
    assert "webhook.site" in details.lower()
    assert "log" in details.lower()


# --- Tier 2: OWASP MASVS DEX-string indicators ---


def _strings_report(blob: str) -> apk_triage.TriageReport:
    report = apk_triage.TriageReport(source="synthetic")
    apk_triage.analyze_strings(blob, report)
    return report


def test_webview_javascript_interface_flagged():
    report = _strings_report("Landroid/webkit/WebView; addJavascriptInterface")
    assert any(f.category == "WebView" and f.severity == "high" for f in report.findings)


def test_webview_ssl_error_bypass_flagged():
    report = _strings_report("public void onReceivedSslError(WebView v, SslErrorHandler h)")
    assert any("TLS" in f.detail or "onReceivedSslError" in f.detail for f in report.findings)


def test_weak_crypto_ecb_flagged():
    report = _strings_report('Cipher.getInstance("AES/ECB/PKCS5Padding")')
    assert any(f.category == "Crypto" for f in report.findings)


def test_broken_hash_flagged():
    report = _strings_report('MessageDigest.getInstance("MD5")')
    assert any(f.category == "Crypto" and "MD5" in f.detail for f in report.findings)


def test_dynamic_code_loading_flagged():
    report = _strings_report("Ldalvik/system/DexClassLoader;")
    assert any(f.category == "Code loading" and f.severity == "high" for f in report.findings)


def test_root_artifact_flagged():
    report = _strings_report("/system/xbin/su and com.noshufou.android.su")
    assert any(f.category == "Anti-analysis" for f in report.findings)


def test_frida_anti_instrumentation_flagged():
    report = _strings_report("connecting to frida-server on 27042")
    assert any(f.category == "Anti-analysis" for f in report.findings)


# --- DEX domain-list noise filtering ---


def test_package_names_identified_as_package_like():
    for token in ("androidx.appcompat.app", "io.ktor.utils.io",
                  "com.example.malware", "9com.mardous.booming", "f.Tv"):
        assert apk_triage._is_package_like(token), token


def test_real_domains_not_package_like():
    for token in ("evil-c2.xyz", "exfil.example.com", "login.bank.top", "360.cn"):
        assert not apk_triage._is_package_like(token), token


def test_high_risk_verdict():
    report = _report()
    assert report.verdict == "high_risk"
    assert report.risk_score >= 60


# --- Tier 1: OWASP MASVS / MASTG app-hardening flags ---


def test_sample_hardening_flags_present():
    report = _report()
    categories = {f.category for f in report.findings}
    # The enhanced sample exercises allowBackup, cleartext, minSdk and launchMode.
    assert "Hardening" in categories
    assert "Network" in categories


def test_debuggable_flagged():
    report = _analyze(
        f'<manifest {_NS} package="x"><application android:debuggable="true"/></manifest>'
    )
    assert any(
        f.category == "Hardening" and "debuggable" in f.detail.lower()
        for f in report.findings
    )


def test_allowbackup_true_flagged():
    report = _analyze(
        f'<manifest {_NS} package="x"><application android:allowBackup="true"/></manifest>'
    )
    assert any("adb backup" in f.detail for f in report.findings)


def test_allowbackup_absent_flagged_softly():
    report = _analyze(
        f'<manifest {_NS} package="x"><application android:label="A"/></manifest>'
    )
    backup = [f for f in report.findings if "allowBackup not set" in f.detail]
    assert backup and backup[0].severity == "low"


def test_cleartext_traffic_flagged():
    report = _analyze(
        f'<manifest {_NS} package="x">'
        f'<application android:usesCleartextTraffic="true"/></manifest>'
    )
    assert any(f.category == "Network" and "HTTP" in f.detail for f in report.findings)


def test_low_minsdk_flagged():
    report = _analyze(
        f'<manifest {_NS} package="x"><uses-sdk android:minSdkVersion="19"/>'
        f'<application android:label="A"/></manifest>'
    )
    assert any("minSdkVersion" in f.detail for f in report.findings)


def test_modern_minsdk_not_flagged():
    report = _analyze(
        f'<manifest {_NS} package="x"><uses-sdk android:minSdkVersion="30"/>'
        f'<application android:label="A"/></manifest>'
    )
    assert not any("minSdkVersion" in f.detail for f in report.findings)


def test_weak_custom_permission_flagged():
    report = _analyze(
        f'<manifest {_NS} package="x">'
        f'<permission android:name="x.perm.SECRET" android:protectionLevel="normal"/>'
        f'<application android:label="A"/></manifest>'
    )
    assert any("protectionLevel" in f.detail for f in report.findings)


def test_signature_custom_permission_not_flagged():
    report = _analyze(
        f'<manifest {_NS} package="x">'
        f'<permission android:name="x.perm.SECRET" android:protectionLevel="signature"/>'
        f'<application android:label="A"/></manifest>'
    )
    assert not any("protectionLevel" in f.detail for f in report.findings)


def test_task_hijack_surface_flagged():
    report = _analyze(
        f'<manifest {_NS} package="x"><application>'
        f'<activity android:name=".Main" android:launchMode="singleTask"/>'
        f'</application></manifest>'
    )
    assert any("StrandHogg" in f.detail for f in report.findings)
