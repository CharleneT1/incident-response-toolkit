# Incident Response Toolkit

A lightweight, dependency-light Python toolkit for first-responder tasks during security incidents: IOC extraction and handling, phishing header analysis, static Android app triage, and a structured NIST-aligned response checklist.

IOCs are exported in [MISP](https://www.misp-project.org/) event format and indicators map to [MITRE ATT&CK](https://attack.mitre.org) where possible, so output slots into standard IR workflows without conversion.

The APK triage tool grew out of a team Android malware / mobile-security project. The detectors are validated against a trojaned version of the open-source BoomingMusic player — the team injected 11 distinct attacks into an existing real-world app rather than writing one from scratch, which makes for a more realistic test than a toy sample (see the APK Triage section for the full attack-by-attack scorecard).

---

## Tools

| Tool | Purpose |
|---|---|
| `ioc_extractor.py` | Parse logs/text for IPs, domains, URLs, hashes; export MISP-compatible JSON |
| `phishing_analyzer.py` | Analyze raw email headers, check SPF/DKIM/DMARC, score phishing risk |
| `apk_triage.py` | Static first-look triage of Android APKs/manifests: dangerous permissions → ATT&CK Mobile, suspicious permission combos, exported components, embedded IOCs |
| `playbooks/incident_response_checklist.md` | NIST SP 800-61r2 checklist with scenario decision trees |

---

## Installation

Python 3.8+ required.

```bash
pip install -r requirements.txt
```

The only external dependency is [dnspython](https://www.dnspython.org/) for live DNS record lookups in `phishing_analyzer.py`. All other functionality works without it.

---

## Usage

### IOC Extractor

Extract indicators from a log file and save MISP-compatible JSON:

```bash
python ioc_extractor.py -f /var/log/nginx/access.log -o iocs.json
```

Extract from stdin, limit to IPs and hashes only:

```bash
cat suspicious.txt | python ioc_extractor.py --stdin --types ipv4 sha256 md5
```

Inline text, include RFC-1918 addresses, output raw dict:

```bash
python ioc_extractor.py -t "host 10.0.0.5 connected to c2.evil.com" --include-private --raw
```

**Output format** is structured as a [MISP JSON event](https://www.misp-project.org/documentation/) (Event envelope with typed Attributes and UUIDs), intended for ingest via the `PyMISP` library or the MISP REST API.

#### Detected IOC types

| Type | Example |
|---|---|
| IPv4 | `203.0.113.42` |
| IPv6 | `2001:db8::1` |
| URL | `https://phish.example.com/login` |
| Domain | `malware-c2.xyz` |
| MD5 | `d41d8cd98f00b204e9800998ecf8427e` |
| SHA1 | `da39a3ee5e6b4b0d3255bfef95601890afd80709` |
| SHA256 | `e3b0c44298fc1c149afb...` |

---

### Phishing Analyzer

Analyze a raw `.eml` file:

```bash
python phishing_analyzer.py -f suspicious.eml
```

Pipe headers from clipboard or another tool:

```bash
cat email_headers.txt | python phishing_analyzer.py --stdin
```

Save the JSON report for further processing:

```bash
python phishing_analyzer.py -f alert.eml -o report.json
```

#### What it checks

| Check | Method |
|---|---|
| SPF record present and valid | Live DNS TXT lookup |
| DMARC policy published | Live DNS TXT lookup on `_dmarc.<domain>` |
| DKIM selector key present | Live DNS TXT lookup on `<selector>._domainkey.<domain>` |
| `Authentication-Results` header values | Header parse (spf/dkim/dmarc pass or fail) |
| Reply-To / From domain mismatch | Header comparison |
| Message-ID domain mismatch | Header comparison |
| Suspicious TLD on sender domain | Regex match (`.xyz`, `.tk`, `.top`, …) |
| Phishing keywords in subject | Regex match |
| Abnormal Received chain length | Header count |

#### Risk scoring

| Score range | Verdict |
|---|---|
| 0–24 | `clean` |
| 25–59 | `suspicious` |
| 60+ | `likely_phishing` |

---

### APK Triage

Static first-look triage to decide whether an Android app is worth a full reverse-engineering pass. Works on a real `.apk` (parses the binary `AndroidManifest.xml` with a self-contained AXML parser — no external dependency) **and** on the plaintext manifests that decompilers like jadx/apktool produce. Dangerous permissions map to MITRE ATT&CK Mobile; hardening flags map to OWASP MASVS/MASTG.

Triage a packaged app, save the report, and export embedded IOCs as a MISP event:

```bash
python apk_triage.py -f sample.apk -o triage.json --misp apk_iocs.json
```

Triage a decompiled manifest (try it now with the bundled sample):

```bash
python apk_triage.py -f sample_data/AndroidManifest.xml
```

#### What it checks

| Check | Detail |
|---|---|
| Dangerous permissions | Mapped to MITRE ATT&CK (Mobile) technique IDs where a confident mapping exists |
| Suspicious permission combinations | e.g. SMS + INTERNET (2FA exfiltration), overlay + boot persistence (banker pattern) |
| Boot persistence | Component registered for `BOOT_COMPLETED` → auto-start after reboot (T1624.001) |
| Permission / hardware-feature mismatch | Dangerous permission requested while its `<uses-feature>` is `required="false"` (Play Store filtering bypass) |
| Exported content providers | Called out specifically — a queryable data-leak surface — separate from other exported components |
| Other exported components | Activities/services/receivers reachable without a permission guard |
| App-hardening flags (OWASP MASVS/MASTG) | `debuggable`, `allowBackup`, `usesCleartextTraffic`, `networkSecurityConfig`, low `minSdkVersion`, weak custom-permission `protectionLevel`, task-hijacking (StrandHogg) launch modes — all read from clear-text manifest attributes Android must honour, so they hold up under obfuscation |
| Behavioural indicators (DEX strings) | Clipboard-access APIs, exfil/request-capture services (webhook.site, requestbin…), covert dotfile log paths — techniques that need no suspicious permission |
| WebView misconfiguration (DEX strings) | `addJavascriptInterface` (JS→native RCE surface), file-access flags, `onReceivedSslError` TLS-bypass handlers (MASVS-PLATFORM/NETWORK) |
| Weak cryptography (DEX strings) | DES/RC4/ECB ciphers, MD5/SHA-1 hashes, `java.util.Random` for secrets (MASVS-CRYPTO) |
| Dynamic code execution (DEX strings) | `DexClassLoader`/`PathClassLoader`, `Runtime.exec`/`ProcessBuilder` (MASVS-CODE) |
| Anti-analysis (DEX strings) | Root-artifact strings (`su`, Magisk) and anti-instrumentation refs (Frida/Xposed/Substrate) (MASVS-RESILIENCE) |
| Embedded IOCs | URLs / domains / IPs pulled from DEX strings (reuses `ioc_extractor`); reverse-DNS package names and mangled identifiers are filtered out of the domain list so it reflects real network indicators |
| File hashes | SHA-256 of the APK and each DEX, emitted as IOCs |

**Scope and limits — read this.** This is a *static* triage aid: it reads the manifest and the plaintext strings in the DEX. It is good at surfacing *capability and intent* (what the app is allowed to do, what endpoints/APIs it references) so an analyst can prioritise. It does **not** execute the app, so it cannot observe runtime behaviour, and string-based indicators degrade against obfuscation/encryption/packing. ATT&CK mappings are **indicative**, not authoritative. The lightweight AXML parser covers the common aapt-compiled manifest layout; for adversarial/obfuscated samples, confirm with `androguard`/`apktool` for statics and a dynamic pass (Frida, network capture, sandbox) for runtime behaviour. See the workflow note below.

#### Where static triage fits (and where it doesn't)

Static triage is the cheap first filter, not the verdict:

1. **Manifest is not obfuscable.** Permissions, `<uses-feature>`, exported components and intent filters must be declared in clear text for Android to honour them — R8/ProGuard cannot hide them. So *capability and attack-surface* findings hold up even on a heavily obfuscated APK.
2. **Strings survive more than you'd expect.** Framework API references (`Landroid/content/ClipboardManager;`, `getPrimaryClip`) and live network endpoints generally remain as plaintext because the code still has to call the real APIs and resolve the real hosts. Obfuscation renames *your* symbols, not the platform's.
3. **What it genuinely can't see:** logic that only manifests at runtime, reflection, dynamically-loaded/decrypted payloads, and string-encrypted constants. Those need a dynamic pass. Static triage's job is to decide *whether that more expensive pass is warranted* — and to do it in milliseconds across a large set of samples.

#### How this compares (and when to use it)

This is **not** a MobSF / androguard / quark-engine replacement. It's the fast, dependency-free first-pass filter that tells you *which* APKs deserve those heavier tools.

| | This tool | MobSF / androguard / quark |
|---|---|---|
| Install footprint | One stdlib-only `.py`, zero `pip install` | Django app + DB, or a heavy dependency tree |
| Job | Triage filter: *"is this 1 of 200 APKs worth opening jadx for?"* | Full audit: *"tell me everything about this one APK"* |
| Output | IR-native: ATT&CK Mobile IDs, IOCs, MISP event in one pass | Appsec/pentest reports |
| Input | Real `.apk` **and** decompiled jadx/apktool manifests | Usually one or the other |
| Confidence | Labels each DEX-string signal `api-ref` (survives obfuscation) vs `data-string` (soft) | Rarely surfaced |
| DEX analysis | Regex over extracted strings — **defeated by string encryption** | Bytecode/CFG, API-sequence behaviour detection |
| Coverage | Manifest + string heuristics; no native-lib/cert/resource analysis; static only | Native libs, certs, resources, some dynamic |
| Ruleset | Hand-curated, small | Thousands of mature rules |

**Where it has a real edge** is operational, not detection depth: zero-install on a locked-down/air-gapped DFIR box, throughput triage with a 3-bucket verdict, IR-native output that drops into MISP, dual binary/decompiled input, and honest obfuscation-resistance labelling.

**The one-liner:** *"Not a MobSF replacement — the fast, dependency-free first-pass filter that tells you which APKs deserve MobSF. Built for IR throughput, not appsec depth."*

> **Measured result.** Run against a trojaned version of the open-source BoomingMusic player (11 distinct attacks injected into a real-world app by the team), the tool produced a `HIGH_RISK` verdict (risk score 278) and surfaced the following:
>
> | Attack | Detected? | Signal |
> |---|---|---|
> | Permission-feature mismatch (Play Store bypass) | ✅ | 4 `Distribution` findings — CAMERA, RECORD_AUDIO, fine + coarse location all marked `required=false` |
> | Boot persistence | ✅ | Both `BOOT_COMPLETED` and `LOCKED_BOOT_COMPLETED` intent filter registration (T1624.001) |
> | Exported content provider | ✅ | `MusicDataProvider` flagged explicitly (HIGH, 20 pts) |
> | Clipboard hijacking | ✅ | `ClipboardManager` API reference — **obfuscation-resistant** (framework API names can't be renamed) (T1414) |
> | Command injection via `Runtime.exec` | ✅ | `Runtime.exec` API reference — **obfuscation-resistant**; `PlaylistFiles` receiver flagged as unguarded |
> | Stealth audio/camera tracking | ✅ | CAMERA→T1512, RECORD_AUDIO→T1429, LOCATION→T1430 + network combo |
> | Confused deputy (privilege escalation) | ✅ | `FilePreviewActivity` explicitly named as unguarded exported activity |
> | Confused deputy + email exfiltration | ✅ | `sandbox.smtp.mailtrap.io` extracted as IOC domain (soft signal, but specific enough to identify the Mailtrap exfil backend) |
> | UI injection / toast spam | ⚠️ partial | Exported receivers flagged generically; toast-loop itself is runtime-only |
> | Resource exhaustion | ⚠️ partial | `WAKE_LOCK` permission flagged; CPU/GPS/network abuse is runtime-only |
> | Hidden analytics logging | ❌ missed | Covert write to `/files/.cache/.analytics/` is a pure runtime behaviour — the path did not appear as a plaintext DEX string, and no manifest attribute declares it |
>
> **8 of 11** attacks fully or substantially detected; **2 of 11** partially (the exported attack surface is visible, the runtime abuse of it is not); **1 of 11** not detected. The missed attack is the designed blind spot: a runtime file-write with no manifest declaration and no survivable plaintext string is exactly what the dynamic pass is for. The two partial detections are correct capability flags — the tool correctly identifies the permissions and unguarded receivers, just not the specific runtime pattern of abuse.

---

### Incident Response Checklist

The checklist in [playbooks/incident_response_checklist.md](playbooks/incident_response_checklist.md) covers the full NIST SP 800-61r2 lifecycle:

1. **Preparation** — team, tooling, logging readiness
2. **Detection & Initial Analysis** — triage, scope, IOC extraction
3. **Containment** — short-term isolation, long-term stabilisation
4. **Eradication** — remove persistence, patch, re-image
5. **Recovery** — phased return, enhanced monitoring
6. **Post-Incident Activity** — timeline, root cause, lessons learned

Decision trees are included for: severity classification, isolate-vs-monitor, re-image-vs-clean, ransomware, phishing/BEC, and data exfiltration/insider threat scenarios.

---

## Development

Run the test suite (parser correctness, IOC handling, triage scoring):

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt
pytest -q
```

Every push runs the same tests plus a sample-data smoke test via GitHub Actions ([.github/workflows/ci.yml](.github/workflows/ci.yml)).

---

## Further reading

- [MISP Threat Intelligence Platform](https://www.misp-project.org/documentation/)
- [MITRE ATT&CK for Mobile](https://attack.mitre.org/matrices/mobile/)
- [NIST SP 800-61r2 — Computer Security Incident Handling Guide](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final)
- [MITRE ATT&CK Framework](https://attack.mitre.org)
- [dnspython documentation](https://dnspython.readthedocs.io/)
