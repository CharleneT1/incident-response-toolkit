# Incident Response Toolkit

A lightweight Python toolkit for first-responder tasks during security incidents: IOC extraction from logs, phishing header analysis, and a structured NIST-aligned response checklist.

Built and tested during hands-on incident simulation practice, including the [CIRCL Room 42](https://www.circl.lu/services/room42/) tabletop exercise environment.

---

## Tools

| Tool | Purpose |
|---|---|
| `ioc_extractor.py` | Parse logs/text for IPs, domains, URLs, hashes; export MISP-compatible JSON |
| `phishing_analyzer.py` | Analyze raw email headers, check SPF/DKIM/DMARC, score phishing risk |
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

**Output format** matches the [MISP JSON event format](https://www.misp-project.org/documentation/), ready for import via the MISP REST API or the `PyMISP` library.

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

## Further reading

- [MISP Threat Intelligence Platform](https://www.misp-project.org/documentation/)
- [NIST SP 800-61r2 — Computer Security Incident Handling Guide](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final)
- [CIRCL Room 42 Incident Simulation](https://www.circl.lu/services/room42/)
- [MITRE ATT&CK Framework](https://attack.mitre.org)
- [dnspython documentation](https://dnspython.readthedocs.io/)
