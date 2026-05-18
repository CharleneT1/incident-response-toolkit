# Incident Response Checklist

**Framework:** NIST SP 800-61r2  
**Version:** 1.0  
**Last reviewed:** 2026-05-18

---

## How to use this checklist

Work through each phase sequentially. Check off completed items and record the timestamp, responsible party, and any notes inline. For severity decisions use the decision trees at the end of each phase.

---

## Phase 1 — Preparation (ongoing)

> Complete before an incident occurs. Revisit quarterly.

- [ ] Incident response team (IRT) roster and on-call rotation documented
- [ ] Communication channels established (primary + backup)
- [ ] Asset inventory current and accessible offline
- [ ] Logging and SIEM rules in place for: authentication failures, lateral movement, data exfiltration, C2 beaconing
- [ ] Out-of-band communication method agreed (Signal, encrypted email)
- [ ] Legal and privacy counsel contact confirmed
- [ ] Law enforcement escalation path documented (CISA, FBI IC3, local CERT)
- [ ] Forensic tooling pre-staged on jump host
- [ ] Backup integrity verified; restoration tested

---

## Phase 2 — Detection & Initial Analysis

> Goal: Confirm the incident is real and establish initial scope.

### 2.1 Triage

- [ ] Record detection time and detection source (SIEM alert / user report / external tip)
- [ ] Assign incident ticket / case number
- [ ] Assign incident commander (IC) and document name + contact
- [ ] Set initial severity (see decision tree below)

### 2.2 Scope assessment

- [ ] Identify affected systems (hostnames, IPs, cloud resources)
- [ ] Identify affected accounts / credentials
- [ ] Identify affected data (classification: public / internal / confidential / regulated)
- [ ] Preserve initial evidence: screenshots, raw log exports, memory dumps if live system
- [ ] Check for lateral movement indicators on adjacent systems
- [ ] Timeline: earliest known Indicator of Compromise (IOC) timestamp

### 2.3 IOC extraction

```
python ioc_extractor.py -f <log_file> -o iocs_<case_id>.json
```

- [ ] IPs extracted and cross-referenced against threat intel (MISP, VirusTotal)
- [ ] Domain names checked (DNS history, registration date, WHOIS)
- [ ] File hashes checked (VirusTotal, MalwareBazaar)
- [ ] IOC report shared with IRT

---

### Decision Tree: Severity Classification

```
Is data exfiltration confirmed or suspected?
├── YES → Critical (P1) — activate full IRT immediately
└── NO
    Is a production system or customer-facing service impacted?
    ├── YES
    │   Is the impact causing downtime?
    │   ├── YES → High (P2) — notify IC + management within 1 hour
    │   └── NO  → Medium (P3) — IRT resolves within 24 hours
    └── NO  → Low (P4) — IRT resolves within 72 hours
```

---

## Phase 3 — Containment

> Goal: Stop the bleeding without destroying evidence.

### 3.1 Short-term containment (first 1–4 hours)

- [ ] Decision documented: isolate vs. monitor (monitoring preferred if safe to do so)
- [ ] Affected hosts isolated from network (VLAN quarantine preferred over full shutdown)
- [ ] Compromised accounts disabled / passwords rotated
- [ ] Malicious network IOCs blocked at perimeter (firewall rules, DNS sinkhole)
- [ ] Cloud resources: revoke leaked keys/tokens, scope-down IAM roles
- [ ] Evidence preserved *before* any remediation action (disk image, memory capture)

### 3.2 Long-term containment

- [ ] Temporary patch or workaround applied to vulnerable component
- [ ] Additional monitoring deployed on adjacent systems
- [ ] Out-of-band status update sent to stakeholders (do NOT use potentially compromised comms)
- [ ] Regulatory notification window assessed (GDPR 72 h, HIPAA 60 days, PCI-DSS promptly)

---

### Decision Tree: Isolate or Monitor?

```
Is attacker likely to destroy evidence or escalate if they detect detection?
├── YES → Isolate immediately
└── NO
    Is ongoing exfiltration actively occurring?
    ├── YES → Isolate + capture traffic first (tcpdump/Wireshark)
    └── NO
        Is the system critical to business operations?
        ├── YES → Monitor with enhanced logging; prepare isolation runbook
        └── NO  → Isolate at next safe maintenance window
```

---

## Phase 4 — Eradication

> Goal: Remove the threat completely from the environment.

- [ ] Root cause identified and documented
- [ ] All malware / backdoors / webshells located (check: startup items, cron, scheduled tasks, WMI subscriptions, kernel modules)
- [ ] Persistence mechanisms removed
- [ ] Compromised credentials invalidated enterprise-wide (not just affected hosts)
- [ ] Vulnerable software patched or mitigated
- [ ] IOCs added to blocking lists and threat intel platform (MISP event created)
- [ ] Affected systems re-imaged from known-good baseline (preferred over manual cleaning)
- [ ] Integrity verification of re-imaged systems before returning to production
- [ ] Threat hunt performed on all systems in blast radius using extracted IOCs

---

### Decision Tree: Re-image or Clean?

```
Is the attacker a nation-state / advanced persistent threat?
├── YES → Always re-image (do not attempt manual cleaning)
└── NO
    Is the compromised system a critical infrastructure component?
    ├── YES → Re-image (risk of incomplete manual cleaning too high)
    └── NO
        Can all persistence mechanisms be enumerated with confidence?
        ├── YES → Manual cleaning acceptable; verify with AV + EDR scan post-clean
        └── NO  → Re-image
```

---

## Phase 5 — Recovery

> Goal: Restore systems to normal operation safely.

- [ ] Pre-return checklist verified for each system:
  - [ ] Clean baseline confirmed
  - [ ] All patches applied
  - [ ] Logging/monitoring re-enabled and verified
  - [ ] EDR agent installed and reporting
- [ ] Phased return to production (dev → staging → production)
- [ ] Enhanced monitoring period defined (recommend minimum 30 days)
- [ ] Credentials rotated for all service accounts on recovered systems
- [ ] Business stakeholder sign-off on restoration
- [ ] Incident status updated to "Monitoring / Recovery"

---

## Phase 6 — Post-Incident Activity (Lessons Learned)

> Complete within 2 weeks of incident closure.

### 6.1 Timeline reconstruction

- [ ] Full attack timeline documented (first access → detection → containment → recovery)
- [ ] Detection gap identified: how long was the attacker present before detection?
- [ ] Mean Time to Detect (MTTD) and Mean Time to Respond (MTTR) recorded

### 6.2 Root cause analysis

- [ ] Five-whys or fishbone analysis completed
- [ ] Initial access vector confirmed (phishing / vuln exploit / credential stuffing / insider / supply chain)
- [ ] Contributing security control failures identified

### 6.3 Action items

- [ ] Control gaps mapped to remediation tasks with owners and due dates
- [ ] Detection rules updated / new rules written based on TTPs observed
- [ ] Runbooks updated based on what worked / didn't work
- [ ] Training needs identified for any team members involved
- [ ] Threat intel shared with sector ISACs or national CERT where appropriate

### 6.4 Reporting

- [ ] Internal executive summary written (non-technical, 1 page)
- [ ] Technical incident report finalized (timeline, IOCs, TTPs, remediation)
- [ ] Regulatory / legal notifications completed and filed
- [ ] Lessons learned session held with IRT (blameless post-mortem format)

---

## Scenario Decision Trees

### Scenario A: Ransomware

```
Ransomware detected
│
├── Is it actively encrypting?
│   ├── YES → Emergency network isolation of affected segment
│   │         Pull power only if encryption cannot be stopped otherwise
│   └── NO  → Forensic acquisition first, then isolate
│
├── Is backup infrastructure confirmed unaffected?
│   ├── YES → Proceed to eradication + recovery from backups
│   └── NO  → Engage IR retainer / law enforcement before any recovery attempts
│
└── Ransom payment decision (management + legal)
    ├── Never pay without law enforcement consultation
    └── Payment does NOT skip eradication — re-image regardless
```

### Scenario B: Phishing / BEC (Business Email Compromise)

```
Suspicious email reported
│
├── Run phishing_analyzer.py on raw headers
│
├── Was the link clicked / attachment opened?
│   ├── YES → Treat as endpoint compromise; begin Phase 2 triage
│   └── NO  → Block sender domain/IP; submit to email gateway blocklist
│
├── Were credentials entered?
│   ├── YES → Immediate password reset + MFA token revocation
│   │         Check mail rules, forwarding, OAuth grants, sent items
│   └── NO  → Awareness notification to affected user
│
└── BEC (financial fraud)?
    ├── Contact financial institution within 24 h (potential wire recall)
    └── File FBI IC3 complaint: ic3.gov
```

### Scenario C: Data Exfiltration / Insider Threat

```
Exfiltration suspected
│
├── Preserve all logs before alerting the suspect account
├── Engage HR and Legal before any employee-facing action
├── Capture DLP alerts, egress traffic logs, cloud sync logs
│
├── Exfiltration confirmed?
│   ├── YES → Quantify data: records, classification, affected individuals
│   │         Begin regulatory notification clock
│   └── NO  → Continue monitoring; document evidence chain
│
└── Insider vs. external attacker?
    ├── Insider → HR + Legal lead; IT supports evidence preservation
    └── External using insider account → Standard IR + credential reset
```

---

## Reference

| Resource | URL |
|---|---|
| NIST SP 800-61r2 | https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final |
| MITRE ATT&CK | https://attack.mitre.org |
| MISP Platform | https://www.misp-project.org/documentation/ |
| CISA Incident Reporting | https://www.cisa.gov/report |
| FBI IC3 | https://ic3.gov |
| US-CERT | https://us-cert.cisa.gov |
