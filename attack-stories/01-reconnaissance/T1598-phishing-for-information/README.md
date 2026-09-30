# T1598: Phishing for Information

## Story

An attacker wants to break into a company but doesn't know much about it yet. They send a deceptive message—an email, text, or phone call—pretending to be someone trustworthy. The goal isn't to install malware; it's to trick someone into revealing sensitive information: a password, the company's structure, which tools they use, or who has access to what. It's like calling a building and pretending to be IT support to learn how their systems are organized.

## Formal Definition

**MITRE ATT&CK T1598: Phishing for Information**

Adversaries may send phishing messages to elicit sensitive information that can be used during targeting. Unlike malware-delivery phishing, this technique focuses purely on information gathering. Methods include spear-phishing emails, vishing (voice phishing), and smishing (SMS phishing). The goal is reconnaissance, not compromise.

---

## Puzzle: Spot the Anomaly

Below are email logs from a company's mail gateway. One message shows signs of phishing for information. Can you find it?

```json
[
  {"timestamp": "2025-01-15T09:12:34Z", "sender": "john.smith@acme.internal", "recipient": "sales@acme.com", "subject": "Q1 Sales Report", "attachment_count": 1, "verdict": "CLEAN"},
  {"timestamp": "2025-01-15T09:15:22Z", "sender": "hr@acme.com", "recipient": "all-employees@acme.com", "subject": "Mandatory Password Reset", "attachment_count": 0, "verdict": "SPAM", "note": "Sent from external domain"},
  {"timestamp": "2025-01-15T09:18:45Z", "sender": "support@microsoft.com", "recipient": "admin@acme.com", "subject": "Urgent: Verify Your Azure Account", "attachment_count": 0, "body_snippet": "Click here to confirm your identity and update your security settings", "verdict": "PHISHING"},
  {"timestamp": "2025-01-15T09:22:11Z", "sender": "finance@acme.internal", "recipient": "accounting@acme.com", "subject": "Expense Report Template", "attachment_count": 1, "verdict": "CLEAN"},
  {"timestamp": "2025-01-15T09:25:33Z", "sender": "it-security-survey@example.com", "recipient": "all-employees@acme.com", "subject": "Please Complete Our IT Security Survey", "attachment_count": 0, "body_snippet": "To improve our security posture, please respond with: your department, manager name, tools you use daily, and VPN access details", "verdict": "SUSPICIOUS"}
]
```

<details>
<summary>🔍 Reveal the anomaly</summary>

**Entry #5 is phishing for information:**

- **Sender**: `it-security-survey@example.com` — External domain, not official company email
- **Subject**: "Please Complete Our IT Security Survey" — Creates false urgency and authority
- **Body**: Asks for:
  - Department (organizational structure)
  - Manager name (identifies chain of command)
  - Tools used daily (technology stack)
  - VPN access details (network topology)
  - **None of this is for malware delivery — it's pure reconnaissance**

**Why this is phishing for information:**
1. **External sender impersonating internal**: Claims to be IT security but uses `example.com`
2. **Requests sensitive operational data**: Answers reveal company structure, tech stack, and access patterns
3. **No attachment or payload**: Unlike malware-delivery phishing, there's nothing to execute — just a form to extract information
4. **Authority manipulation**: Uses "security survey" to make it seem official

**Contrast with other entries:**
- Entry #2 is spam with credential harvesting (Azure phishing) — but it's a different attack type
- Entries #1, #4 are legitimate internal emails
- Entry #3 is credential phishing (pretending to be Microsoft Azure), not information phishing

</details>

---

## Detection Logic

### KQL (Microsoft Sentinel / Defender for Email)

```kql
// Detect phishing-for-information emails requesting sensitive org details
EmailEvents
| where SenderFromAddress !endswith "@acme.com" and SenderFromAddress !endswith "acme.internal"
| where Subject has_any ("survey", "update", "verify", "confirm", "audit", "compliance")
| where EmailBodyPreview has_any ("department", "manager", "tools", "access", "VPN", "infrastructure", "team members")
| where ThreatTypes != "Phish" // Catch cases mail gateway missed
| extend InformationRequested = extract_all(@"(department|manager|tools|access|vpn|infrastructure)", EmailBodyPreview)
| project Timestamp, SenderFromAddress, RecipientEmailAddress, Subject, InformationRequested
```

### YARA-L Detection

```yara
// YARA-L rule for phishing-for-information campaigns
rule phishing_for_information {
  meta:
    description = "Detects phishing emails requesting organizational information"
    mitre_id = "T1598"
    severity = "medium"
  
  events:
    $email.metadata.product_name == "GMAIL" or $email.metadata.product_name == "MICROSOFT_EMAIL"
    $email.security.threat_detection_result == "PHISHING" or
    (
      $email.network.sender_ip != /^10\.|^172\.|^192\./ and
      $email.email.subject has_any ("survey", "audit", "verify", "confirm")
    )
    re.match($email.email.body, "(department|manager|role|team|infrastructure|vpn|tools)", "i")
  
  match:
    $email
  
  condition:
    #$email > 0
}
```

---

## MITRE Mapping

| Field | Value |
|-------|-------|
| **Tactic** | Reconnaissance (TA0043) |
| **Technique** | T1598: Phishing for Information |
| **Sub-techniques** | T1598.001 (Spearphishing Service), T1598.002 (Spearphishing Attachment), T1598.003 (Spearphishing Link), T1598.004 (Spearphishing Voice) |
| **Platform** | Linux, Windows, macOS, SaaS |

---

## False Positives

| Scenario | Why It Triggers | Mitigation |
|----------|-----------------|------------|
| **Legitimate HR survey** | HR collects org data for planning; body may include "department," "manager," "tools" | Whitelist known internal HR email domains; check Sender Policy Framework (SPF) |
| **Vendor technical onboarding** | Integration partners request tech details for setup | Verify sender domain; correlate with known vendor emails |
| **Internal IT security assessment** | Legitimate security team conducts info-gathering for audit | Exclude internal IT security domain from detection |
| **External security audit** | Third-party auditors (SOC 2, ISO 27001) request system details | Pre-communicate audit windows; whitelist auditor domains during engagements |

---

**Last Updated:** January 2025
