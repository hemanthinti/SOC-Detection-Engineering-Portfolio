# T1595: Active Scanning

## Story

An attacker decides to break into a company's network. Before they even try to get in, they need to understand what's out there. They send packets to different servers, ports, and services — testing what responds, what's listening, and what might be vulnerable. It's like knocking on every door in a building to see which ones are unlocked.

## Formal Definition

**MITRE ATT&CK T1595: Active Scanning**

Adversaries may execute active reconnaissance scans to gather information about resources and defenses that can be used during targeting. Examples include network scanning (e.g., Nmap), port scanning, and service discovery. This differs from passive reconnaissance because the adversary's tools directly interact with the target, potentially triggering alerts.

---

## Puzzle: Spot the Anomaly

Below are network logs from a company's edge firewall. One entry shows signs of active scanning. Can you find it?

```json
[
  {"timestamp": "2025-01-15T08:02:34Z", "src_ip": "203.0.113.45", "dst_ip": "10.0.1.5", "dst_port": 443, "protocol": "TCP", "action": "ALLOW", "reason": "Established connection"},
  {"timestamp": "2025-01-15T08:03:12Z", "src_ip": "203.0.113.45", "dst_ip": "10.0.1.6", "dst_port": 443, "protocol": "TCP", "action": "ALLOW", "reason": "Established connection"},
  {"timestamp": "2025-01-15T08:03:28Z", "src_ip": "192.168.1.100", "dst_ip": "10.0.1.5", "dst_port": 443, "protocol": "TCP", "action": "ALLOW", "reason": "Employee web browsing"},
  {"timestamp": "2025-01-15T08:04:01Z", "src_ip": "203.0.113.45", "dst_ip": "10.0.2.1", "dst_port": 22, "protocol": "TCP", "action": "BLOCK", "reason": "No reply"},
  {"timestamp": "2025-01-15T08:04:15Z", "src_ip": "203.0.113.45", "dst_ip": "10.0.2.2", "dst_port": 22, "protocol": "TCP", "action": "BLOCK", "reason": "No reply"},
  {"timestamp": "2025-01-15T08:04:29Z", "src_ip": "203.0.113.45", "dst_ip": "10.0.2.3", "dst_port": 22, "protocol": "TCP", "action": "BLOCK", "reason": "No reply"},
  {"timestamp": "2025-01-15T08:05:02Z", "src_ip": "203.0.113.45", "dst_ip": "10.0.2.50", "dst_port": 8080, "protocol": "TCP", "action": "BLOCK", "reason": "No reply"}
]
```

<details>
<summary>🔍 Reveal the anomaly</summary>

**The scanning activity is from `203.0.113.45`:**

- **08:02:34 → 08:03:12** — Two HTTPS connections to `10.0.1.5` and `10.0.1.6` (ports 443) within 38 seconds. These could be legitimate, but paired with the next activity, they're suspicious.
- **08:04:01 → 08:05:02** — Rapid sequential probes:
  - Port 22 (SSH) on `10.0.2.1`, `.2`, `.3` — **all no reply** (blocked)
  - Port 8080 on `10.0.2.50` — **no reply** (blocked)
  
**Why this is scanning:**
1. **Sequential IPs**: The attacker is incrementing through the `10.0.2.0/24` range
2. **Different ports on the same IPs**: Testing both port 22 and 8080 suggests discovery, not normal business traffic
3. **Short timeframe**: All 5 probes in ~3 minutes, from a single external IP
4. **No established connections**: These are blocked, suggesting the attacker is testing what's reachable

In contrast, `192.168.1.100` → `10.0.1.5:443` is normal employee web browsing (single connection, normal pattern).

</details>

---

## Detection Logic

### KQL (Microsoft Sentinel / Defender for Cloud)

```kql
// Detect rapid sequential port scans from external sources
NetworkSession
| where SrcIpAddr !in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
| where Protocol == "tcp"
| summarize PortsScanned = dcount(DstPort), UniqueTargets = dcount(DstIpAddr) by SrcIpAddr, bin(TimeGenerated, 5m)
| where PortsScanned >= 5 or UniqueTargets >= 10
| extend AlertSeverity = "Medium"
```

### YARA-L Detection

```yara
// YARA-L rule for scanning pattern detection in network logs
rule active_scanning_detection {
  meta:
    description = "Detects active scanning behavior from external IPs"
    mitre_id = "T1595"
    severity = "medium"
  
  events:
    $scan.metadata.event_type == "NETWORK_CONNECTION"
    $scan.network.src_ip != "10.0.0.0/8" and
    $scan.network.src_ip != "172.16.0.0/12" and
    $scan.network.src_ip != "192.168.0.0/16"
    $scan.network.protocol == "TCP"
  
  match:
    $scan over 5m
  
  condition:
    #$scan > 5
}
```

---

## MITRE Mapping

| Field | Value |
|-------|-------|
| **Tactic** | Reconnaissance (TA0043) |
| **Technique** | T1595: Active Scanning |
| **Sub-techniques** | T1595.001 (Scanning IP Blocks), T1595.002 (Find Listening Services), T1595.003 (Analyze Application Content) |
| **Platform** | Linux, Windows, macOS, Network |

---

## False Positives

| Scenario | Why It Triggers | Mitigation |
|----------|-----------------|------------|
| **Legitimate vulnerability scanner** (e.g., Nessus, Qualys running from corp subnet) | Scanners probe multiple ports/IPs by design | Whitelist internal scanner IPs; adjust threshold to >20 unique IPs in 5m |
| **Load balancer health checks** | Health checks probe backend servers rapidly | Exclude load balancer IPs from detection |
| **Automated monitoring tool** (e.g., Pingdom, Uptime Robot) | External monitors may scan your public IPs | Review allowlist; correlate with known monitoring vendors |
| **Pentesting engagement** | Authorized pentesters conduct active scans | Coordinate with security team; tag during engagement window |

---

**Last Updated:** January 2025
