# 🎯 Attack Stories: Interactive MITRE ATT&CK Enterprise Learning

## Concept

Each MITRE ATT&CK Enterprise tactic gets a **short, non-technical story** that explains what the tactic means in plain language, followed by its formal definition. Each technique under a tactic includes:

- **Interactive "Spot the Anomaly" Puzzle**: Real-world sample logs with a hidden answer
- **Detection Rule**: KQL and YARA-L implementations
- **MITRE Mapping**: Official tactic/technique reference
- **False Positives**: Known edge cases and tuning guidance

## 14 MITRE ATT&CK Enterprise Tactics

| # | Tactic | MITRE ID | Status | Description |
|---|--------|----------|--------|-------------|
| 1 | Reconnaissance | TA0043 | In progress | Adversary gathers information before attacking |
| 2 | Resource Development | TA0042 | Planned | Adversary establishes resources for the attack |
| 3 | Initial Access | TA0001 | Planned | Adversary gains first foothold |
| 4 | Execution | TA0002 | Planned | Adversary runs code or commands |
| 5 | Persistence | TA0003 | Planned | Adversary maintains presence |
| 6 | Privilege Escalation | TA0004 | Planned | Adversary gains higher access level |
| 7 | Defense Evasion | TA0005 | Planned | Adversary avoids detection |
| 8 | Credential Access | TA0006 | Planned | Adversary steals login credentials |
| 9 | Discovery | TA0007 | Planned | Adversary learns about the environment |
| 10 | Lateral Movement | TA0008 | Planned | Adversary moves to other systems |
| 11 | Collection | TA0009 | Planned | Adversary gathers data of interest |
| 12 | Command and Control | TA0011 | Planned | Adversary communicates with malware |
| 13 | Exfiltration | TA0010 | Planned | Adversary steals data out |
| 14 | Impact | TA0040 | Planned | Adversary damages or disrupts systems |

---

## How to Use This Section

1. **Start with the story** — get context in plain English
2. **Read the formal definition** — understand the MITRE framework
3. **Try the puzzle** — spot the anomaly in real logs
4. **Reveal the answer** — see what you missed
5. **Study the detection** — learn how to write the rule yourself
6. **Check false positives** — understand when the rule might trigger legitimately

---

**Each tactic folder contains one or more techniques** with full, interactive content.
