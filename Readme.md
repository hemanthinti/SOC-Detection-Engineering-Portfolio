<html><body>
<!--StartFragment--><html><head></head><body>
<h1>🛡️ SOC &amp; Detection Engineering Portfolio</h1>
<p><strong>Hemanth Inti</strong> · SOC Analyst L2 · MSSP-based SOC Operations</p>
<p><a href="https://linkedin.com/in/inti-hemanth/"><img src="https://img.shields.io/badge/LinkedIn-inti--hemanth-0A66C2?style=flat-square&amp;logo=linkedin&amp;logoColor=white" alt="LinkedIn"></a>
<img src="https://img.shields.io/badge/Focus-Detection%20Engineering-critical?style=flat-square" alt="Focus">
<img src="https://img.shields.io/badge/KQL-Primary-blue?style=flat-square" alt="KQL">
<img src="https://img.shields.io/badge/YARA--L-Secondary-blueviolet?style=flat-square" alt="YARA--L"></p>

<hr>
<h2>👋 About Me</h2>
<p>I'm a SOC Analyst L2 with ~3 years of experience in 24x7 enterprise security operations at an MSSP, working across Microsoft Defender XDR, Microsoft Sentinel, Google SecOps (Chronicle), and Proofpoint. This portfolio demonstrates my hands-on detection engineering, incident response methodology, and threat intelligence synthesis.</p>

<h3>🧰 Stack</h3>
<p><img src="https://img.shields.io/badge/-Microsoft%20Defender%20XDR-0078D4?style=flat-square&amp;logo=microsoft&amp;logoColor=white" alt="Defender XDR">
<img src="https://img.shields.io/badge/-Microsoft%20Sentinel-0078D4?style=flat-square&amp;logo=microsoft&amp;logoColor=white" alt="Sentinel">
<img src="https://img.shields.io/badge/-Google%20SecOps%20(Chronicle)-4285F4?style=flat-square&amp;logo=google&amp;logoColor=white" alt="Chronicle">
<img src="https://img.shields.io/badge/-Proofpoint-E31937?style=flat-square" alt="Proofpoint">
<img src="https://img.shields.io/badge/-Entra%20ID-0078D4?style=flat-square&amp;logo=microsoft&amp;logoColor=white" alt="Entra ID">
<img src="https://img.shields.io/badge/-Wiz-611BBD?style=flat-square" alt="Wiz">
<img src="https://img.shields.io/badge/-Google%20Threat%20Intelligence-4285F4?style=flat-square&amp;logo=google&amp;logoColor=white" alt="GTI">
<img src="https://img.shields.io/badge/-ServiceNow-00C7D4?style=flat-square&amp;logo=servicenow&amp;logoColor=white" alt="ServiceNow">
<img src="https://img.shields.io/badge/-JIRA-0052CC?style=flat-square&amp;logo=jira&amp;logoColor=white" alt="JIRA"></p>
<h3>🎓 Certifications</h3>
<p><img src="https://img.shields.io/badge/CompTIA-Security%2B%20(SY0--701)-EE0000?style=flat-square" alt="Security+">
<img src="https://img.shields.io/badge/Microsoft-SC--200-0078D4?style=flat-square" alt="SC-200">
<img src="https://img.shields.io/badge/Google-Professional%20Security%20Operations%20Engineer-4285F4?style=flat-square" alt="Google SOE">
<img src="https://img.shields.io/badge/Google-Associate%20Cloud%20Engineer-4285F4?style=flat-square" alt="Google ACE">
<img src="https://img.shields.io/badge/Microsoft-AZ--900-0078D4?style=flat-square" alt="AZ-900">
<img src="https://img.shields.io/badge/AWS-Certified%20Cloud%20Practitioner-FF9900?style=flat-square" alt="AWS CCP"></p>
<hr>
<h2>🎯 What This Repo Demonstrates</h2>
<p>This isn't a collection of copy-pasted queries — every piece here reflects my own reasoning about <em>why</em> a detection is written the way it is, what it maps to in MITRE ATT&CK, and what edge cases might trigger false alarms. Each technique includes the full story: from plain-English explanation to interactive puzzles, sample logs, detection rules (KQL + YARA-L), and tuning guidance.</p>

<h2>🗂️ Repository Structure</h2>
<pre><code>SOC-Detection-Engineering-Portfolio/
├── attack-stories/              # Interactive MITRE ATT&CK Enterprise learning
│   ├── 01-reconnaissance/
│   │   ├── T1595-active-scanning/
│   │   └── T1598-phishing-for-information/
│   ├── 02-resource-development/
│   ├── 03-initial-access/
│   ├── 04-execution/
│   ├── 05-persistence/
│   ├── 06-privilege-escalation/
│   ├── 07-defense-evasion/
│   ├── 08-credential-access/
│   ├── 09-discovery/
│   ├── 10-lateral-movement/
│   ├── 11-collection/
│   ├── 12-command-and-control/
│   ├── 13-exfiltration/
│   └── 14-impact/
├── campaign-analysis/           # Deep-dives on named threat campaigns
├── Methodology/                 # General IR/detection frameworks and process writeups
│   └── Multi-Vector Incident Response &amp; Recovery/
├── homelab/                     # Attack simulations + end-to-end validated detections
└── Readme.md
</code></pre>

| Folder | What's inside |
| -- | -- |
| attack-stories/ | **Featured section.** Each MITRE ATT&CK Enterprise tactic (14 total) with non-technical stories, formal definitions, and techniques with interactive "spot the anomaly" puzzles, sample logs, detection rules (KQL + YARA-L), and false positive guidance. |
| campaign-analysis/ | Named, publicly reported campaigns broken down into TTPs, cited IOCs, and matching detection logic. |
| Methodology/ | Process-level writeups — incident response frameworks, remediation workflows, and the reasoning behind them (not tied to a specific named campaign). |
| homelab/ | Simulated attacks (via Atomic Red Team or similar) with raw logs and the detection logic that catches them — fully self-contained, zero client dependency. |


<h2>📌 A Note on Sourcing</h2>
<p>Any IOC, technique detail, or campaign fact referenced in this repo is drawn from and cited to public vendor/CTI reporting (e.g., Microsoft, Mandiant, CrowdStrike blogs). Detection logic is my own synthesis, tested and refined through real SOC operations. I do not include any proprietary client-specific data, indicators, or internal processes.</p>
<hr>
<p><strong>📫 Connect with me on <a href="https://linkedin.com/in/inti-hemanth/">LinkedIn</a></strong> — I write a running series on practitioner-level SOC analysis and detection engineering topics.</p>
</body></html><!--EndFragment-->
</body>
</html>
