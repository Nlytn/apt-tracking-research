# [APT Group Name] ([Alias(es)] — [Country or Sponsorship])

> **Example:** APT29 (Cozy Bear — Russia)

---

## 🧠 Overview

Brief description of the group. Who are they? What are they known for? Any affiliations (nation-state, financial motives, hacktivism)?

> _Example:_  
APT29 is a Russian cyber espionage group affiliated with the Russian Foreign Intelligence Service (SVR). Known for stealthy, long-term intrusions targeting diplomatic, governmental, and energy sector organizations.

---

## 🧭 Attribution

| Attribute          | Details                       |
|--------------------|-------------------------------|
| Suspected Origin   | [Country]                     |
| Affiliated Entity  | [SVR / PLA / APT Center 5, etc.] |
| First Observed     | [Year or Campaign]            |
| Target Sectors     | [Govt, Energy, Healthcare, etc.] |
| Notable Operations | [Operation X, Campaign Y]     |

---

## 🎯 Targeting Profile

- Geographic regions targeted  
- Industry verticals  
- Political or strategic motives (if known)

---

## 🛠️ Known Tactics, Techniques & Procedures (TTPs)

> Based on MITRE ATT&CK mappings

| Tactic              | Technique | ID     | Description                        |
|---------------------|-----------|--------|------------------------------------|
| Initial Access      | Spearphishing Attachment | T1566.001 | Malicious document lures          |
| Execution           | PowerShell               | T1059.001 | Script-based payload execution    |
| Persistence         | Scheduled Task           | T1053.005 | Recurring tasks for persistence   |
| Credential Access   | LSASS Dumping            | T1003.001 | Credential theft from memory      |
| Command & Control   | HTTPS                    | T1071.001 | Encrypted C2 over port 443        |

_(Add/remove rows as needed)_

---

## 🧾 Tooling & Malware

| Tool / Malware | Purpose                | Notes                          |
|----------------|------------------------|--------------------------------|
| Cobalt Strike  | C2 Framework           | Used heavily in later stages   |
| WellMess       | Custom backdoor        | Seen in 2020 UK vaccine attack |
| Mimikatz       | Credential Access Tool | Standard credential dumper     |

---

## 📜 Notable Campaigns

### 🎯 Operation Name (Year)
- **Target**: [Govt agencies in XYZ]
- **TTPs**: [Phishing, Cobalt Strike, LSASS dumping]
- **Notes**: [Description, unique behaviors]

---

## 📚 Key Intelligence Sources

- [🔗 Mandiant Threat Profile](https://www.mandiant.com/)
- [🔗 MITRE ATT&CK Entry](https://attack.mitre.org/groups/)
- [🔗 CISA Alert or Advisory](https://www.cisa.gov/)
- [🔗 CrowdStrike Blog / Report](https://www.crowdstrike.com/blog/)
- [🔗 [Report Title]](https://...)

---

## 📂 Indicators of Compromise (IOCs)

| Type       | Value                         | Description     |
|------------|-------------------------------|-----------------|
| IP Address | 185.143.223.101               | C2 Server       |
| Domain     | example-mail[.]com            | Phishing domain |
| SHA256     | f3a90e8fa...                  | Payload hash    |

---

## 🧪 Detection Notes / Hunting Ideas

- Look for long-running PowerShell processes with no parent console window.
- Correlate use of rundll32 with abnormal DLL paths.
- Identify LSASS access attempts outside approved tooling.

---

## 🧠 Analyst Notes

- Any oddities or contradictions in reporting?  
- Differences between vendor assessments?  
- What surprised you about this group?

---

*Last updated: YYYY-MM-DD*
