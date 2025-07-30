# Salt Typhoon — People's Republic of China (PRC))



> **Aliases:**
>
> - Earth Estries
>
> - FamousSparrow
>
> - GhostEmperor
>
> - RedMike
>
> - UNC2286
>
> - Flax Typhoon (Potentially; requires confirmation)
>
> - Volt Typhoon (CISA)
---

## 🧠 Overview

Salt Typhoon is a People's Republic of China (PRC) state-backed actor that has been active since at least 2019 and responsible for numerous compromises of network infrastructure at major U.S. telecommunication and internet service providers (ISP). - Mitre

---

## 🧭 Attribution

| Attribute          | Details                       |
|--------------------|-------------------------------|
| Suspected Origin   | China                         |
| Affiliated Entity  | PRC/Unknown                   |
| First Observed     | 2019                          |
| Target Sectors     | Telecom/ISP/Government        |
| Notable Operations | *Nothing yet, but still looking*|

---

## 🎯 Targeting Profile

- North America (USA), Asia (Taiwan), Africa  
- Industry verticals  
- Political or strategic motives (if known)

---

## 🛠️ Known Tactics, Techniques & Procedures (TTPs)

> Based on MITRE ATT&CK mappings

| Tactic              | Technique        | ID     | Description                          |
|---------------------|-----------|---------------|--------------------------------------|
| Reconnaissance      | Network Topology | T1590.004 | Salt Typhoon has used configuration files from exploited network devices to help discover upstream and downstream network segments  |
| Resource Development | Malware | T1587.001 |   Salt Tyhpoon has employed custom tooling including JumbledPath |
| Resource Development | Tool | T1588.002 | Salt Typhoon has used publicly available tooling to exploit vulnerabilities  |
| Initial Access      | Exploit Public Facing Application | T1190 | Salt Typhoon has exploited CVE-2018-0171 in the Smart Install feature of Cisco IOS and Cisco IOS XE software for initial access  |
| Execution           | Create Account                    | T1136 | Salt Typhoon has created Linux-level users on compromised network devices through modification of /etc/shadow and /etc/passwd   |
| Persistence         | SSH Authorized Keys               | T1098.004 | Salt Typhoon has added SSH authorized_keys under root or other users at the Linux level on compromised network devices   |
| Privilege Escalation | SSH Authorized Keys              | T1098.004 | Salt Typhoon has added SSH authorized_keys under root or other users at the Linux level on compromised network devices   |
| Defense Evasion     | Disable or Modify System Firewall | T1562.004 | Salt Typhoon has made changes to Access Control List (ACL) and loopback interface address on compromised devices   |
| Defense Evasion     | Indicator Removal: Clear Linux or Mac System Logs | T1070.002 | Salt Typhoon has cleared logs including .bash_history, auth.log, lastlog, wtmp, btmp   |
| Credential Access   | Network Sniffing                  | T1040     | Salt Typhoon has used a variety of tools and techniques to capture packet data between network interfaces  |
| Credential Access   | Password Cracking                 | T1110.002 | Salt Typhoon has cracked passwords for accounts with weak encryption obtained from the configuration files of compromised network devices  |
| Discovery           | Network Sniffing                  | T1040     | Salt Typhoon has used a variety of tools and techniques to capture packet data between network interfaces  |
| Lateral Movement    | SSH                               | T1021.004 | Salt Typhoon has has modified the loopback address on compromised switches and used them as the source of SSH connections to additional devices within the target environment, allowing them to bypass access control lists (ACLs).  |
| Collection          | Data from Configuration Repository: Network Device Configuration Dump | T1602.002 | Salt Typhoon has attempted to acquire credentials by dumping network device configurations. |
| Command & Control   | Protocol Tunneling (GRE)           | T1572   | Salt Typhoon has modified device configurations to create and use Generic Routing Encapsulation (GRE) tunnels |

_(Add/remove rows as needed)_

---

## 🧾 Tooling & Malware

| Tool / Malware | Purpose                | Notes                          |
|----------------|------------------------|--------------------------------|
| BitsAdmin           | {Uknown}               | {Uknown}                       |
| CertUtil            | {Uknown}               | {Uknown}                       |
| Cheat Engine driver | {Uknown}               | {Uknown}                       |
| Cobalt Strike       | {Uknown}               | {Uknown}                       |
| CrowDoor            | {Uknown}               | {Uknown}                       |
| Demodex             | {Uknown}               | {Uknown}                       |
| Get-PassHashes.ps1  | {Uknown}               | {Uknown}                       |
| GhostSpider         | {Uknown}               | {Uknown}                       |
| HEMIGATE            | {Uknown}               | {Uknown}                       |
| JumbledPath         | {Uknown}               | {Uknown}                       |
| Ladon               | {Uknown}               | {Uknown}                       |
| Malleable C2        | Command & Control      | {Uknown}                       |
| Masol RAT           | {Uknown}               | {Uknown}                       |
| mimkat_ssp          | {Uknown}               | {Uknown}                       |
| NBTscan             | {Uknown}               | {Uknown}                       |
| Powercat            | {Uknown}               | {Uknown}                       |
| Powershell          | {Uknown}               | {Uknown}                       |
| ProcDump            | {Uknown}               | {Uknown}                       |
| PsExec              | {Uknown}               | {Uknown}                       |
| PsList              | {Uknown}               | {Uknown}                       |
| ShadowPad           | {Uknown}               | {Uknown}                       |
| SMB                 | {Uknown}               | {Uknown}                       |
| SnappyBee           | {Uknown}               | {Uknown}                       |
| SparrowDoor         | {Uknown}               | {Uknown}                       |
| Token.exe           | {Uknown}               | {Uknown}                       |
| TrillClient         | {Uknown}               | {Uknown}                       |
| WinRAR              | {Uknown}               | {Uknown}                       |
| WMIC                | {Uknown}               | {Uknown}                       |
| WMIExec             | {Uknown}               | {Uknown}                       |
| ZINGDOOR            | {Uknown}               | {Uknown}                       |



---

## 📜 Notable Campaigns

### 🎯 Operation Name (Year)
- **Target**: [Govt agencies in XYZ]
- **TTPs**: [Phishing, Cobalt Strike, LSASS dumping]
- **Notes**: [Description, unique behaviors]

---

## 📚 Key Intelligence Sources

- [🔗 Mandiant Threat Profile - *Nothing Yet*](https://www.mandiant.com/)
- [🔗 MITRE ATT&CK Entry](https://attack.mitre.org/groups/G1045/)
- [🔗 CrowdStrike Blog / Report - *Nothing Yet*](https://www.crowdstrike.com/blog/)
- [🔗 FortiGuard Labs Report](https://www.fortiguard.com/threat-actor/5557/salt-typhoon)
- [🔗 CISA Statement on Targeting of Telecom Infrastructure](https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-038a)
- [🔗 CISA - Strengthening against PRC Threats](https://www.cisa.gov/news-events/news/strengthening-americas-resilience-against-prc-cyber-threats)

---

## 📂 Indicators of Compromise (IOCs)

| Type       | Value                         | Description     |
|------------|-------------------------------|-----------------|
| IP Address | 185.143.223.101               | C2 Server       |
| Domain     | example-mail[.]com            | Phishing domain |
| SHA256     | f3a90e8fa...                  | Payload hash    |

---

## 🧪 Detection Notes / Hunting Ideas

- To be added...

---
## :waning_crescent_moon: Potential Overlap - Need further research

- [🔗 Microsoft reports this could also be related to threat actor Flax Typhoon](https://www.microsoft.com/en-us/security/blog/2023/08/24/flax-typhoon-using-legitimate-software-to-quietly-access-taiwanese-organizations/)
- [🔗 Mandiant reports this threat shows overlap](https://cloud.google.com/blog/topics/threat-intelligence/cybercrime-multifaceted-national-security-threat)
- [🔗 Second Mandiant Report](https://cloud.google.com/blog/topics/threat-intelligence/unc4841-post-barracuda-zero-day-remediation)

---

## 🧠 Analyst Notes

- Any oddities or contradictions in reporting?  
- Differences between vendor assessments?  
- What surprised you about this group?

---

*Last updated: 2025-07-30*
