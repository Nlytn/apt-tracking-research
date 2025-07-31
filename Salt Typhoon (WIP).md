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
| Notable Operations | Campaign Alpha - Taiwanese Government and Chemical Company *needs more context/details* (TrendMicro)|
| Notable Operations | Campaign Beta - Telecommunications and Government Entities (US & Others) *needs more context/details* (TrendMicro)|

---

## 🎯 Targeting Profile

- North America (USA), Asia (Taiwan), Africa  
- Industry verticals
- Political or strategic motives (if known)
   * Counterintelligence
   * Telecom
   * Military

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
| BitsAdmin           | Uploads/downloads from web servers or file shares | {Unknown}|
| CertUtil            | Managing certificates, certificate chains and CA configurations | {Unknown} |
| Cheat Engine driver | Compiler for cheating in video games | {Unknown} |
| Cobalt Strike       | Commercial Pentesting Tool | {Unknown}                       |
| CrowDoor            | Backdoor program  | Installed using CAB files and used to collect data from local systems and shared drives [🔗 Link to source of information - Pulsedive](https://pulsedive.com/threat/Crowdoor)|
| Demodex             | Windows Kernel-mode rootkit | Rootkit used to maintain access and invisibility |
| Get-PassHashes.ps1  | Dump password hashes to obtain user access       | The payload dumps password hashes using the modified powerdump script from MSF - [Link to Download](https://github.com/samratashok/nishang/blob/master/Gather/Get-PassHashes.ps1)  |
| GhostSpider         | Backdoor program        | TLS encrypted C&C communication |
| HEMIGATE            | Backdoor program        | Sideloaded with another program - K7AVMScn.exe/K7AVWScn.dll (K7 Computing) [TrendMicro Report](https://www.trendmicro.com/en_us/research/23/h/earth-estries-targets-government-tech-for-cyberespionage.html)|
| JumbledPath         | {Unknown}               | {Unknown}                       |
| Ladon               | {Unknown}               | {Unknown}                       |
| Malleable C2        | Command & Control      | {Unknown}                       |
| Masol RAT           | {Unknown}               | {Unknown}                       |
| mimkat_ssp          | {Unknown}               | {Unknown}                       |
| NBTscan             | {Unknown}               | {Unknown}                       |
| Powercat            | {Unknown}               | {Unknown}                       |
| Powershell          | {Unknown}               | {Unknown}                       |
| ProcDump            | {Unknown}               | {Unknown}                       |
| PsExec              | {Unknown}               | {Unknown}                       |
| PsList              | {Unknown}               | {Unknown}                       |
| ShadowPad           | {Unknown}               | {Unknown}                       |
| SMB                 | {Unknown}               | {Unknown}                       |
| SnappyBee           | {Unknown}               | {Unknown}                       |
| SparrowDoor         | {Unknown}               | {Unknown}                       |
| Token.exe           | {Unknown}               | {Unknown}                       |
| TrillClient         | {Unknown}               | {Unknown}                       |
| WinRAR              | {Unknown}               | {Unknown}                       |
| WMIC                | {Unknown}               | {Unknown}                       |
| WMIExec             | {Unknown}               | {Unknown}                       |
| ZINGDOOR            | {Unknown}               | {Unknown}                       |



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
- [🔗 TrendMicro - Unveiling Long Term Earth Estries Cyber Intrusions](https://www.trendmicro.com/en_us/research/24/k/earth-estries.html)
- [ Wikipedia Entry](https://en.wikipedia.org/wiki/Salt_Typhoon)

---

## 📂 Indicators of Compromise (IOCs)

| Type       | Value                         | Description     |
|------------|-------------------------------|-----------------|
| IP Address | 103.91.64.214                 | Demodex       |
| IP Address | 165.154.227.192               | frpc       |
| IP Address | 23.81.41.166	                 | Open directory C&C       |
| IP Address | 158.247.222.165               | SNAPPYBEE       |
| IP Address | 172.93.165.14	               | related C&C       |
| IP Address | 91.245.253.27	               | SNAPPYBEE       |
| IP Address | 103.75.190.73	               | related C&C       |
| IP Address | 45.125.67.144	               | Demodex       |
| IP Address | 43.226.126.164               | Demodex       |
| IP Address | 172.93.165.10	               | Demodex       |
| IP Address | 193.239.86.168               | Demodex       |
| IP Address | 146.70.79.18               | Demodex       |
| IP Address | 185.143.223.101               | Demodex       |
| IP Address | 205.189.160.3               | Demodex       |
| IP Address | 96.9.211.27               | Demodex       |
| IP Address | 43.226.126.165               | Demodex       |
| IP Address | 139.59.108.43               | GHOSTSPIDER       |
| IP Address | 185.105.1.243	               | GHOSTSPIDER       |
| IP Address | 143.198.92.175               | GHOSTSPIDER       |
| IP Address | 139.99.114.108               | GHOSTSPIDER       |
| IP Address | 139.59.236.31	               | GHOSTSPIDER       |
| IP Address | 104.194.153.65               | GHOSTSPIDER       |
| Domain     | materialplies.com            | Campaign Alpha (related C&C) |
| Domain     | news.colourtinctem.com            | Campaign Alpha (related C&C) |
| Domain     | api.solveblemten.com            | Campaign Alpha (SNAPPYBEE) |
| Domain     | esh.hoovernamosong.com            | Campaign Alpha (SNAPPYBEE) |
| Domain     | vpn114240349.softether.net            | Campaign Alpha (SoftEther VPN) |
| Domain     | imap.dateupdata.com            | Campaign Beta (DEMODEX) |
| Domain     | pulseathermakf.com            | Campaign Beta (DEMODEX) |
| Domain     | www.infraredsen.com            | Campaign Beta (DEMODEX) |
| Domain     | billing.clothworls.com            | Campaign Beta (GHOSTSPIDER) |
| Domain     | helpdesk.stnekpro.com            | Campaign Beta (GHOSTSPIDER) |
| Domain     | jasmine.lhousewares.com            | Campaign Beta (GHOSTSPIDER) |
| Domain     | private.royalnas.com            | Campaign Beta (GHOSTSPIDER) |
| Domain     | telcom.grishamarkovgf8936.workers.dev            | Campaign Beta (GHOSTSPIDER) |
| Domain     | vpn305783366.softether.net            | Campaign Beta (SoftEther VPN) |
| Domain     | vpn487875652.softether.net            | Campaign Beta (SoftEther VPN) |
| Domain     | vpn943823465.softether.net            | Campaign Beta (SoftEther VPN) |
| Log Entry - PowerShell  | Powershell.exe -ex bypass c:\windows\assembly\onedrived.ps1 | Install demodex rootkit    |
| SHA256     | f3a90e8fa...                  | Payload hash    |
| Service/Export Name | spider.dll / core.dll | First-stage stager [Initial infection and stager deployment](https://www.trendmicro.com/en_us/research/24/k/earth-estries.html)


[🔗 Source of IOC's](https://www.trendmicro.com/content/dam/trendmicro/global/en/research/24/k/earth-estries/IOC_list-EarthEstries.txt)

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
