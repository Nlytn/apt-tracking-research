Observations and conclusions on Salt Typhoon will be compiled here

Target: Government entities and related telecom providers
Goal: Unclear as of now, but seems to be intent on exfiltrating national secrets

Initial access: compromise of network devices. In one instance, Cisco reports finding CVE-2018-0171 was abused; however in other instances the victim credentials were obtained illegitimately (https://blog.talosintelligence.com/salt-typhoon-analysis/). Though the blog does not mention specifics, it is safe to assume this is some form of social engineering (i.e. phishing), default credentials, or potentially an insecure repository of username/password information. This allowed them to find other upstream/downstream devices.

### Mentioned CVE's - Further review required to understand context in attack -> will add and update
CVE-2018-0171 - Cisco IOS and IOS XE Software Smart Install Remote Code Execution Vulnerability (Last Updated: 15-Dec-2022)
CVE-2023-20198, CVE-2023-20273 - Multiple Vulnerabilities in Cisco IOS XE Software Web UI Feature (Last Updated: 1-Nov-2023)
CVE-2024-20399 - Cisco NX-OS Software CLI Command Injection Vulnerability (Last Updated: 17-Sep-2024)

* Compromise account
* Find other credential hashes
     * Once access is secured, the attacker sniffs for TACACS/RADIUS traffic, as well as SNMP, in hopes of capturing traffic w/ keys for later decryption
* Exfiltrate those to crack offline
* Move laterally to other network devices
* Hit initial Telecom provider in order to pivot to a different provider

Hypothesis:
---
* To gather information on & infiltrate telecom industry corporations. (It is important to note that while the telecommunications industry is the primary victim... - [Weathering the storm: In the midst of a Typhoon](https://blog.talosintelligence.com/salt-typhoon-analysis/)) 

[Recorded Future analysis (See section "Technical Analysis")](https://www.recordedfuture.com/research/redmike-salt-typhoon-exploits-vulnerable-devices)
---
* First noticed in 2024
* Attempted to exploit over 1,000 internet-facing Cisco network devices worldwide (primarily telecommunications providers)
    * Used combination of two **privilege escalation** vulnerabilities:
      * CVE-2023-20198 -> found in Cisco IOS XE software web UI feature (version 16 and earlier) -> published by Cisco in 2023
          * Actors exploited this vulnerability to gain initial access to the device and issue a *privilege 15 command* to create a local user and password.
      * CVE-2023-20273 -> Subsequent to the previous exploit, once an account has been created this vulnerability is leveraged to gain *root user privileges* 
* When successful, group uses new privileged user account to change device's configuration and adds a GRE tunnel for persistent access and data exfiltration
* It is believed the targets were telecommunications providers and universities
      * It is believed the targets were research in areas related to telecommunications, engineering, and technology
* Scanning and exploitation activity was recorded on six (6) different occasions between December 2024 and January 2025
  * 2024-12-04
  * 2024-12-10
  * 2024-12-17
  * 2024-12-24
  * 2025-01-13
  * 2025-01-23

* Seven compromised Cisco network devices communicating with Salt Typhoon/RedMike including devices associated with:
  * US Based affiliate of a UK telecommunications provider
  * US internet service provider (ISP) and telecommunications company
  * South African telecommunications provider
  * Italian ISP
  * A large Thailand telecommunications provider


Attack Flow is as follows (WIP - Potentially to be removed):
---
* Recon:  Open source intelligence gathering on target devices. Targets involved Cisco network devices that were publicly facing and known to be associated with telecom companies and university institutions.
    * Once targets were acquired, scans were run against the devices; these scans led to discovery of CVE-2023-20198 as an opening.
* Initial Access: Leveraging this vulnerability, the actor was able to gain initial access into the target network. This exploit allows the actor to bypass authentication to reach the webui_wsma_http endpoint. Executing the exploit allows arbitrary Cisco IOS commands or configuration changes to be issued with Privilege 15 privileges
    * Privilege 15 is the *highest* privilege level available on Cisco devices
    * The actor used this ability to create a new local account
* Next, the actor leveraged CVE-2023-20273 to elevate the new account to root level
    *  Due to insufficient input validation, actor could remotely exploit vulnerability by sending crafted input to web UI.
    *  This allowed the actor to elevate privileges of newly created account
*  The actor then created GRE tunnels between their own infrastructure and the compromised Cisco devices, likely in attempts to set up exfiltration pipelines.
*  Questions:
    * What were their next steps? How did they pivot, and what did they target?
    * What was the target information? RecordedFuture appears to think its related to research on telecommunications, engineering and technology.

Overview: 
---
Salt Typhoon is sponsored by the People's Rebublic of China (PRC) and has been active since as early as 2019 (2024 - Talos). The main targets have been major telecommunications companies across the United States. The latest reports indicate nine (9) telecommunications providers have been breached[1]:
* AT&T
* Verizon
* T-Mobile
* Lumen Technologies
*  

[1]: [US Telecom Breaches Widen to 9 Firms Hit by Chinese Salt Typhoon Hackers](https://hackread.com/us-telecom-breaches-firms-chinese-salt-typhoon-hackers/)
