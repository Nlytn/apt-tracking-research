Observations and conclusions on Salt Typhoon will be compiled here

Target: Government entities and related telecom providers
Goal: Unclear as of now, but seems to be intent on exfiltrating national secrets

Initial access: compromise of network devices. In one instance, Cisco reports finding CVE-2018-0171 was abused; however in other instances the victim credentials were obtained illegitimately (https://blog.talosintelligence.com/salt-typhoon-analysis/). Though the blog does not mention specifics, it is safe to assume this is some form of social engineering (i.e. phishing), default credentials, or potentially an insecure repository of username/password information. This allowed them to find other upstream/downstream devices.

### Mentioned CVE's - Further review required to understand context in attack -> will add and update
CVE-2018-0171 - Cisco IOS and IOS XE Software Smart Install Remote Code Execution Vulnerability (Last Updated: 15-Dec-2022)
CVE-2023-20198, CVE-2023-20273 - Multiple Vulnerabilities in Cisco IOS XE Software Web UI Feature (Last Updated: 1-Nov-2023)
CVE-2024-20399 - Cisco NX-OS Software CLI Command Injection Vulnerability (Last Updated: 17-Sep-2024)

* Compromise account
    * Once access is secured, the attacker sniffs for TACACS/RADIUS traffic, as well as SNMP, in hopes of capturing traffic w/ keys for later decryption
* Find other credential hashes
* Exfiltrate those to crack offline
