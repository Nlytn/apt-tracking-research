Observations and conclusions on Salt Typhoon will be compiled here

Target: Government entities and related telecom providers
Goal: Unclear as of now, but seems to be intent on exfiltrating national secrets

Initial access: compromise of cisco devices leads to mapping of network. This leads to discovery of external facing servers connected to network. These servers are compromised by a known CVE (WILL ADD SPECIFIC CVE LATER), which allows initial access. Then the attackers pivot to the internal network, scooping credentials and elevating permissions as possible. THe full impact of these attacks have not been realized as of yet. 
