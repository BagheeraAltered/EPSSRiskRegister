
I've written more about this in the projects section of my site: https://www.bagheeralabs.com


# EPSSRiskRegister

EPSS
The EPSS model produces a probability score between 0 and 1 (0 and 100%). The higher the score, the greater the probability that a vulnerability will be exploited.
https://www.first.org/epss/

A Cybersecurity Asset Risk Register is to systematically identify, assess, and manage the risks associated with an organization's  assets. It details each asset's vulnerabilities, the threats exploiting these vulnerabilities, the current controls in place, and the residual risk after these controls are applied. By maintaining a Cybersecurity Asset Risk Register, organizations can ensure a structured and proactive approach to safeguarding their digital ecosystem against evolving cyber threats, thereby enhancing their resilience and security posture.

This script is an illustration of of how to combine the EPSS score into a Risk Register

The script uses ProjectDiscoveries subfinder and nuclei technology detection tools to identify assets and fingerprint them. There are probabaly better ways to do this, but it's good enough for this illustration purpose.

The technology is queried on the NIST NVD database, using the nvdlib api, gathering CVEID, and Descriptions.
The EPSS api is queried for the EPSS score, and all of these are added to a Risk Register Matrix.

Project Discovery has a tool called CVEMAP that could probably be used and do this is a four line bash script.

This is the theoretical output:

## Impact Criteria				
				
| Impact Scores | Mission | Operational Objectives | Financial Objectives | Obligations |
|---------------|---------------|---------------|---------------|---------------|
| Definition | | | The high dollar limit for each impact score.	| |
| 1. Acceptable | We would achieve our mission. |	We would meet our objectives. | |	No harm would come to others. |
| 2. Unacceptable |	We would have to reinvest or correct the situation to achieve our mission. | We would have to reinvest or correct the situation to achieve our objectives. | | The harm that would come to others would be correctable. |
| 3. Catastrophic |	We would not be able to achieve our mission. | We would not be able to meet our objectives. | | The harm that would come to others would not be correctable.|




## Asset Risk Register Matrix


| Asset | Technology | CVE | EPSS Score | Description |
|-------|------------|-----|------------|-----|
| remote.example.com | Palo Alto Networks GlobalProtect     | CVE-2012-6606 | 0.000610000  | Palo Alto Networks GlobalProtect before 1.1.7, and NetConnect, does not verify X.509 certificates from SSL servers, which allows man-in-the-middle attackers to spoof portal servers and obtain sensitive information via a crafted certificate.|
| portal.example.com | Palo Alto Networks GlobalProtect     | CVE-2012-6606 | 0.000610000  | Palo Alto Networks GlobalProtect before 1.1.7, and NetConnect, does not verify X.509 certificates from SSL servers, which allows man-in-the-middle attackers to spoof portal servers and obtain sensitive information via a crafted certificate.|
