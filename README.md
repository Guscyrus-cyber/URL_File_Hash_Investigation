**URL & File Hash Reputation Investigation**

Main SOC Skill: IOC Enrichment\
Primary Tools: VirusTotal, URL analysis, file-hash analysis\
Analyst Role: Tier-1 SOC Analyst

Investigate URL and file-hash IOCs, enrich the indicators with reputation/threat-intelligence data, interpret the results correctly, and determine whether escalation is warranted.

Lab Workflow

Scenario/Evidence → IOC Extraction → VirusTotal Investigation → Reputation Analysis → Analyst Validation → Classification → MITRE ATT&CK (when evidence supports it) → SOC Conclusion → GitHub Documentation\
\
I will not assume that a VirusTotal detection automatically means malicious activity. The important SOC skill is interpreting the enrichment data in context.

Step 1 — Investigation Scenario

A Tier-1 SOC analyst receives an alert involving a suspicious URL and a downloaded file. The alert contains the following artifacts:

Alert Name: Suspicious File Detection\
Severity: Medium\
Source Host: WS-104\
Timestamp: 2026-09-21 14:32:18 UTC

Observed URL: https://secure.eicar.org/eicar.com\
\
Filename: eicar.com

SHA-256:\
275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f

Observed Activity: bSecurity monitoring detected a suspicious file on WS-104.

Additional Evidence:\
No execution evidence available.\
No persistence activity confirmed.\
No endpoint behavioral evidence available.\
\
SOC analyst: extracting the IOCs from the evidence.

Identify these three items:

URL: https://secure.eicar.org/eicar.com\
Filename: eicar.com\
SHA-256 hash: 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f

Step 2 — URL Reputation Investigation

I open [<u>VirusTotal</u>](https://www.virustotal.com/?utm_source=chatgpt.com) and I select search, then I submit SHA-256 hash. (Images 1 through 5)

\
\
\
\
\
\
\
\
\
\
Step 3 — Reputation Analysis and Analyst Validation
---------------------------------------------------

Interpreting VirusTotal results without treating detection count alone as proof of malware.

I review the VirusTotal results already collected, and I record the following evidence:

SHA-256: 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f\
\
Filename: eicar.com\
\
File Size: 68 B\
\
VirusTotal Detection: 66 / 68\
\
Popular Threat Label: virus.eicar/test\
\
Examples of Vendor Results: Microsoft: Virus:DOS/EICAR_Test_File\
\
BitDefender: EICAR-Test-File (not A Virus)\
\
Avast: EICAR Test-NOT Virus!!! Kaspersky: EICAR-Test-File\
\
Symantec: EICAR Test String\
\
66 = 66 security vendors/antivirus engines flagged the file.\
68 = 68 security engines analyzed the file in that VirusTotal analysis.

Therefore, 66 / 68 = 66 engines detected or flagged the file out of 68 engines that analyzed the file.\
VirusTotal detection ratio = number of engines flagging an artifact / number of engines analyzing the artifact.

### Analyst Validation

I analyze the detection names rather than relying only on 66/68.

Document:\
\
Analyst Validation:

. The SHA-256 reputation search produced detections from 66 of 68 security engines.

. Multiple security engines identified the artifact specifically as an EICAR test file or EICAR test signature.

. EICAR represents a standardized antivirus testing artifact rather than genuine malware.

. The high detection count therefore represents expected security-tool detection of the EICAR test signature.

. No evidence currently supports malware execution, persistence, command-and-control activity, or additional malicious behavior.

So, SOC skill demonstrated: IOC enrichment requires context + reputation data + analyst validation, not detection-count interpretation alone.\
\
Step 4 — URL Reputation Investigation
----------------------------------------------------------------------------------------------------------------------------------------------

Enrich a URL IOC and compare URL reputation with file-hash reputation.

In VirusTotal, I select URL and I search: https://secure.eicar.org/eicar.com

The VirusTotal URL investigation shows:\
\
URL: https://secure.eicar.org/eicar.com

Security Vendor Detection:9 / 90

Examples:

AutoShun: Malicious\
BitDefender: Malware\
Fortinet: Malware\
G-Data: Malware\
VIPRE: Malware\
Gridinsoft: Suspicious

HTTP Status: 200\
Community Score: 84\
\
Most remaining vendors show Clean or Unrated.

\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\
Analyst Validation:\
\
. The URL reputation search produced detections from 9 of 90 security vendors.

. Several vendors classified the URL as malicious, malware, or suspicious. Most vendors classified the URL as clean or provided no rating.

. The URL belongs to the EICAR antivirus-testing environment.

. EICAR content intentionally triggers security detections.

. The 9/90 detection ratio alone does not establish genuine malicious activity.

. File-hash enrichment and URL enrichment support identification of an antivirus test artifact rather than confirmed malware. (Images 6 through 10)\
\
\
\
\
\
\
\
----------------------------------------------------------------------------------------------------------------------------------------------------

\
\
\
\
\
Step 5 — IOC Correlation and Classification
-------------------------------------------

Correlate multiple IOC-enrichment results before assigning an alert classification.

I place the file-hash result and URL result together and evaluate whether both indicators support the same conclusion (Correlating the URL reputation and file-hash reputation with the known EICAR testing context before classification).

| IOC | VirusTotal result | Meaning |
|-----|-------------------|---------|

| SHA-256 hash | 66/68 | Strong recognition of the EICAR test file |
|--------------|-------|-------------------------------------------|

| URL | 9/90 | Several vendors flag the EICAR download URL |
|-----|------|---------------------------------------------|

| Context | EICAR test artifact | Antivirus testing, not genuine malware |
|---------|---------------------|----------------------------------------|

. File Hash:\
SHA-256: 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f

. Detection: 66 / 68

. Identification: EICAR test file

. URL: https://secure.eicar.org/eicar.com

. Detection: 9 / 90

. Context: EICAR antivirus-testing resource

Analyst Classification:\
\
. Classification: Benign / Security Test Activity

. Confidence: High

. Reasoning: File-hash enrichment identifies the artifact as the EICAR antivirus test file.

. URL enrichment identifies detections associated with the EICAR testing resource.

. High file-detection counts reflect intentional antivirus signature detection rather than confirmed malware behavior.

### . Available evidence contains no confirmed malware execution, persistence, command-and-control activity, or additional malicious behavior.\
\
SOC Decision

Escalation: Not required based on available evidence.

Disposition: Close as benign security-test activity.

Additional Action: Document IOC-enrichment results and preserve investigation

evidence.

\
Step 6 — MITRE ATT&CK Assessment
--------------------------------

Determine whether available evidence supports assignment of a MITRE ATT&CK technique.

### Evidence Review

Observed Evidence:

\- EICAR test file identified

\- SHA-256 enriched through VirusTotal

\- URL enriched through VirusTotal

\- No confirmed malicious execution

\- No persistence activity

\- No command-and-control activity

\- No adversary behavior identified

### \
\
MITRE ATT&CK Assessment

MITRE ATT&CK Mapping: Not applicable based on available evidence.

Reason:EICAR represents an antivirus test artifact rather than

confirmed adversary activity.

VirusTotal reputation results alone do not demonstrate an

ATT&CK technique.

T1204.001 — User Execution: Malicious Link Not supported.

T1204.002 — User Execution: Malicious File Not supported.

No confirmed malicious link interaction or malicious file

execution exists in available evidence.

MITRE defines T1204.002 — User Execution: Malicious File around adversary reliance on file execution/opening; detection guidance similarly correlates a downloaded/opened file with subsequent process activity. Such evidence does not exist in the current scenario. 

Analyst Decision: No MITRE ATT&CK technique assigned.

This step demonstrates an important SOC practice: ATT&CK mapping requires behavioral evidence; an IOC or VirusTotal detection count alone does not justify technique assignment.

## Step 7 — SOC Conclusion

Documenting a concise final investigation conclusion based on validated IOC-enrichment evidence.\
\
Final Investigation Summary and SOC Conclusion:

### . VirusTotal enrichment identified the SHA-256 hash as the EICAR antivirus test file, with 66 of 68 security engines reporting detections.

### . URL enrichment produced 9 detections from 90 security vendors.

### . Several vendors classified the URL as malicious, malware, or suspicious.

### . Analyst validation confirmed association between both IOCs and the EICAR antivirus-testing environment.

### . No evidence confirmed malware execution, persistence, command-and-control activity, or additional malicious behavior.

### 

### Classification:

### . Benign / Security Test Activity

### . Confidence: High

### . MITRE ATT&CK: No technique assigned based on available evidence.

### . Disposition: Close alert as benign security-test activity.

### . Escalation: Not required based on available evidence.

### SOC Skill Demonstrated

IOC enrichment → reputation interpretation → evidence correlation → analyst validation → classification → disposition
