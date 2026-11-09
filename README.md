# Azure-Cloud
Microsoft Sentinel and Defender SOC lab covering SIEM monitoring, KQL investigations, MITRE ATT&amp;CK, phishing analysis, identity security, and endpoint protection.

Microsoft Sentinel & Microsoft Defender – SOC Analyst Lab

1. Project Overview

This project demonstrates hands-on experience with Microsoft Sentinel, Microsoft Defender, Microsoft Entra ID, and Microsoft Intune in a simulated Security Operations Center (SOC) environment.

The lab focuses on security monitoring, incident investigation, threat detection, phishing protection, identity security, and endpoint protection.

I worked through different SOC analyst activities, including investigating failed logons, writing KQL queries, creating detection rules, mapping alerts to MITRE ATT&CK, reviewing phishing reports, and configuring endpoint security policies.

Project Type: SOC Analyst / Blue Team / Cybersecurity Lab

Tools Used:

Microsoft Sentinel
Microsoft Defender XDR
Microsoft Defender for Office 365
Microsoft Defender for Endpoint
Microsoft Entra ID
Microsoft Intune
Kusto Query Language (KQL)
MITRE ATT&CK Framework

2. Microsoft Sentinel – SIEM Monitoring and Investigation
MITRE ATT&CK Integration

Accessed the Microsoft Sentinel workspace and reviewed the MITRE ATT&CK framework integration.

This helped me understand how security detections can be mapped to attacker tactics and techniques.

Skills Demonstrated:

SIEM monitoring
MITRE ATT&CK framework
Threat detection concepts
Microsoft Defender Incident Management

Reviewed security incidents and alerts in Microsoft Defender.

Examined:

Incident names
Severity levels
Investigation status
Incident categories
Alert status

Skills Demonstrated: Alert monitoring, incident management, and SOC triage.

Sentinel Analytics

Explored Microsoft Sentinel Analytics to understand how detection rules are created and maintained.

Skills Demonstrated: Detection engineering and SIEM configuration.

3. KQL – Log Investigation and Analysis

Used the Microsoft Sentinel Logs interface to explore security data and practice Kusto Query Language (KQL).

Windows Event ID Analysis

Queried the SecurityEvent_CL table and summarized events by Event ID to understand the most common Windows security events.

Investigating Failed Logons

Focused on Windows Event ID 4625, which represents a failed logon attempt.

Example KQL query:

kql
SecurityEvent_CL
| where EventID_s == "4625"
| summarize Count = count() by Account_s
| sort by Count desc


This query groups failed authentication attempts by account.

A high number of failed logons can indicate suspicious authentication activity, including possible brute-force or password-spraying attempts.

Authentication Activity Visualization

Created a visualization based on authentication activity to identify accounts with unusually high numbers of failed logons.

Account-Based Investigation

Reviewed accounts associated with failed authentication attempts, including administrator and other test or service accounts.

Refining the Investigation

Applied additional filters and time-based conditions to narrow down the investigation and identify relevant authentication activity.

Skills Demonstrated:

KQL query writing
Windows Event Log analysis
Authentication investigation
Failed logon analysis
Security data visualization
Anomaly identification

4. Detection Engineering – Brute-Force Detection

Created a scheduled analytics rule in Microsoft Sentinel.

Rule Name: MyDFIR-Gatien-FailedLogonAlert

Description: Detect Brute Force Attacks

Severity: Medium

MITRE ATT&CK Technique: T1110 – Brute Force

Detection Query
kql
SecurityEvent_CL
| where EventID_s == "4625"
| summarize FailedLogons = count() by Account_s
| where FailedLogons >= 1000
| sort by FailedLogons desc


The detection rule was configured with:

Execution frequency: Every 5 minutes
Lookback period: Previous 24 hours
Detection condition: 1,000 or more failed logons per account
Severity: Medium

The purpose of this rule is to identify accounts with unusually high failed authentication activity.

This converts a manual investigation query into an automated SIEM detection.

Skills Demonstrated:

Detection engineering
Scheduled analytics rules
KQL detection logic
MITRE ATT&CK mapping
Automated threat monitoring

5. Microsoft Defender for Office 365 – Email Security
Threat Explorer and URL Investigation

Explored Microsoft Defender Threat Explorer to investigate email and URL-related activity.

Reviewed URL-click investigation capabilities and the role of Microsoft Safe Links.

Anti-Phishing Policy Configuration

Created an anti-phishing policy:

Policy Name: MyDFIR-Gatien-AntiPhishingPolicy

Configured protection settings involving:

Phishing thresholds
User impersonation protection
Domain impersonation protection
Trusted senders and domains
Safe Links Policy Configuration

Created a Safe Links policy:

Policy Name: MyDFIR-Gatien-SafeLinksPolicy

Reviewed and configured:

URL scanning
Real-time URL scanning
URL rewriting
Scanning links before delivery

Tested URL protection and observed the original URL being rewritten into a Microsoft Safe Links URL.

Preset Security Policies

Reviewed Microsoft's Standard and Strict preset security policies and examined the default Office 365 anti-phishing policy.

Skills Demonstrated:

Email security investigation
Phishing protection
Safe Links configuration
Threat Explorer
Security policy management
URL protection

6. Phishing Simulation and Investigation

Used Microsoft Attack Simulation Training to create a controlled phishing simulation.

Simulation Name: MyDFIR-Phishing-Test

Simulation Technique: Credential Harvesting

Reviewed the following simulation settings:

Simulation payload
Target users
User notifications
Launch schedule

Selected specific test users rather than automatically targeting everyone.

User-Reported Phishing

Reviewed user-reported phishing submissions in Microsoft Defender.

Investigated a reported test email and reviewed Microsoft's phishing classification.

The workflow demonstrated:

A user reports a suspicious email.
The security team reviews the submission.
The email is analyzed and classified.
The investigation result is communicated.

Skills Demonstrated:

Phishing simulation
Phishing email investigation
User-reported phishing triage
Security awareness testing
Security control validation

7. Microsoft Entra ID – Identity Security

Reviewed the Microsoft Entra ID environment and its identity-related security information.

Entra ID Audit Logs

Examined audit logs to understand administrative and identity-related activities, including:

Policy changes
Directory changes
Application and service principal changes
Identity administration activities
User and Identity Review

Reviewed users, groups, devices, applications, roles, and identity protection features.

Skills Demonstrated:

Identity monitoring
Audit log investigation
User account investigation
Identity and access security

8. Microsoft Defender for Endpoint – EDR Monitoring

Reviewed the Microsoft Defender alerts dashboard and investigated alerts involving suspicious endpoint activity.

Examples of alert categories included:

Suspicious PowerShell activity
Suspicious command-line activity
Registry persistence
Post-exploitation activity
Attack Surface Reduction

Accessed Microsoft Intune Endpoint Security and configured an Attack Surface Reduction policy.

Policy Name: MyDFIR-Gatien-Policy

Explored how Attack Surface Reduction policies help prevent common attacker techniques and reduce endpoint exposure.

Defender Device Inventory

Reviewed the Defender device inventory to understand:

Computer devices
Mobile devices
Network devices
IoT/OT devices
Device risk levels
Exposure levels
Critical assets
Defender for Endpoint Onboarding

Reviewed the Microsoft Defender for Endpoint onboarding configuration and the process of connecting devices to the security monitoring environment.

Skills Demonstrated:

EDR alert triage
Endpoint monitoring
Attack Surface Reduction
Endpoint hardening
Asset inventory
Defender onboarding

9. Key SOC Skills Demonstrated

Through this lab, I gained practical exposure to the following cybersecurity activities:

Skill	Technology
SIEM monitoring	Microsoft Sentinel
Incident triage	Microsoft Defender
Log investigation	Sentinel Logs
Query development	KQL
Windows event analysis	Event ID 4625
Detection engineering	Sentinel Analytics
Threat intelligence mapping	MITRE ATT&CK
Email security	Defender for Office 365
Phishing investigation	Threat Explorer
Phishing simulation	Attack Simulation Training
Identity monitoring	Microsoft Entra ID
Endpoint detection	Microsoft Defender for Endpoint
Endpoint hardening	Microsoft Intune

10. Project Conclusion

This lab provided hands-on experience with Microsoft security technologies and demonstrated several important responsibilities performed by SOC analysts.

I explored how security incidents are monitored, how authentication events are investigated, how KQL is used to identify suspicious activity, and how automated detection rules can be created in Microsoft Sentinel.

I also gained experience with phishing investigation, email protection policies, identity monitoring, and endpoint security.

The project strengthened my understanding of Blue Team operations, SIEM monitoring, detection engineering, and incident investigation.

11. Future Improvements

Potential improvements and additional exercises include:

Creating more advanced KQL detection queries.
Investigating additional Windows Security Event IDs.
Developing correlation rules for suspicious authentication patterns.
Building Sentinel workbooks and dashboards.
Investigating additional MITRE ATT&CK techniques.
Performing deeper incident investigations.
Improving endpoint detection and response monitoring.

Project Focus: SOC Analyst | Blue Team | SIEM | Threat Detection | Incident Investigation
