"""
Compliance Framework Mapping and Recommendation Engine
Maps security events to ISO 27001, PCI DSS, and MITRE ATT&CK controls.
Generates actionable recommendations based on ML predictions and compliance requirements.
"""
from __future__ import annotations

import csv
import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

# ============================================================================
# ISO 27001:2022 Controls Mapping
# ============================================================================

ISO27001_CONTROLS: dict[str, dict[str, str]] = {
    # A.5 - Organizational Controls
    "ISO_A5_1": {"name": "Policies for Information Security", "description": "Definition and approval of information security policies"},
    "ISO_A5_2": {"name": "Information Security Roles", "description": "Roles and responsibilities for information security"},
    "ISO_A5_3": {"name": "Segregation of Duties", "description": "Segregating conflicting duties and responsibilities"},
    "ISO_A5_7": {"name": "Threat Intelligence", "description": "Collection and analysis of threat intelligence"},
    "ISO_A5_23": {"name": "Information Security for Cloud Services", "description": "Security controls for cloud service usage"},
    "ISO_A5_24": {"name": "Information Security Incident Management Planning", "description": "Planning and preparation for incident response"},
    "ISO_A5_26": {"name": "Response to Information Security Incidents", "description": "Effective and timely response to security incidents"},
    # A.6 - People Controls
    "ISO_A6_1": {"name": "Screening", "description": "Background verification checks on candidates"},
    "ISO_A6_2": {"name": "Terms and Conditions of Employment", "description": "Employee responsibilities for information security"},
    "ISO_A6_3": {"name": "Information Security Awareness Training", "description": "Regular awareness and training programs"},
    "ISO_A6_6": {"name": "Confidentiality/NDA", "description": "Confidentiality agreements reflecting organizational needs"},
    "ISO_A6_8": {"name": "Reporting of Information Security Events", "description": "Mechanisms for staff to report security events"},
    # A.7 - Physical Controls
    "ISO_A7_2": {"name": "Physical Entry Controls", "description": "Secure areas accessible only to authorized personnel"},
    "ISO_A7_8": {"name": "Equipment Maintenance", "description": "Regular and timely maintenance of equipment"},
    "ISO_A7_12": {"name": "Off-site Protection", "description": "Protection of off-site assets and remote working"},
    # A.8 - Technological Controls
    "ISO_A8_1": {"name": "User Endpoint Devices", "description": "Protection of user endpoint devices"},
    "ISO_A8_2": {"name": "Privileged Access Rights", "description": "Management and restriction of privileged access"},
    "ISO_A8_3": {"name": "Information Access Restriction", "description": "Restriction of access to information and assets"},
    "ISO_A8_4": {"name": "Access to Source Code/Tools", "description": "Restriction of access to source code and development tools"},
    "ISO_A8_5": {"name": "Secure Authentication", "description": "Authentication mechanisms and password management"},
    "ISO_A8_6": {"name": "Capacity Management", "description": "Capacity management of computing resources"},
    "ISO_A8_7": {"name": "Protection Against Malware", "description": "Detection, prevention, and recovery from malware"},
    "ISO_A8_8": {"name": "Management of Technical Vulnerabilities", "description": "Management and remediation of vulnerabilities"},
    "ISO_A8_9": {"name": "Configuration Management", "description": "Secure configuration of IT infrastructure"},
    "ISO_A8_10": {"name": "Information Deletion", "description": "Secure deletion and destruction of information"},
    "ISO_A8_11": {"name": "Data Masking", "description": "Masking of sensitive data"},
    "ISO_A8_12": {"name": "Data Leakage Prevention", "description": "DLP controls to prevent unauthorized disclosure"},
    "ISO_A8_15": {"name": "Logging", "description": "Production and storage of event logs"},
    "ISO_A8_16": {"name": "Monitoring Activities", "description": "Monitoring for anomalous activity and policy violations"},
    "ISO_A8_20": {"name": "Networks Security", "description": "Security of network infrastructure and services"},
    "ISO_A8_21": {"name": "Security of Services with External Providers", "description": "Security controls for externally provided services"},
    "ISO_A8_22": {"name": "Monitoring External Provider Services", "description": "Monitoring and reviewing external provider services"},
    "ISO_A8_23": {"name": "Web Filtering", "description": "Access controls for internet and external networks"},
    "ISO_A8_24": {"name": "Cryptographic Controls", "description": "Use of cryptography to protect information"},
    "ISO_A8_25": {"name": "Secure Development Lifecycle", "description": "Secure development lifecycle practices"},
    "ISO_A8_26": {"name": "Application Security Requirements", "description": "Security requirements for applications"},
    "ISO_A8_28": {"name": "Secure Coding", "description": "Secure coding principles and practices"},
    "ISO_A8_33": {"name": "Separation of Environments", "description": "Separation of development, test, and production"},
    "ISO_A8_34": {"name": "Protection of Information Systems During Audit", "description": "Audit activities without compromising systems"},
}

# ============================================================================
# PCI DSS v4.0 Controls Mapping
# ============================================================================

PCI_DSS_CONTROLS: dict[str, dict[str, str]] = {
    # Requirement 1: Network Security Controls
    "PCI_1_1": {"name": "Network Security Controls Implementation", "description": "Implement network security controls (firewalls, routers)"},
    "PCI_1_2": {"name": "Network Connection Controls", "description": "Secure inbound/outbound network traffic with appropriate controls"},
    "PCI_1_3": {"name": "Network Access for Remote Computing", "description": "Secure access for remote users in trusted paths"},
    # Requirement 2: Secure Configurations
    "PCI_2_1": {"name": "Default Passwords/Parameters", "description": "Ensure no vendor defaults or easily-guessable passwords"},
    "PCI_2_2": {"name": "System Security Configuration", "description": "Implement and maintain secure system configurations"},
    # Requirement 3: Stored Account Data
    "PCI_3_1": {"name": "Data Storage Limits", "description": "Keep cardholder data storage to a minimum"},
    "PCI_3_2": {"name": "Sensitive Data Identification & Management", "description": "Discover and classify stored cardholder data"},
    "PCI_3_3": {"name": "PAN Masking/Truncation", "description": "Protect stored PAN with masking/truncation"},
    "PCI_3_4": {"name": "SAK Cryptographic Key Protection", "description": "Encrypt stored account data with strong cryptography"},
    # Requirement 4: Strong Cryptography
    "PCI_4_1": {"name": "Strong Cryptography for Transmission", "description": "Protect cardholder data in transit with strong cryptography"},
    "PCI_4_2": {"name": "PAN Unprotected in End-of-Channel", "description": "Secure messaging endpoints to prevent PAN exposure"},
    # Requirement 5: Malware Protection
    "PCI_5_1": {"name": "Malware Detection/Prevention", "description": "Deploy anti-malware mechanisms on all systems"},
    "PCI_5_2": {"name": "Anti-Malware Protection", "description": "Keep anti-malware software current and detect/remove/eject malicious code"},
    "PCI_5_3": {"name": "Anti-Malware Mechanism Process", "description": "Ensure anti-malware mechanisms are actively running"},
    "PCI_5_4": {"name": "Anti-Malware Training", "description": "Train personnel on anti-malware awareness"},
    # Requirement 6: Secure Software Development
    "PCI_6_1": {"name": "Vulnerability Identification & Management", "description": "Identify and manage vulnerabilities via patching"},
    "PCI_6_2": {"name": "System Integrity/SBOM", "description": "Establish/process of maintaining Software Bill of Materials"},
    "PCI_6_3": {"name": "Security Vulnerability Management", "description": "Identify and prioritize security vulnerabilities"},
    "PCI_6_4": {"name": "Software/Application Vulnerability Management", "description": "Prioritize and remediate software vulnerabilities"},
    "PCI_6_5": {"name": "Tampered Software Detection", "description": "Detect tampered software and unauthorized changes"},
    # Requirement 7: Access Control
    "PCI_7_1": {"name": "Need-to-Know Principle", "description": "Limit access to system components and CHD to need-to-know"},
    "PCI_7_2": {"name": "Access Rights Assignment Process", "description": "Establish access rights assignment and removal process"},
    # Requirement 8: Identification & Authentication
    "PCI_8_1": {"name": "Unique User Identification", "description": "Define and implement unique user identification"},
    "PCI_8_2": {"name": "Authentication Policies", "description": "Implement strong authentication policies and controls"},
    "PCI_8_3": {"name": "Secure Authentication", "description": "Secure all non-console administrative access with MFA"},
    # Requirement 9: Physical Access
    "PCI_9_1": {"name": "Physical Access Controls", "description": "Use facility entry controls for cardholder data areas"},
    "PCI_9_2": {"name": "Physical Access Authorization", "description": "Verify authorization before granting physical access"},
    "PCI_9_3": {"name": "Physical Access for Personnel", "description": "Visitor management and escort procedures"},
    "PCI_9_4": {"name": "Physical Device Access", "description": "Protect and secure sensitive information systems"},
    "PCI_9_5": {"name": "Physical Device Access for Personnel", "description": "Physical access for personnel and media distribution"},
    "PCI_9_6": {"name": "Physical Access Logging/Monitoring", "description": "Maintain and log entry/exit records"},
    # Requirement 10: Logging & Monitoring
    "PCI_10_1": {"name": "Audit Trail Implementation", "description": "Implement audit trails and logging mechanisms"},
    "PCI_10_2": {"name": "Automated Audit Trails", "description": "Implement automated audit trails for all system components"},
    "PCI_10_3": {"name": "Audit Trail Entries", "description": "Record all critical security audit trail entries"},
    "PCI_10_4": {"name": "Audit Trail Logging Details", "description": "Log details required: user, event type, date, time, success/fail, origin"},
    "PCI_10_5": {"name": "Audit Trail Retention", "description": "Retain audit trail history for at least 12 months"},
    "PCI_10_6": {"name": "Review/Audit Trails & Logs", "description": "Review logs and security event logs for anomalies"},
    "PCI_10_7": {"name": "Audit Failure Alerting", "description": "Alert on failed audit trails and unauthorized access"},
    # Requirement 11: Security Testing
    "PCI_11_1": {"name": "Internal/External Vulnerability Testing", "description": "Internal/external testing of networks and systems"},
    "PCI_11_2": {"name": "Wireless Access Point Scanning", "description": "Scan for unauthorized wireless access points"},
    "PCI_11_3": {"name": "Penetration Testing", "description": "Conduct external/internal penetration testing annually"},
    "PCI_11_4": {"name": "Intrusion Detection/Prevention", "description": "Deploy IDS/IPS to detect/restrict inbound network traffic"},
    "PCI_11_5": {"name": "Change Detection/Tamper Alerts", "description": "Deploy change detection and tamper-alert mechanisms"},
    "PCI_11_6": {"name": "Public-Facing Web Applications", "description": "Protect public-facing web apps from attacks via WAF"},
    # Requirement 12: Security Policy
    "PCI_12_1": {"name": "Information Security Policy", "description": "Establish, publish, and maintain security policy"},
    "PCI_12_2": {"name": "Vendor Management Program", "description": "Implement vendor management and shared accountability"},
    "PCI_12_3": {"name": "Acceptable Use Policy", "description": "Develop acceptable use policies for computing assets"},
    "PCI_12_4": {"name": "Security Responsibilities", "description": "Define and publish security responsibilities for stakeholders"},
    "PCI_12_5": {"name": "Key Security Management", "description": "Assign management responsibility for key security functions"},
    "PCI_12_6": {"name": "Security Awareness Training", "description": "Train and educate personnel on security awareness"},
    "PCI_12_7": {"name": "Personnel Screening", "description": "Screen potential personnel before hiring"},
    "PCI_12_8": {"name": "Detection and Response", "description": "Maintain incident response plan and readiness for detection and response"},
}

# ============================================================================
# MITRE ATT&CK - Recommended Mitigations
# ============================================================================

MITRE_MITIGATIONS: dict[str, dict[str, str]] = {
    "M1013": {"name": "Application Developer Guidance", "description": "Provide secure coding guidance to developers"},
    "M1015": {"name": "Active Directory Configuration", "description": "Configure AD security settings to harden the environment"},
    "M1016": {"name": "Patch Application Software", "description": "Regularly apply patches to application software"},
    "M1017": {"name": "User Training", "description": "Train users to be aware of attacks and how to respond"},
    "M1018": {"name": "Password Policy", "description": "Implement and enforce strong password policies"},
    "M1019": {"name": "Threat Intelligence Program", "description": "Establish threat intelligence to understand adversary behavior"},
    "M1020": {"name": "Software Configuration", "description": "Harden software configurations following security guidelines"},
    "M1021": {"name": "Restrict Registry Permissions", "description": "Restrict registry access to privileged users"},
    "M1022": {"name": "Restrict File and Directory Permissions", "description": "Restrict file and directory access to authorized users"},
    "M1024": {"name": "Restrict Registry Permissions", "description": "Restrict registry access to prevent malicious changes"},
    "M1025": {"name": "Privileged Account Management", "description": "Manage and monitor privileged account access"},
    "M1026": {"name": "Multi-Factor Authentication", "description": "Require multi-factor authentication for access"},
    "M1027": {"name": "Exploit Protection", "description": "Enable exploit protection features on endpoints"},
    "M1028": {"name": "Operating System Configuration", "description": "Harden and maintain OS security settings"},
    "M1029": {"name": "Remote Data Backup", "description": "Maintain secure off-site data backups"},
    "M1030": {"name": "Network Intrusion Prevention", "description": "Deploy and maintain network intrusion prevention"},
    "M1031": {"name": "Account Use Policies", "description": "Implement policies governing acceptable account use"},
    "M1032": {"name": "Multi-Factor Authentication", "description": "Implement MFA for all remote and privileged access"},
    "M1033": {"name": "Restrict Web-Based Content", "description": "Filter and restrict access to malicious web content"},
    "M1034": {"name": "External Remote Services", "description": "Implement strong protective configurations for remote services"},
    "M1035": {"name": "Application Control", "description": "Prevent execution of unauthorized applications"},
    "M1036": {"name": "Application Isolation and Sandboxing", "description": "Isolate and sandbox applications to prevent spread"},
    "M1037": {"name": "Filter Network Traffic", "description": "Filter and monitor inbound and outbound network traffic"},
    "M1038": {"name": "Update Software", "description": "Keep all software up-to-date with latest patches"},
    "M1039": {"name": "Network Segmentation", "description": "Segment networks to limit lateral movement"},
    "M1040": {"name": "Behavior Prevalence on Network", "description": "Monitor and baseline normal network behavior"},
    "M1041": {"name": "Encrypt Sensitive Information", "description": "Use encryption to protect sensitive data"},
    "M1042": {"name": "Disable or Remove Unneeded Tools", "description": "Remove or disable unnecessary utilities and tools"},
    "M1043": {"name": "Credential Access Protection", "description": "Implement protections against credential theft"},
    "M1045": {"name": "Software Configuration", "description": "Enforce and secure software configurations"},
    "M1046": {"name": "Boot Integrity", "description": "Ensure boot process integrity with secure boot"},
    "M1047": {"name": "Audit", "description": "Implement comprehensive audit logging and monitoring"},
    "M1048": {"name": "Antivirus/Antimalware", "description": "Deploy and maintain anti-malware capabilities"},
    "M1049": {"name": "Authentication Credential Hardening", "description": "Strengthen authentication credential protection"},
    "M1050": {"name": "Endpoint Detection and Response", "description": "Deploy EDR for advanced endpoint threat detection"},
    "M1051": {"name": "User Account Management", "description": "Centrally manage and monitor user accounts"},
    "M1052": {"name": "Disable or Remove Feature/Program", "description": "Disable unnecessary features and remove unused programs"},
    "M1053": {"name": "Application Layer Protocol Control", "description": "Monitor and filter application layer protocols"},
    "M1054": {"name": "Software Configuration", "description": "Maintain secure software configurations"},
    "M1055": {"name": "Code Signing", "description": "Use code signing to verify software authenticity"},
    "M1056": {"name": "Restrict File and Directory Permissions", "description": "Restrict permissions to limit unauthorized access"},
}

# ============================================================================
# Compliance Recommendation Mapping
# Maps threat indicators to relevant compliance controls and mitigations
# ============================================================================

COMPLIANCE_MAPPING: dict[str, dict[str, Any]] = {
    "malware_infection": {
        "severity": "critical",
        "iso_controls": ["ISO_A8_7", "ISO_A8_16", "ISO_A5_26"],
        "pci_controls": ["PCI_5_1", "PCI_5_2", "PCI_5_3", "PCI_10_2"],
        "mitre_mitigations": ["M1048", "M1050", "M1027", "M1035"],
        "immediate_actions": [
            "Isolate the affected endpoint from the network immediately",
            "Preserve memory dump and disk image for forensics analysis",
            "Run full anti-malware scan on all connected systems",
            "Block identified malicious IOCs in perimeter firewall",
            "Notify incident response team and begin containment playbook"
        ],
        "investigation_steps": [
            "Analyze malware behavior, C2 communication, and persistence mechanisms",
            "Correlate Wazuh alerts with MISP threat intelligence indicators",
            "Review Cortex sandbox analysis results for behavioral indicators",
            "Check for lateral movement patterns across network segments",
            "Identify initial access vector and timeline of compromise"
        ],
        "remediation_steps": [
            "Remove malware and verify clean state through repeated scanning",
            "Patch exploited vulnerabilities and update signatures",
            "Rebuild compromised systems from known-good images",
            "Update IDS/IPS rules to detect similar attacks",
            "Conduct lessons learned and update incident response procedures"
        ],
        "compliance_notes": [
            "ISO 27001 A.8.7: Malware detection and prevention controls must be maintained",
            "PCI DSS 5.1: Anti-malware mechanisms required on all CDE systems",
            "PCI DSS 10.2: Automated audit trails must capture all malware events"
        ]
    },
    "credential_theft": {
        "severity": "critical",
        "iso_controls": ["ISO_A8_5", "ISO_A8_2", "ISO_A8_43", "ISO_A5_26"],
        "pci_controls": ["PCI_8_1", "PCI_8_2", "PCI_8_3", "PCI_7_1"],
        "mitre_mitigations": ["M1026", "M1018", "M1043", "M1049", "M1025"],
        "immediate_actions": [
            "Disable compromised accounts and force password reset for all related accounts",
            "Revoke all active session tokens and API keys",
            "Enable enhanced authentication logging",
            "Block source IPs associated with credential theft activity",
            "Activate incident response bridge for credential compromise"
        ],
        "investigation_steps": [
            "Identify which accounts and credential types were compromised",
            "Trace the credential theft vector (phishing, keylogging, pass-the-hash, etc.)",
            "Review authentication logs for anomalous patterns",
            "Check for unauthorized privilege escalation using stolen credentials",
            "Assess if service accounts or application credentials were exposed"
        ],
        "remediation_steps": [
            "Reset all impacted credentials with strong, unique passwords",
            "Implement or strengthen multi-factor authentication",
            "Deploy Credential Guard or similar protection mechanisms",
            "Update access control policies and enforce least privilege",
            "Conduct security awareness training focused on credential protection"
        ],
        "compliance_notes": [
            "ISO 27001 A.8.5: Secure authentication mechanisms must be implemented",
            "PCI DSS 8.3: MFA required for all non-console administrative access",
            "PCI DSS 7.1: Access to cardholder data must follow need-to-know principle"
        ]
    },
    "lateral_movement": {
        "severity": "high",
        "iso_controls": ["ISO_A8_20", "ISO_A8_3", "ISO_A8_16", "ISO_A5_26"],
        "pci_controls": ["PCI_1_1", "PCI_1_2", "PCI_11_4", "PCI_11_5"],
        "mitre_mitigations": ["M1039", "M1025", "M1050", "M1037", "M1047"],
        "immediate_actions": [
            "Segment affected network zones to contain lateral movement",
            "Block identified lateral movement protocols (RDP, SMB, WMI) at segment boundaries",
            "Deploy enhanced monitoring on critical network paths",
            "Isolate compromised hosts from the network",
            "Activate network forensic capture for affected segments"
        ],
        "investigation_steps": [
            "Map the lateral movement path using host and network telemetry",
            "Identify which techniques were used (RDP, SMB, pass-the-hash, PsExec, etc.)",
            "Determine if the attacker escalated privileges during lateral movement",
            "Check for persistence mechanisms established on pivoted systems",
            "Assess data accessed or exfiltrated during lateral movement"
        ],
        "remediation_steps": [
            "Implement network micro-sementation between trust zones",
            "Restrict administrative protocols to designated management networks",
            "Deploy network-based intrusion prevention for lateral movement detection",
            "Implement just-in-time and just-enough-access administrative models",
            "Review and harden all remote administration configurations"
        ],
        "compliance_notes": [
            "ISO 27001 A.8.20: Network security controls must restrict unauthorized access",
            "PCI DSS 1.1: Network security controls required for all CDE connections",
            "PCI DSS 11.4: IDS/IPS must detect and prevent network-based attacks"
        ]
    },
    "data_exfiltration": {
        "severity": "critical",
        "iso_controls": ["ISO_A8_12", "ISO_A8_24", "ISO_A8_16", "ISO_A5_26"],
        "pci_controls": ["PCI_3_4", "PCI_4_1", "PCI_4_2", "PCI_10_6"],
        "mitre_mitigations": ["M1041", "M1030", "M1037", "M1050", "M1029"],
        "immediate_actions": [
            "Block identified exfiltration channels and destination addresses",
            "Implement emergency DLP rules for sensitive data types",
            "Capture and preserve network traffic for forensic analysis",
            "Identify and isolate systems involved in data staging",
            "Engage legal team for potential data breach notification obligations"
        ],
        "investigation_steps": [
            "Determine what data was exfiltrated, volume, and sensitivity classification",
            "Identify the exfiltration method (DNS tunneling, HTTP, cloud storage, etc.)",
            "Trace back through the attack chain to initial access point",
            "Assess if encryption was used to hide exfiltration",
            "Review DLP logs and alerting history for missed indicators"
        ],
        "remediation_steps": [
            "Deploy or enhance DLP controls at network egress points",
            "Implement encrypted traffic inspection where legally permissible",
            "Restrict outbound connections to approved destinations",
            "Implement DNS monitoring and restrict DNS tunneling vectors",
            "Update incident response playbooks with data-specific procedures"
        ],
        "compliance_notes": [
            "ISO 27001 A.8.12: Data leakage prevention controls must be implemented",
            "PCI DSS 3.4: Cardholder data must be encrypted at rest",
            "PCI DSS 4.1: Cardholder data in transit must be encrypted",
            "Data breach notification may be required per jurisdiction regulations"
        ]
    },
    "web_application_attack": {
        "severity": "high",
        "iso_controls": ["ISO_A8_26", "ISO_A8_28", "ISO_A8_33", "ISO_A8_23"],
        "pci_controls": ["PCI_6_1", "PCI_6_2", "PCI_6_4", "PCI_6_5", "PCI_11.6"],
        "mitre_mitigations": ["M1013", "M1033", "M1035", "M1055", "M1020"],
        "immediate_actions": [
            "Enable WAF blocking mode with updated rule sets",
            "Identify and patch the exploited web application vulnerability",
            "Implement input validation for all user-supplied parameters",
            "Block source IPs or ranges involved in the attack",
            "Review recent web application changes for introduced vulnerabilities"
        ],
        "investigation_steps": [
            "Analyze web server and WAF logs for attack patterns",
            "Identify the specific attack vector (SQLi, XSS, RCE, etc.)",
            "Check for successful exploitation and data accessed",
            "Review web application code for similar vulnerability patterns",
            "Assess if the attack was automated or targeted"
        ],
        "remediation_steps": [
            "Apply security patches to the vulnerable web application",
            "Implement secure development lifecycle practices",
            "Deploy or update WAF with custom rules for the attack pattern",
            "Conduct code review and static analysis of the application",
            "Implement runtime application self-protection (RASP) if applicable"
        ],
        "compliance_notes": [
            "ISO 27001 A.8.28: Secure coding practices must be followed",
            "PCI DSS 6.1: Security vulnerabilities must be identified and managed",
            "PCI DSS 6.5: Publicly accessible web applications must be protected against known attacks",
            "PCI DSS 11.6: Changes to external-facing systems must be evaluated for attack surfaces"
        ]
    },
    "phishing_attempt": {
        "severity": "medium",
        "iso_controls": ["ISO_A6_3", "ISO_A5_23", "ISO_A8_23", "ISO_A8_21"],
        "pci_controls": ["PCI_5_4", "PCI_12_6", "PCI_6_3"],
        "mitre_mitigations": ["M1017", "M1033", "M1020", "M1036"],
        "immediate_actions": [
            "Quarantine the phishing email across all mailboxes",
            "Block sender address, domain, and any malicious URLs/attachments",
            "Send user awareness alert about the phishing attempt",
            "Check for any users who clicked links or provided credentials",
            "Scan any downloaded attachments in isolated sandbox environment"
        ],
        "investigation_steps": [
            "Analyze email headers for spoofing and routing information",
            "Identify all recipients and determine who interacted with the email",
            "Examine any credential harvesting sites mimicked by the phish",
            "Check for malware delivery via phishing attachments or links",
            "Assess the targeting sophistication and potential APT indicators"
        ],
        "remediation_steps": [
            "Update email security gateway rules and signatures",
            "Implement DMARC, DKIM, and SPF to prevent domain spoofing",
            "Conduct targeted security awareness training for affected users",
            "Deploy email attachment sandboxing capabilities",
            "Enable URL rewriting and reputation checking in email gateway"
        ],
        "compliance_notes": [
            "ISO 27001 A.6.3: Information security awareness training is required",
            "PCI DSS 5.4: Personnel must be trained on anti-malware awareness",
            "PCI DSS 12.6: Security awareness program must address phishing"
        ]
    },
    "vulnerability_exploitation": {
        "severity": "critical",
        "iso_controls": ["ISO_A8_8", "ISO_A8_9", "ISO_A8_16", "ISO_A5_7"],
        "pci_controls": ["PCI_6_1", "PCI_6_3", "PCI_11_1", "PCI_11_2", "PCI_11_3"],
        "mitre_mitigations": ["M1016", "M1038", "M1027", "M1041", "M1050"],
        "immediate_actions": [
            "Apply emergency patch or mitigation for the exploited CVE",
            "Isolate affected systems if patching is not immediately available",
            "Block exploit delivery vectors at network perimeter",
            "Check for other systems vulnerable to the same CVE",
            "Activate vulnerability response playbook"
        ],
        "investigation_steps": [
            "Identify the specific CVE and affected software versions",
            "Determine the exploit kit or attacker tooling used",
            "Assess if the exploitation was successful or attempted",
            "Check for indicators of post-exploitation activity",
            "Cross-reference with threat intelligence for active exploitation in the wild"
        ],
        "remediation_steps": [
            "Patch all affected systems with the latest security update",
            "Implement virtual patching via WAF/IPS until patches can be applied",
            "Review vulnerability management program and patching SLAs",
            "Deploy continuous vulnerability scanning and prioritization",
            "Update threat detection rules for exploit attempt patterns"
        ],
        "compliance_notes": [
            "ISO 27001 A.8.8: Technical vulnerabilities must be managed and remediated",
            "PCI DSS 6.1: Critical and high-risk vulnerabilities must be resolved within 30 days",
            "PCI DSS 11.3: Penetration testing must be conducted annually and after significant changes"
        ]
    },
    "privilege_escalation": {
        "severity": "high",
        "iso_controls": ["ISO_A8_2", "ISO_A8_3", "ISO_A8_4", "ISO_A5_26"],
        "pci_controls": ["PCI_7_1", "PCI_7_2", "PCI_8_1", "PCI_8_2"],
        "mitre_mitigations": ["M1025", "M1026", "M1018", "M1051", "M1043"],
        "immediate_actions": [
            "Disable compromised privileged accounts immediately",
            "Revoke elevated permissions granted through exploitation",
            "Enable enhanced privileged access monitoring",
            "Review recent changes to group policies and permissions",
            "Activate incident response for privilege abuse"
        ],
        "investigation_steps": [
            "Identify the escalation technique used (exploit, misconfiguration, stolen creds)",
            "Determine which privileged accounts and systems were affected",
            "Review all administrative actions taken during compromise window",
            "Check for persistence established through scheduled tasks or services",
            "Assess what data or systems the escalated privilege enabled access to"
        ],
        "remediation_steps": [
            "Remediate the root cause of the privilege escalation",
            "Implement least privilege access model across all systems",
            "Deploy privileged access management (PAM) solution",
            "Enable just-in-time privilege elevation with approval workflows",
            "Conduct regular privileged access audits and certification"
        ],
        "compliance_notes": [
            "ISO 27001 A.8.2: Privileged access rights must be managed and restricted",
            "PCI DSS 7.1: Access to system components must be limited to need-to-know",
            "PCI DSS 8.1: All users must be uniquely identified before accessing system components"
        ]
    },
    "brute_force_attack": {
        "severity": "medium",
        "iso_controls": ["ISO_A8_5", "ISO_A8_16", "ISO_A8_15", "ISO_A5_26"],
        "pci_controls": ["PCI_8_1", "PCI_8_2", "PCI_8_3", "PCI_10_2"],
        "mitre_mitigations": ["M1018", "M1026", "M1025", "M1043", "M1051"],
        "immediate_actions": [
            "Implement temporary IP-based lockout for the targeted accounts",
            "Block source IPs generating brute force attempts",
            "Enable account lockout policies if not already configured",
            "Force password reset for accounts that received excessive attempts",
            "Deploy rate limiting on authentication endpoints"
        ],
        "investigation_steps": [
            "Analyze authentication logs to determine attack scope and duration",
            "Identify if the brute force was successful for any accounts",
            "Determine if credential stuffing, dictionary attack, or brute force was used",
            "Check if the attack originated from a single source or distributed botnet",
            "Review if targeted accounts had weak or reused passwords"
        ],
        "remediation_steps": [
            "Enforce strong password complexity and expiration policies",
            "Implement multi-factor authentication for all remote access",
            "Deploy CAPTCHA or bot detection on public-facing login pages",
            "Implement progressive delays after failed login attempts",
            "Configure account lockout thresholds and notification alerts"
        ],
        "compliance_notes": [
            "ISO 27001 A.8.5: Secure authentication mechanisms are required",
            "PCI DSS 8.2: Authentication policies must include password complexity requirements",
            "PCI DSS 8.3: Multi-factor authentication required for remote access to the CDE"
        ]
    },
    "unauthorized_access": {
        "severity": "high",
        "iso_controls": ["ISO_A8_3", "ISO_A8_1", "ISO_A8_2", "ISO_A5_26"],
        "pci_controls": ["PCI_7_1", "PCI_7_2", "PCI_8_1", "PCI_9_1"],
        "mitre_mitigations": ["M1025", "M1051", "M1022", "M1015", "M1039"],
        "immediate_actions": [
            "Revoke unauthorized access and disable compromised accounts",
            "Isolate affected systems for forensic investigation",
            "Enhance access monitoring and logging on critical systems",
            "Review and restrict unnecessary network access paths",
            "Activate unauthorized access incident response playbook"
        ],
        "investigation_steps": [
            "Determine how unauthorized access was obtained",
            "Identify what systems, data, and accounts were accessed",
            "Assess if data was viewed, modified, copied, or exfiltrated",
            "Review access logs for the full time window of compromise",
            "Check if additional accounts or persistence mechanisms exist"
        ],
        "remediation_steps": [
            "Strengthen access controls and authentication requirements",
            "Implement network segmentation to limit unauthorized access paths",
            "Deploy user and entity behavior analytics (UEBA) for anomaly detection",
            "Review and update access control policies and procedures",
            "Conduct access rights certification across all systems"
        ],
        "compliance_notes": [
            "ISO 27001 A.8.3: Access to information and assets must be restricted",
            "PCI DSS 9.1: Physical access controls must protect cardholder data areas",
            "Unauthorized access may trigger data breach notification requirements"
        ]
    }
}

def classify_threat_category(scoring_request: Any, feature_map: dict[str, float]) -> str:
    """Classify the threat into a category based on features, Wazuh alerts, and text analysis."""
    # Build combined text from all available sources
    title = getattr(scoring_request, 'title', '') or ''
    asset_name = getattr(scoring_request, 'asset_name', '') or ''
    workflow_id = getattr(scoring_request, 'workflow_id', '') or ''
    notes = getattr(scoring_request, 'notes', '') or ''
    misp_info = getattr(scoring_request.misp_enrichment, 'event_info', '') if getattr(scoring_request, 'misp_enrichment', None) else ''
    
    combined_text = " ".join(filter(None, [title, asset_name, workflow_id, notes, misp_info])).lower()
    
    # Extract Wazuh groups for additional context
    wazuh_alert = getattr(scoring_request, 'wazuh_alert', None)
    wazuh_groups = []
    wazuh_description = ''
    if wazuh_alert:
        wazuh_groups = [g.lower() for g in getattr(wazuh_alert, 'groups', []) or []]
        wazuh_description = getattr(wazuh_alert, 'rule_description', '').lower()
        combined_text += " " + wazuh_description + " " + " ".join(wazuh_groups)
    combined_text = combined_text.lower()
    
    # === Wazuh group-based classification ===
    if "malware" in wazuh_groups or "malware" in wazuh_description:
        return "malware_infection"
    if "brute_force" in wazuh_groups or "authentication_failed" in wazuh_groups:
        if feature_map.get("authentication_failures", 0) >= 1:
            return "brute_force_attack"
    if "privilege_escalation" in wazuh_groups or "sudo" in wazuh_description:
        return "privilege_escalation"
    if "web" in wazuh_groups and ("sqli" in wazuh_description or "xss" in wazuh_description or "injection" in wazuh_description):
        return "web_application_attack"
    if "phishing" in wazuh_groups or "phishing" in wazuh_description:
        return "phishing_attempt"
    if "lateral" in wazuh_description or "pivot" in combined_text:
        return "lateral_movement"
    if "vulnerability" in wazuh_description or "cve" in wazuh_description or "exploit" in wazuh_description:
        return "vulnerability_exploitation"
    
    # === Text-based classification ===
    # Check for malware indicators
    if any(token in combined_text for token in ['malware', 'virus', 'trojan', 'ransom', 'worm', 'rootkit']):
        return "malware_infection"
    
    # Check for credential theft
    if any(token in combined_text for token in ['credential', 'password', 'authentication', 'login', 'brute force', 'account takeover']):
        if any(token in combined_text for token in ['theft', 'stolen', 'compromise', 'breach']):
            return "credential_theft"
    
    # Check for lateral movement
    if any(token in combined_text for token in ['lateral', 'pivot', 'movement', 'rdp', 'smb', 'wmi', 'psexec']):
        return "lateral_movement"
    
    # Check for data exfiltration
    if any(token in combined_text for token in ['exfil', 'leak', 'dump', 'transfer', 'upload', 'data theft']):
        return "data_exfiltration"
    
    # Check for web application attacks
    if any(token in combined_text for token in ['sql injection', 'xss', 'sqli', 'rce', 'web attack', 'sqlmap', 'directory traversal']):
        return "web_application_attack"
    
    # Check for phishing
    if any(token in combined_text for token in ['phish', 'spear phish', 'email attach', 'suspicious email', 'spoof']):
        return "phishing_attempt"
    
    # Check for privilege escalation
    if any(token in combined_text for token in ['privilege', 'escalation', 'admin', 'root', 'sudo', 'uac bypass']):
        return "privilege_escalation"
    
    # Check for brute force
    if any(token in combined_text for token in ['brute force', 'password spray', 'dictionary attack', 'credential stuffing']):
        return "brute_force_attack"
    
    # Check for vulnerability exploitation
    if any(token in combined_text for token in ['exploit', 'vuln', 'cve-', 'zero-day', 'unpatched']):
        return "vulnerability_exploitation"
    
    # Check for unauthorized access
    if any(token in combined_text for token in ['unauthorized', 'access denied', 'intrusion', 'break-in', 'unauthorized access']):
        return "unauthorized_access"
    
    # Default based on feature analysis
    if feature_map.get("cortex_malicious", 0) >= 1:
        return "vulnerability_exploitation"
    if feature_map.get("authentication_failures", 0) >= 1:
        return "brute_force_attack"
    if feature_map.get("lateral_movement_signal", 0) >= 1:
        return "lateral_movement"
    if feature_map.get("exfiltration_signal", 0) >= 1:
        return "data_exfiltration"
    
    return "unauthorized_access"


def generate_compliance_recommendation(scoring_request: Any, feature_map: dict[str, float], score: int, decision: str) -> dict[str, Any]:
    """Generate compliance-based recommendation using ML classification and framework mappings."""
    
    # Classify the threat category
    threat_category = classify_threat_category(scoring_request, feature_map)
    
    # Get the compliance mapping for this threat
    threat_info = COMPLIANCE_MAPPING.get(threat_category, COMPLIANCE_MAPPING["unauthorized_access"])
    
    # Build ISO 27001 controls list
    iso_controls = []
    for control_id in threat_info["iso_controls"]:
        control = ISO27001_CONTROLS.get(control_id, {})
        iso_controls.append({
            "control_id": control_id,
            "name": control.get("name", "Unknown"),
            "description": control.get("description", "")
        })
    
    # Build PCI DSS controls list
    pci_controls = []
    for control_id in threat_info["pci_controls"]:
        control = PCI_DSS_CONTROLS.get(control_id, {})
        pci_controls.append({
            "control_id": control_id,
            "name": control.get("name", "Unknown"),
            "description": control.get("description", "")
        })
    
    # Build MITRE mitigations list
    mitre_mitigations = []
    for mitigation_id in threat_info["mitre_mitigations"]:
        mitigation = MITRE_MITIGATIONS.get(mitigation_id, {})
        mitre_mitigations.append({
            "mitigation_id": mitigation_id,
            "name": mitigation.get("name", "Unknown"),
            "description": mitigation.get("description", "")
        })
    
    # Build the recommendation response
    recommendation = {
        "threat_category": threat_category,
        "severity": threat_info["severity"],
        "score": score,
        "decision": decision,
        "immediate_actions": threat_info["immediate_actions"],
        "investigation_steps": threat_info["investigation_steps"],
        "remediation_steps": threat_info["remediation_steps"],
        "compliance_framework": {
            "iso_27001_controls": iso_controls,
            "pci_dss_controls": pci_controls,
            "mitre_attck_mitigations": mitre_mitigations
        },
        "compliance_notes": threat_info["compliance_notes"]
    }
    
    return recommendation