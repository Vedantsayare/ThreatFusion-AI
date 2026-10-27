"""
normalization/mitre.py — Static MITRE ATT&CK reference for technique naming.

Used only to label technique IDs that are already present in an alert (e.g. a
Wazuh rule's ``mitre.id`` list) with their public ATT&CK name and primary
tactic when the alert itself omits them. It never adds techniques to a finding.

Source: MITRE ATT&CK Enterprise matrix (public). Sub-techniques fall back to
their parent technique's tactic. Unknown IDs return None and stay unlabelled.
"""

from __future__ import annotations

# technique_id -> (technique name, primary tactic)
ATTACK_TECHNIQUES: dict[str, tuple[str, str]] = {
    "T1003": ("OS Credential Dumping", "Credential Access"),
    "T1003.001": ("LSASS Memory", "Credential Access"),
    "T1021": ("Remote Services", "Lateral Movement"),
    "T1021.001": ("Remote Desktop Protocol", "Lateral Movement"),
    "T1021.002": ("SMB/Windows Admin Shares", "Lateral Movement"),
    "T1021.004": ("SSH", "Lateral Movement"),
    "T1041": ("Exfiltration Over C2 Channel", "Exfiltration"),
    "T1046": ("Network Service Discovery", "Discovery"),
    "T1048": ("Exfiltration Over Alternative Protocol", "Exfiltration"),
    "T1053": ("Scheduled Task/Job", "Persistence"),
    "T1053.005": ("Scheduled Task", "Persistence"),
    "T1059": ("Command and Scripting Interpreter", "Execution"),
    "T1059.001": ("PowerShell", "Execution"),
    "T1059.003": ("Windows Command Shell", "Execution"),
    "T1059.004": ("Unix Shell", "Execution"),
    "T1068": ("Exploitation for Privilege Escalation", "Privilege Escalation"),
    "T1070": ("Indicator Removal", "Defense Evasion"),
    "T1070.001": ("Clear Windows Event Logs", "Defense Evasion"),
    "T1071": ("Application Layer Protocol", "Command and Control"),
    "T1071.001": ("Web Protocols", "Command and Control"),
    "T1071.004": ("DNS", "Command and Control"),
    "T1078": ("Valid Accounts", "Initial Access"),
    "T1078.002": ("Domain Accounts", "Initial Access"),
    "T1078.003": ("Local Accounts", "Initial Access"),
    "T1098": ("Account Manipulation", "Persistence"),
    "T1110": ("Brute Force", "Credential Access"),
    "T1110.001": ("Password Guessing", "Credential Access"),
    "T1110.003": ("Password Spraying", "Credential Access"),
    "T1190": ("Exploit Public-Facing Application", "Initial Access"),
    "T1486": ("Data Encrypted for Impact", "Impact"),
    "T1490": ("Inhibit System Recovery", "Impact"),
    "T1547.001": ("Registry Run Keys / Startup Folder", "Persistence"),
    "T1548": ("Abuse Elevation Control Mechanism", "Privilege Escalation"),
    "T1548.003": ("Sudo and Sudo Caching", "Privilege Escalation"),
    "T1560": ("Archive Collected Data", "Collection"),
    "T1567": ("Exfiltration Over Web Service", "Exfiltration"),
    "T1567.002": ("Exfiltration to Cloud Storage", "Exfiltration"),
}


def lookup_technique(technique_id: str) -> tuple[str, str] | None:
    """Return (name, tactic) for a technique ID, or None when not catalogued."""
    tid = technique_id.strip().upper()
    if tid in ATTACK_TECHNIQUES:
        return ATTACK_TECHNIQUES[tid]
    parent = tid.split(".")[0]
    if parent in ATTACK_TECHNIQUES and parent != tid:
        name, tactic = ATTACK_TECHNIQUES[parent]
        return f"{name} (sub-technique {tid})", tactic
    return None
