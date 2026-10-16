from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field

class RawSecurityAlert(BaseModel):
    alert_id: str
    timestamp: str
    source: str  # EDR, SIEM, Firewall, Identity
    host: str
    user: str
    event_type: str
    process_name: Optional[str] = None
    command_line: Optional[str] = None
    parent_process: Optional[str] = None
    dest_ip: Optional[str] = None
    raw_log: str

class MitreTechnique(BaseModel):
    technique_id: str
    technique_name: str
    tactic: str  # Initial Access, Execution, Persistence, Defense Evasion, Credential Access, Lateral Movement, C2, Impact
    description: str

class CorrelatedIncident(BaseModel):
    incident_id: str
    severity: str  # Critical, High, Medium, Low
    title: str
    client_name: str
    affected_host: str
    affected_user: str
    alerts_count: int
    primary_tactic: str
    mapped_techniques: List[Dict[str, str]]
    attack_narrative: str
    recommended_containment: List[str]
    status: str  # PENDING_ANALYST_TRIAGE, CONTAINED, ESCALATED_TIER_2


# MITRE ATT&CK Knowledge Base
MITRE_ATTACK_KNOWLEDGE = [
    {
        "technique_id": "T1566.001",
        "technique_name": "Spearphishing Attachment",
        "tactic": "Initial Access",
        "indicators": ["outlook.exe", "winword.exe", "excel.exe", "zip", "iso", "macro"],
        "containment": "Purge phishing email tenant-wide; reset compromised mailbox credentials."
    },
    {
        "technique_id": "T1059.001",
        "technique_name": "PowerShell Execution",
        "tactic": "Execution",
        "indicators": ["powershell.exe", "-enc", "-w hidden", "invoke-expression", "iex", "downloadstring"],
        "containment": "Isolate endpoint via EDR; terminate suspicious PowerShell process trees."
    },
    {
        "technique_id": "T1003.001",
        "technique_name": "LSASS Memory Dumping",
        "tactic": "Credential Access",
        "indicators": ["lsass.exe", "procdump", "mimikatz", "comsvcs.dll", "minidump"],
        "containment": "Revoke all active Kerberos sessions; force password reset for affected administrative users."
    },
    {
        "technique_id": "T1562.001",
        "technique_name": "Disable Security Tools",
        "tactic": "Defense Evasion",
        "indicators": ["set-mppreference -disablerealtimemonitoring", "net stop windefend", "fltmc unload"],
        "containment": "Re-enable Defender real-time protection; deploy tamper protection policy via Intune."
    },
    {
        "technique_id": "T1021.002",
        "technique_name": "SMB/Windows Admin Shares",
        "tactic": "Lateral Movement",
        "indicators": ["c$", "admin$", "psexec", "wmiexec", "net use"],
        "containment": "Block internal SMB traffic between workstations; enforce host-based firewall isolation."
    },
    {
        "technique_id": "T1486",
        "technique_name": "Data Encrypted for Impact",
        "tactic": "Impact",
        "indicators": [".locked", "vssadmin delete shadows", "wbadmin delete", "ransom", "readme.txt"],
        "containment": "Immediately disconnect host from network; preserve RAM dump; verify offline immutable backups."
    }
]

# Realistic Multi-Stage Attack Telemetry (Phishing -> PowerShell -> Credential Dumping -> Ransomware)
SAMPLE_ATTACK_ALERTS: List[Dict[str, Any]] = [
    {
        "alert_id": "ALT-0911",
        "timestamp": "2026-10-16T14:15:02Z",
        "source": "Microsoft Defender for Endpoint",
        "host": "WKSTN-FIN-04.acme.local",
        "user": "priya.patel",
        "event_type": "Suspicious Process Creation",
        "process_name": "powershell.exe",
        "command_line": "powershell.exe -w hidden -enc aQBlAHgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAKQAuA...",
        "parent_process": "winword.exe",
        "dest_ip": "185.220.101.5",
        "raw_log": "EDR detected Word launching hidden base64 encoded PowerShell connecting to external IP 185.220.101.5."
    },
    {
        "alert_id": "ALT-0912",
        "timestamp": "2026-10-16T14:16:35Z",
        "source": "EDR Behavior Monitor",
        "host": "WKSTN-FIN-04.acme.local",
        "user": "SYSTEM",
        "event_type": "Suspicious Memory Access",
        "process_name": "powershell.exe",
        "command_line": "rundll32.exe C:\\windows\\system32\\comsvcs.dll, MiniDump 648 C:\\temp\\lsass.dmp full",
        "parent_process": "powershell.exe",
        "dest_ip": None,
        "raw_log": "Process accessed LSASS process memory attempting to write minidump to temp directory."
    },
    {
        "alert_id": "ALT-0913",
        "timestamp": "2026-10-16T14:18:10Z",
        "source": "Network Firewall",
        "host": "WKSTN-FIN-04.acme.local",
        "user": "priya.patel",
        "event_type": "Lateral Network Connection",
        "process_name": None,
        "command_line": None,
        "parent_process": None,
        "dest_ip": "10.0.4.15",
        "raw_log": "Unusual SMB connection from workstation WKSTN-FIN-04 to core file server 10.0.4.15 over port 445."
    },
    {
        "alert_id": "ALT-0914",
        "timestamp": "2026-10-16T14:20:00Z",
        "source": "EDR Ransomware Guard",
        "host": "WKSTN-FIN-04.acme.local",
        "user": "priya.patel",
        "event_type": "Shadow Copy Deletion",
        "process_name": "vssadmin.exe",
        "command_line": "vssadmin.exe delete shadows /all /quiet",
        "parent_process": "cmd.exe",
        "dest_ip": None,
        "raw_log": "High-confidence ransomware behavior: command attempted to purge Volume Shadow Copies."
    }
]
