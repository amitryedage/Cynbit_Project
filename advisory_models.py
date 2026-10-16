from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field

class TechAsset(BaseModel):
    category: str = Field(..., description="Asset category: os, network, cloud, software, database")
    vendor: str = Field(..., description="Vendor name: Microsoft, Fortinet, Cisco, Veeam, Palo Alto")
    product: str = Field(..., description="Product name: FortiGate, Windows Server, Exchange Online, Veeam B&R")
    version: Optional[str] = Field(default=None, description="Installed version or release")
    criticality: str = Field(default="high", description="Business criticality: critical, high, medium, low")

class ClientProfile(BaseModel):
    client_id: str
    client_name: str
    industry: str
    contact_email: str
    tech_stack: List[TechAsset]

class SecurityAdvisory(BaseModel):
    advisory_id: str
    cve_id: str
    title: str
    vendor: str
    affected_products: List[str]
    cvss_score: float
    severity: str  # Critical, High, Medium, Low
    is_actively_exploited: bool
    summary: str
    technical_details: str
    remediation_steps: List[str]
    published_date: str

class ClientMatchResult(BaseModel):
    client_id: str
    client_name: str
    is_affected: bool
    affected_assets: List[str]
    risk_score: float  # 0 to 10
    urgency: str       # Immediate Action, Scheduled Patch, Informational

class AdvisoryDigest(BaseModel):
    digest_id: str
    advisory_id: str
    cve_id: str
    client_id: str
    client_name: str
    executive_summary: str
    client_impact: str
    cybit_action_taken: str
    client_action_required: str
    status: str  # DRAFT_PENDING_REVIEW, APPROVED_BY_ANALYST, DISPATCHED


# Illustrative Managed Client Inventories representing Cybit client sectors
SAMPLE_CLIENTS: List[Dict[str, Any]] = [
    {
        "client_id": "CLI-ACME",
        "client_name": "Acme Manufacturing UK",
        "industry": "Manufacturing",
        "contact_email": "it-director@acme-mfg.co.uk",
        "tech_stack": [
            {"category": "network", "vendor": "Fortinet", "product": "FortiGate 60F", "version": "7.0.12", "criticality": "critical"},
            {"category": "os", "vendor": "Microsoft", "product": "Windows Server 2019", "version": "1809", "criticality": "high"},
            {"category": "software", "vendor": "Veeam", "product": "Veeam Backup & Replication", "version": "12.0", "criticality": "critical"},
            {"category": "cloud", "vendor": "Microsoft", "product": "Microsoft 365", "version": "E3", "criticality": "high"}
        ]
    },
    {
        "client_id": "CLI-BELFAST",
        "client_name": "Belfast Legal Associates",
        "industry": "Legal Services",
        "contact_email": "operations@belfast-legal.co.uk",
        "tech_stack": [
            {"category": "network", "vendor": "Palo Alto", "product": "GlobalProtect VPN", "version": "10.1", "criticality": "critical"},
            {"category": "os", "vendor": "Microsoft", "product": "Windows 11 Enterprise", "version": "23H2", "criticality": "medium"},
            {"category": "cloud", "vendor": "Microsoft", "product": "Exchange Online", "version": "Cloud", "criticality": "critical"},
            {"category": "cloud", "vendor": "Microsoft", "product": "Azure Virtual Machines", "version": "Cloud", "criticality": "high"}
        ]
    },
    {
        "client_id": "CLI-HIGHLAND",
        "client_name": "Highland Cold Chain Logistics",
        "industry": "Logistics & Transport",
        "contact_email": "infrastructure@highland-logistics.com",
        "tech_stack": [
            {"category": "network", "vendor": "Cisco", "product": "Cisco Meraki MX68", "version": "18.107", "criticality": "critical"},
            {"category": "os", "vendor": "Microsoft", "product": "Windows Server 2022", "version": "21H2", "criticality": "high"},
            {"category": "database", "vendor": "Microsoft", "product": "SQL Server Standard", "version": "2019", "criticality": "critical"},
            {"category": "software", "vendor": "QuickBooks", "product": "QuickBooks Desktop Enterprise", "version": "23.0", "criticality": "medium"}
        ]
    }
]

# Real-world vulnerability bulletins (CVE threat intelligence)
SAMPLE_ADVISORIES: List[Dict[str, Any]] = [
    {
        "advisory_id": "ADV-2026-001",
        "cve_id": "CVE-2024-21762",
        "title": "Fortinet FortiOS SSL-VPN Out-of-Bounds Write Vulnerability",
        "vendor": "Fortinet",
        "affected_products": ["FortiGate", "FortiOS", "SSL-VPN"],
        "cvss_score": 9.8,
        "severity": "Critical",
        "is_actively_exploited": True,
        "summary": "Critical out-of-bounds write vulnerability in FortiOS SSL-VPN allows remote unauthenticated attacker to execute arbitrary code via specially crafted HTTP requests.",
        "technical_details": "Affects FortiOS versions 7.4, 7.2, 7.0, and 6.4. Exploitation is confirmed in the wild by state-sponsored threat actors.",
        "remediation_steps": [
            "Upgrade FortiOS to version 7.0.14, 7.2.7, or 7.4.3 immediately.",
            "If immediate upgrade is not feasible, disable SSL-VPN functionality as a temporary workaround.",
            "Verify perimeter firewall logs for unusual outbound connections from the FortiGate management plane."
        ],
        "published_date": "2026-02-09"
    },
    {
        "advisory_id": "ADV-2026-002",
        "cve_id": "CVE-2024-40711",
        "title": "Veeam Backup & Replication Remote Code Execution Vulnerability",
        "vendor": "Veeam",
        "affected_products": ["Veeam Backup & Replication", "Veeam Agent"],
        "cvss_score": 9.8,
        "severity": "Critical",
        "is_actively_exploited": True,
        "summary": "Critical deserialization vulnerability in Veeam Backup & Replication allows an unauthenticated remote attacker to gain full system-level execution on the backup server.",
        "technical_details": "Affects Veeam Backup & Replication 12.1.2.172 and older. Frequently leveraged by ransomware gangs to destroy backups prior to encryption.",
        "remediation_steps": [
            "Apply Veeam Security Hotfix 12.2.0.334 immediately.",
            "Ensure the backup server is isolated on a dedicated, non-routable management VLAN.",
            "Enable immutability on backup repositories to prevent malicious deletion."
        ],
        "published_date": "2026-09-04"
    },
    {
        "advisory_id": "ADV-2026-003",
        "cve_id": "CVE-2024-3400",
        "title": "Palo Alto Networks PAN-OS GlobalProtect Command Injection Vulnerability",
        "vendor": "Palo Alto",
        "affected_products": ["Palo Alto", "PAN-OS", "GlobalProtect VPN"],
        "cvss_score": 10.0,
        "severity": "Critical",
        "is_actively_exploited": True,
        "summary": "Command injection vulnerability in GlobalProtect feature of PAN-OS allows unauthenticated attacker to execute arbitrary code with root privileges on the firewall.",
        "technical_details": "Affects PAN-OS 10.2, 11.0, and 11.1 firewalls configured with GlobalProtect gateway or portal.",
        "remediation_steps": [
            "Apply hotfixes PAN-OS 10.2.9-h1, 11.0.4-h1, or 11.1.2-h3.",
            "Enable Threat Prevention signature 95187 to detect exploitation attempts.",
            "Disable device telemetry until hotfix is installed."
        ],
        "published_date": "2026-04-12"
    },
    {
        "advisory_id": "ADV-2026-004",
        "cve_id": "CVE-2024-38077",
        "title": "Windows Remote Desktop Licensing Service Remote Code Execution",
        "vendor": "Microsoft",
        "affected_products": ["Windows Server 2019", "Windows Server 2022", "Windows Server 2016"],
        "cvss_score": 9.8,
        "severity": "Critical",
        "is_actively_exploited": False,
        "summary": "Vulnerability in Windows Remote Desktop Licensing Service allows remote unauthenticated code execution on domain servers hosting the licensing role.",
        "technical_details": "Affects all supported Windows Server editions with Remote Desktop Licensing Service enabled.",
        "remediation_steps": [
            "Apply Microsoft July 2024 cumulative security update (KB5040437 / KB5040442).",
            "Disable Remote Desktop Licensing Service if not actively required in the environment."
        ],
        "published_date": "2026-07-09"
    }
]
