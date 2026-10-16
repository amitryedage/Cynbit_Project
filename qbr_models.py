"""
Stage 4: Automated Service Reports and Quarterly Business Review (QBR) Drafts (PRD Section 15).
Defines data structures and historical metrics for:
- Service Desk Operations & SLA Performance
- Infrastructure Reliability & Backup Health
- Cybersecurity Posture & Threat Remediation
- Strategic IT Roadmap Recommendations
"""
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field

class ServiceDeskKPIs(BaseModel):
    total_tickets: int
    sla_compliance_rate: float  # e.g. 0.982 for 98.2%
    median_first_response_mins: float
    p1_incidents_count: int
    top_categories: Dict[str, int]
    user_satisfaction_rating: float  # e.g. 4.8 / 5.0

class InfrastructureReliabilityKPIs(BaseModel):
    backup_success_rate: float  # e.g. 0.994
    total_storage_protected_tb: float
    disaster_recovery_drill_passed: bool
    endpoint_patch_compliance_pct: float

class SecurityPostureKPIs(BaseModel):
    threat_advisories_remediated: int
    soc_incidents_contained: int
    phishing_emails_blocked: int
    mfa_enforcement_rate: float

class StrategicInitiative(BaseModel):
    title: str
    target_timeline: str
    business_impact: str
    estimated_budget: str

class QBRDocument(BaseModel):
    report_id: str
    client_id: str
    client_name: str
    reporting_quarter: str
    generated_at: str
    executive_summary: str
    service_desk_kpis: ServiceDeskKPIs
    infrastructure_kpis: InfrastructureReliabilityKPIs
    security_kpis: SecurityPostureKPIs
    strategic_initiatives: List[StrategicInitiative]
    status: str  # DRAFT_PENDING_DIRECTOR_REVIEW, APPROVED_FOR_CLIENT_PRESENTATION


# Realistic Quarterly Benchmark Datasets for Cybit Managed Accounts
SAMPLE_QBR_DATA: Dict[str, Dict[str, Any]] = {
    "CLI-ACME": {
        "client_name": "Acme Manufacturing UK",
        "quarter": "Q3 2026",
        "service_desk": {
            "total_tickets": 412,
            "sla_compliance_rate": 0.978,
            "median_first_response_mins": 8.4,
            "p1_incidents_count": 1,
            "top_categories": {"software": 124, "account_access": 98, "network_vpn": 74, "hardware": 62, "cloud_azure": 54},
            "user_satisfaction_rating": 4.7
        },
        "infrastructure": {
            "backup_success_rate": 0.996,
            "total_storage_protected_tb": 14.8,
            "disaster_recovery_drill_passed": True,
            "endpoint_patch_compliance_pct": 0.991
        },
        "security": {
            "threat_advisories_remediated": 6,
            "soc_incidents_contained": 1,
            "phishing_emails_blocked": 1420,
            "mfa_enforcement_rate": 1.000
        },
        "initiatives": [
            {
                "title": "Upgrade Legacy Windows Server 2019 to Windows Server 2025",
                "target_timeline": "Q4 2026",
                "business_impact": "Eliminates technical debt on manufacturing line database host.",
                "estimated_budget": "£6,500"
            },
            {
                "title": "Deploy FIDO2 Hardware Security Keys for Factory Floor Shared Workstations",
                "target_timeline": "Q1 2027",
                "business_impact": "Streamlines multi-user logins while meeting cyber insurance MFA requirements.",
                "estimated_budget": "£3,200"
            }
        ]
    },
    "CLI-BELFAST": {
        "client_name": "Belfast Legal Associates",
        "quarter": "Q3 2026",
        "service_desk": {
            "total_tickets": 284,
            "sla_compliance_rate": 0.991,
            "median_first_response_mins": 5.2,
            "p1_incidents_count": 0,
            "top_categories": {"account_access": 110, "email_m365": 84, "software": 52, "printing": 38},
            "user_satisfaction_rating": 4.9
        },
        "infrastructure": {
            "backup_success_rate": 1.000,
            "total_storage_protected_tb": 8.2,
            "disaster_recovery_drill_passed": True,
            "endpoint_patch_compliance_pct": 0.995
        },
        "security": {
            "threat_advisories_remediated": 4,
            "soc_incidents_contained": 0,
            "phishing_emails_blocked": 890,
            "mfa_enforcement_rate": 1.000
        },
        "initiatives": [
            {
                "title": "Microsoft Purview Information Protection & Sensitivity Labeling Rollout",
                "target_timeline": "Q4 2026",
                "business_impact": "Automated data-loss prevention for confidential client litigation casework.",
                "estimated_budget": "£4,800"
            }
        ]
    }
}
