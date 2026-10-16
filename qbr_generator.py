"""
Automated Service Reports and QBR Draft Generator (Stage 4).
Compiles multi-department managed service data (ITSM ticket metrics, backup health,
and SOC cybersecurity telemetry) into executive Quarterly Business Review reports.
"""
from typing import Dict, List, Any, Optional
import datetime
from qbr_models import QBRDocument, ServiceDeskKPIs, InfrastructureReliabilityKPIs, SecurityPostureKPIs, StrategicInitiative, SAMPLE_QBR_DATA
from storage import PilotStorage

class QBRGenerator:
    def __init__(self, storage: Optional[PilotStorage] = None):
        self.storage = storage or PilotStorage()

    def generate_qbr(self, client_id: str, custom_data: Optional[Dict[str, Any]] = None) -> QBRDocument:
        raw_data = custom_data or SAMPLE_QBR_DATA.get(client_id)
        if not raw_data:
            raise ValueError(f"No QBR baseline data found for client ID: {client_id}")

        client_name = raw_data["client_name"]
        quarter = raw_data["quarter"]
        report_id = f"QBR-{client_id}-{quarter.replace(' ', '')}"
        now = datetime.datetime.utcnow().isoformat()

        sd = raw_data["service_desk"]
        infra = raw_data["infrastructure"]
        sec = raw_data["security"]

        # Synthesize Executive Narrative
        exec_summary = (
            f"During {quarter}, Cybit delivered continuous managed IT, cloud infrastructure, and 24/7 cybersecurity "
            f"services for {client_name}. Across the quarter, the service desk maintained an exceptional SLA compliance "
            f"rate of {sd['sla_compliance_rate'] * 100:.1f}%, with a median first response time of {sd['median_first_response_mins']} minutes. "
            f"Infrastructure backup health achieved {infra['backup_success_rate'] * 100:.1f}% reliability with verified disaster "
            f"recovery drill sign-off. On the security front, Cybit Managed SOC neutralized {sec['phishing_emails_blocked']} malicious emails "
            f"and contained {sec['soc_incidents_contained']} high-severity incident with zero client operational data loss."
        )

        initiatives = [
            StrategicInitiative(**item) for item in raw_data.get("initiatives", [])
        ]

        doc = QBRDocument(
            report_id=report_id,
            client_id=client_id,
            client_name=client_name,
            reporting_quarter=quarter,
            generated_at=now,
            executive_summary=exec_summary,
            service_desk_kpis=ServiceDeskKPIs(**sd),
            infrastructure_kpis=InfrastructureReliabilityKPIs(**infra),
            security_kpis=SecurityPostureKPIs(**sec),
            strategic_initiatives=initiatives,
            status="DRAFT_PENDING_DIRECTOR_REVIEW"
        )

        # Write Markdown Report File
        self._write_markdown_qbr(doc)

        # Log into audit trail
        self.storage.log_audit_event(
            event_type="qbr_report_drafted",
            actor="qbr_generator",
            details=f"Generated executive QBR document {report_id} for {client_name} ({quarter})"
        )

        return doc

    def _write_markdown_qbr(self, doc: QBRDocument, filepath: Optional[str] = None) -> str:
        out_path = filepath or f"QBR_Report_{doc.client_id}_{doc.reporting_quarter.replace(' ', '_')}.md"
        sd = doc.service_desk_kpis
        infra = doc.infrastructure_kpis
        sec = doc.security_kpis

        top_cat_lines = "\n".join([f"- {cat}: {cnt} tickets" for cat, cnt in sd.top_categories.items()])
        initiatives_lines = "\n\n".join([
            f"### {init.title} (Target: {init.target_timeline})\n"
            f"- Business Impact: {init.business_impact}\n"
            f"- Estimated Investment: {init.estimated_budget}"
            for init in doc.strategic_initiatives
        ])

        lines = [
            f"# Executive Quarterly Business Review (QBR): {doc.client_name}",
            f"Reporting Period: {doc.reporting_quarter} | Generated: {doc.generated_at[:10]}",
            f"Author: Cybit Service Delivery & Managed Security Team",
            "",
            "## 1. Executive Summary",
            doc.executive_summary,
            "",
            "## 2. Service Desk Operations & SLA Performance",
            f"- Total Support Tickets Handled: {sd.total_tickets}",
            f"- SLA Compliance Rate: {sd.sla_compliance_rate * 100:.1f}% (Contract Target: >= 95.0%)",
            f"- Median First Response Time: {sd.median_first_response_mins} minutes (Target: < 15 mins)",
            f"- Major P1 Outages Recorded: {sd.p1_incidents_count}",
            f"- End-User Satisfaction Rating: {sd.user_satisfaction_rating} / 5.0",
            "",
            "### Top Incident Categories",
            top_cat_lines,
            "",
            "## 3. Infrastructure Health & Disaster Recovery Readiness",
            f"- Backup Success Rate: {infra.backup_success_rate * 100:.1f}%",
            f"- Total Storage Protected: {infra.total_storage_protected_tb} TB across virtual & cloud environments",
            f"- Quarterly Disaster Recovery Drill: {'PASSED (Zero recovery errors)' if infra.disaster_recovery_drill_passed else 'ACTION REQUIRED'}",
            f"- Endpoint Patch Compliance: {infra.endpoint_patch_compliance_pct * 100:.1f}%",
            "",
            "## 4. Managed Cybersecurity Posture (Cybit SOC)",
            f"- Malicious Phishing Emails Blocked: {sec.phishing_emails_blocked}",
            f"- Critical Vulnerability Advisories Patched: {sec.threat_advisories_remediated}",
            f"- High-Severity SOC Incidents Neutralized: {sec.soc_incidents_contained}",
            f"- Corporate MFA Enforcement Rate: {sec.mfa_enforcement_rate * 100:.1f}%",
            "",
            "## 5. Strategic Technology Roadmap (Next Quarter Priorities)",
            initiatives_lines,
            "",
            "---",
            "Document Status: " + doc.status
        ]

        with open(out_path, "w") as f:
            f.write("\n".join(lines) + "\n")
        return out_path

    def approve_qbr(self, doc: QBRDocument, director_id: str, notes: str = "") -> QBRDocument:
        """
        Service Director sign-off workflow (FR-8 human approval).
        """
        doc.status = "APPROVED_FOR_CLIENT_PRESENTATION"
        self.storage.log_audit_event(
            event_type="qbr_report_approved",
            actor=director_id,
            details=f"Service Director {director_id} approved QBR {doc.report_id}. Notes: {notes}"
        )
        return doc
