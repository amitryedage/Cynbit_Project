
from typing import List, Dict, Any, Optional
import datetime
from soc_models import RawSecurityAlert, CorrelatedIncident, MITRE_ATTACK_KNOWLEDGE, SAMPLE_ATTACK_ALERTS
from storage import PilotStorage

class SocAnalyzer:
    def __init__(self, storage: Optional[PilotStorage] = None):
        self.storage = storage or PilotStorage()
        self.mitre_kb = MITRE_ATTACK_KNOWLEDGE

    def map_alert_to_technique(self, alert: Dict[str, Any]) -> Optional[Dict[str, str]]:
        """
        Inspects process, command line, and log content to identify matching MITRE ATT&CK technique.
        """
        search_blob = (
            f"{alert.get('event_type', '')} {alert.get('process_name', '')} "
            f"{alert.get('command_line', '')} {alert.get('parent_process', '')} {alert.get('raw_log', '')}"
        ).lower()

        for tech in self.mitre_kb:
            for ind in tech["indicators"]:
                if ind.lower() in search_blob:
                    return {
                        "technique_id": tech["technique_id"],
                        "technique_name": tech["technique_name"],
                        "tactic": tech["tactic"],
                        "containment": tech["containment"]
                    }
        return None

    def correlate_and_summarize(self, alerts: List[Dict[str, Any]], client_name: str = "Acme Manufacturing UK") -> CorrelatedIncident:
        """
        Correlates raw alerts into a unified incident, maps ATT&CK kill-chain, and drafts executive narrative.
        """
        if not alerts:
            raise ValueError("No alerts provided for correlation")

        # Group by host and primary user
        affected_host = alerts[0].get("host", "Unknown Host")
        affected_user = alerts[0].get("user", "Unknown User")
        
        mapped_techniques = []
        tactics_seen = set()
        containment_actions = []

        for alt in alerts:
            t = self.map_alert_to_technique(alt)
            if t and t["technique_id"] not in [m["technique_id"] for m in mapped_techniques]:
                mapped_techniques.append(t)
                tactics_seen.add(t["tactic"])
                if t["containment"] not in containment_actions:
                    containment_actions.append(t["containment"])

        # Determine overall severity
        has_impact = any(t["tactic"] == "Impact" for t in mapped_techniques)
        has_cred_access = any(t["tactic"] == "Credential Access" for t in mapped_techniques)
        
        if has_impact or (has_cred_access and len(mapped_techniques) >= 3):
            severity = "Critical"
        elif len(mapped_techniques) >= 2:
            severity = "High"
        else:
            severity = "Medium"

        # Primary tactic (latest kill-chain stage)
        kill_chain_order = [
            "Initial Access", "Execution", "Persistence", "Privilege Escalation",
            "Defense Evasion", "Credential Access", "Lateral Movement", "Command and Control", "Exfiltration", "Impact"
        ]
        sorted_tactics = sorted(tactics_seen, key=lambda x: kill_chain_order.index(x) if x in kill_chain_order else 0, reverse=True)
        primary_tactic = sorted_tactics[0] if sorted_tactics else "Execution"

        # Synthesize Attack Narrative
        narrative_lines = [
            f"Automated kill-chain correlation analysis for host {affected_host} (Account: {affected_user}).",
            f"The incident comprises {len(alerts)} correlated telemetry alerts spanning {len(tactics_seen)} MITRE ATT&CK tactics.",
            ""
        ]
        for i, alt in enumerate(alerts, 1):
            tech = self.map_alert_to_technique(alt)
            tech_str = f"[{tech['technique_id']} {tech['technique_name']}]" if tech else "[Unclassified Telemetry]"
            narrative_lines.append(f"Step {i} ({alt.get('timestamp', 'N/A')}): {alt.get('source')} reported {alt.get('event_type')}. {tech_str}. Details: {alt.get('raw_log')}")

        attack_narrative = "\n".join(narrative_lines)

        incident_id = f"INC-{datetime.datetime.utcnow().strftime('%Y%m%d')}-001"
        title = f"Multi-Stage Cyber Attack Detected on {affected_host}: {primary_tactic} ({', '.join([t['technique_id'] for t in mapped_techniques])})"

        incident = CorrelatedIncident(
            incident_id=incident_id,
            severity=severity,
            title=title,
            client_name=client_name,
            affected_host=affected_host,
            affected_user=affected_user,
            alerts_count=len(alerts),
            primary_tactic=primary_tactic,
            mapped_techniques=mapped_techniques,
            attack_narrative=attack_narrative,
            recommended_containment=containment_actions,
            status="PENDING_ANALYST_TRIAGE"
        )

        # Log into audit trail
        self.storage.log_audit_event(
            event_type="soc_incident_synthesized",
            actor="soc_analyzer",
            details=f"Synthesized incident {incident_id} ({severity}) with {len(mapped_techniques)} mapped techniques."
        )

        return incident

    def triage_incident(self, incident: CorrelatedIncident, analyst_id: str, action: str, notes: str = "") -> CorrelatedIncident:
        """
        Security analyst sign-off and containment execution (FR-8 human approval).
        """
        incident.status = action  # "CONTAINED" or "ESCALATED_TIER_2"
        self.storage.log_audit_event(
            event_type="soc_incident_triaged",
            actor=analyst_id,
            details=f"Analyst {analyst_id} triaged incident {incident.incident_id} to status {action}. Notes: {notes}"
        )
        return incident
