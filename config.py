"""
Dynamic Policy and Threshold Configuration Engine (FR-9).
Allows admins to configure thresholds, category confidence floors,
and escalation rules without code modifications. Every change is logged to the audit trail.
"""
from typing import Dict, Any, List, Optional
import os
import json
import datetime
from storage import PilotStorage

CONFIG_FILE_PATH = os.environ.get("CYBIT_CONFIG_PATH", "cybit_config.json")

# Default system policy configuration
DEFAULT_CONFIG = {
    "version": "1.0.0",
    "global_low_confidence_threshold": 0.45,
    "category_thresholds": {
        "account_access": 0.40,
        "email_m365": 0.45,
        "network_vpn": 0.45,
        "hardware": 0.45,
        "software": 0.45,
        "security_incident": 0.35,  # Lower threshold for recall-first safety
        "cloud_azure": 0.50,
        "backup_storage": 0.45,
        "printing": 0.45,
        "data_bi": 0.50
    },
    "routing_rules": {
        "security_incident_team": "Security Operations",
        "p1_outage_team": "Senior engineer / duty manager",
        "default_team": "Service desk L1"
    },
    "retrieval_settings": {
        "default_mode": "hybrid",
        "top_k": 3,
        "hybrid_alpha": 0.50,
        "category_boost": 0.15
    },
    "guardrail_thresholds": {
        "prompt_injection_action": "escalate_to_security",
        "block_ungrounded_drafts": True
    },
    "drift_alert_tolerances": {
        "category_accuracy_drop_max": 0.05,
        "p1_recall_drop_max": 0.05,
        "kb_hit3_drop_max": 0.05
    }
}


class PolicyConfigManager:
    """Manages reading, validation, persistence, and audit logging of system policy configurations."""
    def __init__(self, config_path: str = CONFIG_FILE_PATH, storage: Optional[PilotStorage] = None):
        self.config_path = config_path
        self.storage = storage or PilotStorage()
        self.config = self.load_config()

    def load_config(self) -> Dict[str, Any]:
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, "r") as f:
                    data = json.load(f)
                    return data
            except Exception:
                return DEFAULT_CONFIG.copy()
        else:
            self.save_config(DEFAULT_CONFIG, actor="system", reason="Initial configuration generation")
            return DEFAULT_CONFIG.copy()

    def save_config(self, new_config: Dict[str, Any], actor: str = "system", reason: str = "") -> None:
        with open(self.config_path, "w") as f:
            json.dump(new_config, f, indent=2)
        self.config = new_config

        # Record in audit log (FR-9)
        self.storage.log_audit_event(
            event_type="policy_config_updated",
            actor=actor,
            details=json.dumps({
                "reason": reason,
                "timestamp": datetime.datetime.utcnow().isoformat(),
                "config_version": new_config.get("version", "1.0.0")
            })
        )

    def get_category_threshold(self, category: str) -> float:
        cat_thresh = self.config.get("category_thresholds", {})
        return float(cat_thresh.get(category, self.config.get("global_low_confidence_threshold", 0.45)))

    def update_thresholds(self,
                          global_thresh: Optional[float] = None,
                          category_thresh: Optional[Dict[str, float]] = None,
                          actor: str = "admin",
                          reason: str = "Threshold tuning") -> Dict[str, Any]:
        cfg = self.load_config()
        if global_thresh is not None:
            cfg["global_low_confidence_threshold"] = round(float(global_thresh), 3)
        if category_thresh:
            if "category_thresholds" not in cfg:
                cfg["category_thresholds"] = {}
            for cat, val in category_thresh.items():
                cfg["category_thresholds"][cat] = round(float(val), 3)
        self.save_config(cfg, actor=actor, reason=reason)
        return cfg
