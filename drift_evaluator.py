"""
Automated Weekly Evaluation and Model Drift Detection Engine (FR-22).
Runs automatic evaluations against frozen gold sets, monitors performance degradation,
and triggers operational alerts if key metrics fall below agreed baselines.
"""
from typing import Dict, List, Any, Optional, Tuple
import datetime
import json
import numpy as np
from sklearn.metrics import accuracy_score, f1_score
from kb_and_data import HAND_TESTSET, PRIORITIES
from blind_testset import BLIND_TESTSET
from triage import TicketTriage
from storage import PilotStorage
from config import PolicyConfigManager

# Baseline targets established in PRD Proof of Concept (Appendix A)
POC_BASELINES = {
    "blind_set": {
        "category_accuracy": 0.833,
        "priority_within_one": 0.967,
        "p1_recall": 0.800,
        "kb_hit3_hybrid": 0.867,
        "security_miss_rate": 0.000
    },
    "dev_set": {
        "category_accuracy": 0.750,
        "priority_within_one": 0.900,
        "p1_recall": 0.800,
        "kb_hit3_hybrid": 0.800,
        "security_miss_rate": 0.000
    }
}

class DriftEvaluator:
    """Evaluates active models against frozen gold sets to detect metric drift and degradation."""
    def __init__(self,
                 storage: Optional[PilotStorage] = None,
                 config_mgr: Optional[PolicyConfigManager] = None):
        self.storage = storage or PilotStorage()
        self.config_mgr = config_mgr or PolicyConfigManager(storage=self.storage)

    def evaluate_dataset(self, model: TicketTriage, tickets: List[Dict[str, Any]]) -> Dict[str, Any]:
        texts = [t["text"] for t in tickets]
        actual_cat = [t["category"] for t in tickets]
        actual_pri = [t["priority"] for t in tickets]
        actual_kb = [t["kb_id"] for t in tickets]

        preds = [model.predict(x, mode="hybrid") for x in texts]
        pred_cat = [p["category"] for p in preds]
        pred_pri = [p["priority"] for p in preds]

        cat_acc = accuracy_score(actual_cat, pred_cat)
        cat_f1 = f1_score(actual_cat, pred_cat, average="macro")

        pri_levels = PRIORITIES
        pri_one = float(np.mean([
            abs(pri_levels.index(a) - pri_levels.index(b)) <= 1
            for a, b in zip(actual_pri, pred_pri)
        ]))

        p1_cases = [p == "P1" for a, p in zip(actual_pri, pred_pri) if a == "P1"]
        p1_rec = float(np.mean(p1_cases)) if p1_cases else 1.0

        hit3 = float(np.mean([
            act in [h["kb_id"] for h in p["kb"][:3]]
            for act, p in zip(actual_kb, preds)
        ]))

        sec_tickets = [(t, p) for t, p in zip(tickets, preds) if t["category"] == "security_incident"]
        sec_misses = [p["category"] != "security_incident" for _, p in sec_tickets]
        sec_miss_rate = float(np.mean(sec_misses)) if sec_misses else 0.0

        return {
            "n": len(tickets),
            "category_accuracy": round(float(cat_acc), 4),
            "category_macro_f1": round(float(cat_f1), 4),
            "priority_within_one": round(float(pri_one), 4),
            "p1_recall": round(float(p1_rec), 4),
            "kb_hit3_hybrid": round(float(hit3), 4),
            "security_miss_rate": round(float(sec_miss_rate), 4)
        }

    def run_weekly_drift_check(self, model: TicketTriage) -> Dict[str, Any]:
        """
        Runs comprehensive evaluation against dev set and blind set.
        Generates alerts if performance drops exceed configured tolerances.
        """
        hand_data = [{"text": t, "category": c, "priority": p, "kb_id": k} for t, c, p, k in HAND_TESTSET]
        blind_data = [{"text": t, "category": c, "priority": p, "kb_id": k} for t, c, p, k in BLIND_TESTSET]

        dev_results = self.evaluate_dataset(model, hand_data)
        blind_results = self.evaluate_dataset(model, blind_data)

        tolerances = self.config_mgr.config.get("drift_alert_tolerances", {
            "category_accuracy_drop_max": 0.05,
            "p1_recall_drop_max": 0.05,
            "kb_hit3_drop_max": 0.05
        })

        alerts = []

        # Check Blind Set Drift against PoC Baseline
        blind_base = POC_BASELINES["blind_set"]
        
        # 1. Safety check: Security miss rate MUST be 0.0
        if blind_results["security_miss_rate"] > 0.0:
            alerts.append({
                "severity": "CRITICAL",
                "metric": "security_miss_rate",
                "dataset": "blind_set",
                "current": blind_results["security_miss_rate"],
                "target": 0.0,
                "message": "CRITICAL SAFETY ALERT: Confirmed security tickets were not routed to security queue."
            })

        # 2. Safety check: P1 recall drop
        p1_drop = blind_base["p1_recall"] - blind_results["p1_recall"]
        if p1_drop > tolerances["p1_recall_drop_max"]:
            alerts.append({
                "severity": "HIGH",
                "metric": "p1_recall",
                "dataset": "blind_set",
                "current": blind_results["p1_recall"],
                "baseline": blind_base["p1_recall"],
                "drop": round(p1_drop, 4),
                "message": f"Major outage P1 recall degraded by {p1_drop*100:.1f}% below baseline."
            })

        # 3. Quality check: Category accuracy drop
        cat_drop = blind_base["category_accuracy"] - blind_results["category_accuracy"]
        if cat_drop > tolerances["category_accuracy_drop_max"]:
            alerts.append({
                "severity": "MEDIUM",
                "metric": "category_accuracy",
                "dataset": "blind_set",
                "current": blind_results["category_accuracy"],
                "baseline": blind_base["category_accuracy"],
                "drop": round(cat_drop, 4),
                "message": f"Category accuracy dropped by {cat_drop*100:.1f}% on frozen blind test set."
            })

        # 4. Retrieval check: Hit@3 drop
        hit_drop = blind_base["kb_hit3_hybrid"] - blind_results["kb_hit3_hybrid"]
        if hit_drop > tolerances["kb_hit3_drop_max"]:
            alerts.append({
                "severity": "MEDIUM",
                "metric": "kb_hit3_hybrid",
                "dataset": "blind_set",
                "current": blind_results["kb_hit3_hybrid"],
                "baseline": blind_base["kb_hit3_hybrid"],
                "drop": round(hit_drop, 4),
                "message": f"Runbook retrieval Hit@3 dropped by {hit_drop*100:.1f}%."
            })

        status = "PASSED" if not alerts else ("ALERT" if any(a["severity"] in ["CRITICAL", "HIGH"] for a in alerts) else "WARNING")
        now = datetime.datetime.utcnow().isoformat()

        report = {
            "timestamp": now,
            "status": status,
            "blind_set_evaluation": blind_results,
            "dev_set_evaluation": dev_results,
            "active_alerts": alerts,
            "alert_count": len(alerts)
        }

        # Log evaluation in immutable audit trail (FR-22)
        self.storage.log_audit_event(
            event_type="weekly_drift_evaluation",
            actor="drift_monitor",
            details=json.dumps({
                "status": status,
                "alert_count": len(alerts),
                "blind_cat_acc": blind_results["category_accuracy"],
                "blind_p1_recall": blind_results["p1_recall"]
            })
        )

        return report
