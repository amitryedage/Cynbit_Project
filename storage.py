"""
Pilot Storage Engine (FR-18, FR-19, FR-20, FR-21).
Manages persistent SQLite storage for:
- Triaged tickets and metadata
- Shadow mode comparisons (silent model predictions vs human engineer actuals)
- Engineer feedback (1-click accept, override, thumbs up/down, reasons)
- Immutable audit trail
"""
from typing import Dict, List, Any, Optional
import sqlite3
import json
import datetime
import os

DEFAULT_DB_PATH = os.environ.get("CYBIT_DB_PATH", "cybit_pilot.db")

class PilotStorage:
    def __init__(self, db_path: str = DEFAULT_DB_PATH):
        self.db_path = db_path
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            # 1. Triaged tickets table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS tickets (
                ticket_id TEXT PRIMARY KEY,
                text TEXT,
                sanitized_text TEXT,
                category TEXT,
                cat_conf REAL,
                priority TEXT,
                pri_conf REAL,
                route_team TEXT,
                auto_reply_allowed INTEGER,
                draft_reply TEXT,
                draft_status TEXT,
                model_version TEXT,
                latency_ms REAL,
                created_at TEXT
            )
            """)

            # 2. Engineer feedback table (FR-18)
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS feedback (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ticket_id TEXT,
                engineer_id TEXT,
                rating TEXT,
                action TEXT,
                final_category TEXT,
                final_priority TEXT,
                final_runbook_id TEXT,
                override_reason TEXT,
                comments TEXT,
                created_at TEXT,
                FOREIGN KEY (ticket_id) REFERENCES tickets (ticket_id)
            )
            """)

            # 3. Shadow mode evaluation table (FR-19, Stage 1 Phase 2)
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS shadow_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ticket_id TEXT,
                predicted_category TEXT,
                actual_category TEXT,
                predicted_priority TEXT,
                actual_priority TEXT,
                predicted_p1 INTEGER,
                actual_p1 INTEGER,
                security_flagged INTEGER,
                actual_security INTEGER,
                category_agreed INTEGER,
                priority_within_one INTEGER,
                created_at TEXT
            )
            """)

            # 4. Immutable audit trail table (FR-20)
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT,
                ticket_id TEXT,
                actor TEXT,
                details TEXT,
                created_at TEXT
            )
            """)
            conn.commit()

    def save_ticket(self,
                    ticket_id: str,
                    text: str,
                    sanitized_text: str,
                    triage_result: Dict[str, Any],
                    model_version: str = "v1.0.0",
                    latency_ms: float = 0.0) -> None:
        now = datetime.datetime.utcnow().isoformat()
        route = triage_result.get("route", {})
        reply = triage_result.get("reply", {})
        
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            INSERT OR REPLACE INTO tickets (
                ticket_id, text, sanitized_text, category, cat_conf,
                priority, pri_conf, route_team, auto_reply_allowed,
                draft_reply, draft_status, model_version, latency_ms, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                ticket_id,
                text,
                sanitized_text,
                triage_result.get("category"),
                float(triage_result.get("cat_conf", 0.0)),
                triage_result.get("priority"),
                float(triage_result.get("pri_conf", 0.0)),
                route.get("escalate_to", "Service desk L1"),
                1 if route.get("auto_reply_allowed", False) else 0,
                reply.get("text", ""),
                reply.get("status", "DRAFT"),
                model_version,
                latency_ms,
                now
            ))
            
            # Log audit event
            self._log_audit_internal(
                cursor,
                event_type="ticket_triaged",
                ticket_id=ticket_id,
                actor="system",
                details=json.dumps({
                    "category": triage_result.get("category"),
                    "priority": triage_result.get("priority"),
                    "route": route.get("escalate_to"),
                    "model_version": model_version
                })
            )
            conn.commit()

    def save_feedback(self,
                      ticket_id: str,
                      engineer_id: str,
                      rating: str,
                      action: str,
                      final_category: Optional[str] = None,
                      final_priority: Optional[str] = None,
                      final_runbook_id: Optional[str] = None,
                      override_reason: Optional[str] = None,
                      comments: Optional[str] = None) -> int:
        now = datetime.datetime.utcnow().isoformat()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            INSERT INTO feedback (
                ticket_id, engineer_id, rating, action, final_category,
                final_priority, final_runbook_id, override_reason, comments, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                ticket_id,
                engineer_id,
                rating,
                action,
                final_category,
                final_priority,
                final_runbook_id,
                override_reason,
                comments,
                now
            ))
            feedback_id = cursor.lastrowid
            
            self._log_audit_internal(
                cursor,
                event_type="feedback_submitted",
                ticket_id=ticket_id,
                actor=engineer_id,
                details=json.dumps({
                    "rating": rating,
                    "action": action,
                    "override_reason": override_reason,
                    "final_category": final_category,
                    "final_priority": final_priority
                })
            )
            conn.commit()
            return feedback_id

    def record_shadow_event(self,
                            ticket_id: str,
                            predicted_category: str,
                            actual_category: str,
                            predicted_priority: str,
                            actual_priority: str,
                            security_flagged: bool,
                            actual_security: bool) -> int:
        now = datetime.datetime.utcnow().isoformat()
        
        pri_levels = ["P1", "P2", "P3", "P4"]
        p_idx = pri_levels.index(predicted_priority) if predicted_priority in pri_levels else 3
        a_idx = pri_levels.index(actual_priority) if actual_priority in pri_levels else 3
        pri_within_one = 1 if abs(p_idx - a_idx) <= 1 else 0
        
        cat_agreed = 1 if predicted_category == actual_category else 0
        pred_p1 = 1 if predicted_priority == "P1" else 0
        act_p1 = 1 if actual_priority == "P1" else 0

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            INSERT INTO shadow_logs (
                ticket_id, predicted_category, actual_category,
                predicted_priority, actual_priority, predicted_p1, actual_p1,
                security_flagged, actual_security, category_agreed,
                priority_within_one, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                ticket_id,
                predicted_category,
                actual_category,
                predicted_priority,
                actual_priority,
                pred_p1,
                act_p1,
                1 if security_flagged else 0,
                1 if actual_security else 0,
                cat_agreed,
                pri_within_one,
                now
            ))
            log_id = cursor.lastrowid
            conn.commit()
            return log_id

    def _log_audit_internal(self, cursor: sqlite3.Cursor, event_type: str, ticket_id: str, actor: str, details: str):
        now = datetime.datetime.utcnow().isoformat()
        cursor.execute("""
        INSERT INTO audit_log (event_type, ticket_id, actor, details, created_at)
        VALUES (?, ?, ?, ?, ?)
        """, (event_type, ticket_id, actor, details, now))

    def log_audit_event(self, event_type: str, actor: str, details: str, ticket_id: Optional[str] = None):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            self._log_audit_internal(cursor, event_type, ticket_id or "system", actor, details)
            conn.commit()

    def get_audit_logs(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,))
            return [dict(row) for row in cursor.fetchall()]

    def get_pilot_metrics(self) -> Dict[str, Any]:
        """Calculates live pilot scorecard metrics for dashboards and weekly reviews."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            # Total triaged tickets
            cursor.execute("SELECT COUNT(*) FROM tickets")
            total_triaged = cursor.fetchone()[0]

            # Average latency
            cursor.execute("SELECT AVG(latency_ms) FROM tickets")
            avg_latency = cursor.fetchone()[0] or 0.0

            # Feedback metrics
            cursor.execute("SELECT COUNT(*) FROM feedback")
            total_feedback = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM feedback WHERE action = 'accepted'")
            accepted_count = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM feedback WHERE action = 'overridden'")
            overridden_count = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM feedback WHERE rating = 'thumbs_up'")
            thumbs_up_count = cursor.fetchone()[0]

            acceptance_rate = (accepted_count / total_feedback) if total_feedback > 0 else 0.0
            override_rate = (overridden_count / total_feedback) if total_feedback > 0 else 0.0
            satisfaction_rate = (thumbs_up_count / total_feedback) if total_feedback > 0 else 0.0

            # Shadow mode metrics
            cursor.execute("SELECT COUNT(*), SUM(category_agreed), SUM(priority_within_one) FROM shadow_logs")
            shadow_row = cursor.fetchone()
            shadow_total = shadow_row[0] or 0
            shadow_cat_agreed = shadow_row[1] or 0
            shadow_pri_within_one = shadow_row[2] or 0
            
            shadow_agreement_rate = (shadow_cat_agreed / shadow_total) if shadow_total > 0 else 0.0
            shadow_pri_rate = (shadow_pri_within_one / shadow_total) if shadow_total > 0 else 0.0

            # P1 recall in shadow mode
            cursor.execute("SELECT COUNT(*) FROM shadow_logs WHERE actual_p1 = 1")
            actual_p1_count = cursor.fetchone()[0]
            cursor.execute("SELECT COUNT(*) FROM shadow_logs WHERE actual_p1 = 1 AND predicted_p1 = 1")
            caught_p1_count = cursor.fetchone()[0]
            p1_recall = (caught_p1_count / actual_p1_count) if actual_p1_count > 0 else 1.0

            # Category distribution
            cursor.execute("SELECT category, COUNT(*) FROM tickets GROUP BY category")
            category_counts = {row[0]: row[1] for row in cursor.fetchall()}

            # Override reasons breakdown
            cursor.execute("SELECT override_reason, COUNT(*) FROM feedback WHERE override_reason IS NOT NULL GROUP BY override_reason")
            override_reasons = {row[0]: row[1] for row in cursor.fetchall()}

            return {
                "total_triaged": total_triaged,
                "avg_latency_ms": round(avg_latency, 2),
                "total_feedback": total_feedback,
                "acceptance_rate": round(acceptance_rate, 3),
                "override_rate": round(override_rate, 3),
                "satisfaction_rate": round(satisfaction_rate, 3),
                "shadow_total": shadow_total,
                "shadow_agreement_rate": round(shadow_agreement_rate, 3),
                "shadow_priority_rate": round(shadow_pri_rate, 3),
                "shadow_p1_recall": round(p1_recall, 3),
                "category_distribution": category_counts,
                "override_reasons": override_reasons
            }
