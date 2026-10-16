"""
Production API Service for Cybit Service-Desk Copilot (Stage 1 Pilot).
Provides REST endpoints and webhooks for:
- Automated ticket triage, priority scoring, runbook retrieval, and grounded reply drafting
- ITSM/PSA ticketing tool webhook ingestion with duplicate detection (FR-1)
- Engineer 1-click feedback capture and override tracking (FR-18)
- Shadow mode evaluation records (PRD Phase 2)
- Live pilot scorecard metrics and audit logging (FR-19, FR-20, FR-21)
"""
from typing import Dict, List, Any, Optional
import time
import uuid
from pydantic import BaseModel, Field
from fastapi import FastAPI, HTTPException, status
from triage import TicketTriage
from kb_and_data import generate
from storage import PilotStorage

# Initialize FastAPI application
app = FastAPI(
    title="Cybit Service-Desk Copilot API",
    description="Automated triage, runbook retrieval, and safety copilot for Cybit Service Desk",
    version="1.0.0"
)

# Global storage and model singleton
storage = PilotStorage()
CURRENT_MODEL_VERSION = "v1.0.0"
PREVIOUS_MODEL_VERSION = "v0.9.0-poc"

# Lazy-loaded model instance
_model_instance: Optional[TicketTriage] = None

def get_model() -> TicketTriage:
    global _model_instance
    if _model_instance is None:
        train_corpus = generate(3000, seed=42)
        _model_instance = TicketTriage().fit(train_corpus)
    return _model_instance


# -----------------------------------------------------------------------------
# Request & Response Schemas
# -----------------------------------------------------------------------------
class TicketTriageRequest(BaseModel):
    ticket_id: Optional[str] = Field(default=None, description="External ticketing tool ID (e.g. CYB-10842)")
    text: str = Field(..., min_length=3, description="Unstructured customer ticket text")
    retrieval_mode: str = Field(default="hybrid", description="Runbook retrieval mode: hybrid, dense, or sparse")
    use_llm: bool = Field(default=False, description="Whether to call external LLM for reply drafting")

class WebhookPayload(BaseModel):
    ticket_id: str = Field(..., description="Unique ticket ID from ticketing system")
    summary: Optional[str] = Field(default="", description="Ticket subject line")
    description: str = Field(..., description="Detailed ticket description")
    source_tool: str = Field(default="ConnectWise", description="Originating ITSM/PSA platform")

class FeedbackRequest(BaseModel):
    engineer_id: str = Field(..., description="ID or username of the reviewing engineer")
    rating: str = Field(..., description="Rating: thumbs_up or thumbs_down")
    action: str = Field(..., description="Action: accepted, lightly_edited, or overridden")
    final_category: Optional[str] = Field(default=None, description="Engineer's confirmed category")
    final_priority: Optional[str] = Field(default=None, description="Engineer's confirmed priority")
    final_runbook_id: Optional[str] = Field(default=None, description="Runbook ID selected by engineer")
    override_reason: Optional[str] = Field(default=None, description="Reason if suggestion was changed")
    comments: Optional[str] = Field(default=None, description="Optional engineering notes")

class ShadowEvaluationRequest(BaseModel):
    ticket_id: str = Field(..., description="Ticket ID evaluated in shadow mode")
    actual_category: str = Field(..., description="Category assigned by human engineer")
    actual_priority: str = Field(..., description="Priority assigned by human engineer")
    actual_security: bool = Field(default=False, description="Whether ticket was a confirmed security incident")

class RollbackRequest(BaseModel):
    target_version: str = Field(default="v0.9.0-poc", description="Version to roll back to")
    reason: str = Field(..., description="Required operational justification for rollback")
    operator: str = Field(..., description="Username of authorising lead engineer")


# -----------------------------------------------------------------------------
# API Endpoints
# -----------------------------------------------------------------------------
@app.get("/health", status_code=status.HTTP_200_OK)
def health_check():
    return {
        "status": "healthy",
        "service": "cybit-copilot-service",
        "model_version": CURRENT_MODEL_VERSION,
        "database": storage.db_path
    }

@app.post("/api/v1/tickets/triage")
def triage_ticket(req: TicketTriageRequest):
    ticket_id = req.ticket_id or f"CYB-{uuid.uuid4().hex[:8].upper()}"
    model = get_model()
    
    start_time = time.perf_counter()
    pred = model.predict(req.text, mode=req.retrieval_mode)
    pred["route"] = model.route(pred)
    pred["reply"] = model.draft_reply(req.text, pred, use_llm=req.use_llm)
    latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
    
    sanitized_text = pred.get("reply", {}).get("redaction", {}).get("sanitized_text", req.text)
    
    # Persist prediction to pilot database
    storage.save_ticket(
        ticket_id=ticket_id,
        text=req.text,
        sanitized_text=sanitized_text,
        triage_result=pred,
        model_version=CURRENT_MODEL_VERSION,
        latency_ms=latency_ms
    )
    
    return {
        "ticket_id": ticket_id,
        "model_version": CURRENT_MODEL_VERSION,
        "latency_ms": latency_ms,
        "result": pred
    }

@app.post("/api/v1/webhooks/ticket", status_code=status.HTTP_200_OK)
def ingest_ticket_webhook(payload: WebhookPayload):
    """
    Webhook intake for ITSM/PSA ticketing platforms (ConnectWise, HaloITSM, ServiceNow).
    Includes idempotency check (FR-1) to avoid duplicate reprocessing on webhook retries.
    """
    full_text = f"{payload.summary}\n{payload.description}".strip() if payload.summary else payload.description
    
    # Idempotency check: verify if ticket was already triaged
    with storage._get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM tickets WHERE ticket_id = ?", (payload.ticket_id,))
        existing = cursor.fetchone()
        if existing:
            return {
                "status": "already_processed",
                "ticket_id": payload.ticket_id,
                "category": existing["category"],
                "priority": existing["priority"],
                "notice": "Idempotent response: ticket was previously processed."
            }
            
    # Process fresh ticket
    return triage_ticket(TicketTriageRequest(ticket_id=payload.ticket_id, text=full_text))

@app.post("/api/v1/tickets/{ticket_id}/feedback", status_code=status.HTTP_201_CREATED)
def submit_feedback(ticket_id: str, fb: FeedbackRequest):
    """
    Captures engineer 1-click feedback (accept, override, thumbs up/down, reasons) (FR-18).
    """
    feedback_id = storage.save_feedback(
        ticket_id=ticket_id,
        engineer_id=fb.engineer_id,
        rating=fb.rating,
        action=fb.action,
        final_category=fb.final_category,
        final_priority=fb.final_priority,
        final_runbook_id=fb.final_runbook_id,
        override_reason=fb.override_reason,
        comments=fb.comments
    )
    return {
        "status": "recorded",
        "feedback_id": feedback_id,
        "ticket_id": ticket_id
    }

@app.post("/api/v1/shadow/evaluate")
def record_shadow_evaluation(ev: ShadowEvaluationRequest):
    """
    Records shadow mode outcome comparing silent model prediction with engineer's final action.
    """
    with storage._get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT category, priority, flags FROM tickets WHERE ticket_id = ?", (ev.ticket_id,))
        ticket_row = cursor.fetchone()
        if not ticket_row:
            raise HTTPException(status_code=404, detail=f"Ticket ID {ev.ticket_id} not found in database")
            
        pred_cat = ticket_row["category"]
        pred_pri = ticket_row["priority"]
        flags = ticket_row["flags"] or ""
        sec_flagged = (pred_cat == "security_incident") or ("security" in flags)

    log_id = storage.record_shadow_event(
        ticket_id=ev.ticket_id,
        predicted_category=pred_cat,
        actual_category=ev.actual_category,
        predicted_priority=pred_pri,
        actual_priority=ev.actual_priority,
        security_flagged=sec_flagged,
        actual_security=ev.actual_security
    )
    
    return {
        "status": "recorded",
        "shadow_log_id": log_id,
        "category_agreed": pred_cat == ev.actual_category,
        "priority_match": pred_pri == ev.actual_priority
    }

@app.get("/api/v1/metrics/pilot")
def get_pilot_metrics():
    """
    Returns live pilot scorecard metrics: acceptance rate, override rate, shadow agreement (FR-19).
    """
    return storage.get_pilot_metrics()

@app.get("/api/v1/audit/logs")
def get_audit_trail(limit: int = 50):
    """
    Returns immutable audit log for compliance and operational tracking (FR-20).
    """
    return storage.get_audit_logs(limit=limit)

@app.post("/api/v1/admin/model/rollback")
def rollback_model(req: RollbackRequest):
    """
    Model version rollback mechanism with audit trail (FR-21).
    """
    global CURRENT_MODEL_VERSION
    old_version = CURRENT_MODEL_VERSION
    CURRENT_MODEL_VERSION = req.target_version
    
    storage.log_audit_event(
        event_type="model_rollback",
        actor=req.operator,
        details=f"Model rolled back from {old_version} to {req.target_version}. Reason: {req.reason}"
    )
    
    return {
        "status": "rolled_back",
        "previous_version": old_version,
        "current_version": CURRENT_MODEL_VERSION,
        "reason": req.reason,
        "operator": req.operator
    }

# -----------------------------------------------------------------------------
# Phase D: Configuration & Scorecard Endpoints (FR-9, FR-22, Section 10-11)
# -----------------------------------------------------------------------------
from config import PolicyConfigManager
from drift_evaluator import DriftEvaluator
from scorecard import PilotScorecardGenerator

config_manager = PolicyConfigManager(storage=storage)
drift_evaluator = DriftEvaluator(storage=storage, config_mgr=config_manager)
scorecard_generator = PilotScorecardGenerator(storage=storage, evaluator=drift_evaluator)

class ConfigUpdateRequest(BaseModel):
    global_threshold: Optional[float] = None
    category_thresholds: Optional[Dict[str, float]] = None
    actor: str = Field(default="admin", description="Operator updating policy configuration")
    reason: str = Field(..., description="Justification for policy update")

@app.get("/api/v1/admin/config")
def get_policy_config():
    """
    Returns active policy thresholds and routing rules (FR-9).
    """
    return config_manager.load_config()

@app.put("/api/v1/admin/config")
def update_policy_config(req: ConfigUpdateRequest):
    """
    Updates category thresholds without code modifications, logging to audit trail (FR-9).
    """
    updated = config_manager.update_thresholds(
        global_thresh=req.global_threshold,
        category_thresh=req.category_thresholds,
        actor=req.actor,
        reason=req.reason
    )
    return {
        "status": "updated",
        "config": updated
    }

@app.post("/api/v1/admin/evaluate/drift")
def trigger_drift_check():
    """
    Runs automated evaluation on frozen gold set to detect metric degradation (FR-22).
    """
    model = get_model()
    report = drift_evaluator.run_weekly_drift_check(model)
    return report

@app.get("/api/v1/admin/scorecard")
def generate_pilot_scorecard():
    """
    Generates formal Pilot Scorecard Report assessing Go / Extend / Stop gates (PRD Section 10 & 11).
    """
    model = get_model()
    scorecard = scorecard_generator.generate_scorecard(model=model)
    return scorecard

