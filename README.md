# AI Service-Desk Ticket Triage Copilot: Stage 1 Pilot & Stage 2 Security Advisory for Cybit

Production-grade pilot implementation for the AI Service-Desk Copilot and Security Advisory Digest at Cybit (UK managed IT and cybersecurity provider).

What it does:
- Stage 1: Takes a support ticket -> redacts PII and credentials (FR-5) -> inspects for prompt injection and adversarial inputs (FR-14) -> predicts category and priority -> retrieves verified runbooks via hybrid dense/sparse search (FR-10, FR-11) -> drafts a grounded reply with citation verification (FR-12) -> decides human-in-the-loop routing (SOC, duty manager, or L1 approval) -> records 1-click feedback and shadow mode telemetry (FR-18, FR-19) -> automates weekly drift checks and formal pilot scorecard reporting against agreed gates (FR-9, FR-22, Section 10-11).
- Stage 2: Ingests vulnerability intelligence bulletins (CVEs) -> matches impacted software/hardware against managed client tech stack inventories -> calculates contextual risk scores -> synthesizes client-tailored executive security digests with mandatory analyst sign-off before dispatch (PRD Section 15).

## Setup and Run with uv

We use uv as the fast, modern Python package manager:

```bash
# 1. Create and activate a virtual environment
uv venv
# On Windows PowerShell:
.venv\Scripts\activate
# On Linux/macOS:
# source .venv/bin/activate

# 2. Install dependencies (including dev test tools)
uv pip install -e ".[dev]"

# 3. Run all automated test suites (all 8 test modules)
uv run pytest -v

# 4. Start the Production REST API and Webhook Service (FastAPI)
uv run uvicorn api:app --reload --port 8000

# 5. Launch the Pilot Interface, Advisory Digest, and Governance App
uv run streamlit run app.py

# 6. Run model benchmarking comparison (Sparse vs Dense vs Hybrid)
uv run python benchmark_models.py
```

Optional LLM-generated replies:
```bash
$env:ANTHROPIC_API_KEY="sk-ant-..."   # PowerShell
# export ANTHROPIC_API_KEY=...       # Bash
```

## System Architecture

| Module | Purpose | PRD Stage / Requirement |
|---|---|---|
| redaction.py | PII Redaction Engine: masks emails, UK phone numbers, IP/MAC addresses, credentials, and personal names. Supports safe rehydration. | Stage 1 (FR-5) |
| guardrails.py | Prompt Injection Guard and Grounding Verifier: detects adversarial overrides, enforces XML input containment, and blocks dangerous system directives. | Stage 1 (FR-12, FR-14) |
| embeddings.py | Semantic Embedding Engine: dense vector representations via sentence-transformers or calibrated dense semantic projector. | Stage 1 & 2 (FR-10, FR-11) |
| retrieval.py | Hybrid Runbook Retriever: blends dense semantic vectors with lexical TF-IDF matching and historical symptom memory. | Stage 1 (FR-10, FR-11) |
| triage.py | Core pipeline: text sanitization, hybrid classification, heuristic safety floors, runbook retrieval, and grounded reply drafting. | Stage 1 (FR-2, FR-3, FR-6, FR-7) |
| storage.py | Pilot Storage Engine: SQLite persistent storage for tickets, feedback, shadow evaluations, and immutable audit logs. | Stage 1 (FR-18, FR-19, FR-20, FR-21) |
| config.py | Dynamic Policy & Threshold Configuration: enables adjusting confidence floors without code changes; logs all changes. | Stage 1 (FR-9) |
| drift_evaluator.py | Weekly Automated Evaluation: checks model performance on frozen gold sets and raises operational degradation alerts. | Stage 1 (FR-22) |
| scorecard.py | Formal Pilot Scorecard Generator: evaluates 8 Go/No-Go gates and generates executive Markdown reports. | Stage 1 (Section 10, Section 11) |
| advisory_models.py | Data schemas for client technology stack inventories, CVE threat bulletins, and advisory digests. | Stage 2 (Section 15) |
| advisory_matcher.py | Relevance Matching Engine: matches CVE advisories to client tech stacks and calculates contextual risk scores. | Stage 2 (Section 15) |
| advisory_generator.py | Grounded Client Advisory Digest Generator: synthesizes executive digests with mandatory analyst sign-off. | Stage 2 (Section 15) |
| api.py | Production FastAPI service: REST endpoints, ITSM webhook intake with idempotency check, feedback capture, and Stage 2 APIs. | Stage 1 & 2 (FR-1, FR-8, FR-18, FR-21) |
| benchmark_models.py | Comparative evaluation harness measuring category accuracy, P1 recall, and Hit@K across sparse, dense, and hybrid modes. | Stage 1 (FR-19, FR-22) |
| tests/ | Automated test suites: test_redaction.py, test_prompt_injection.py, test_robustness.py, test_retrieval_and_embeddings.py, test_pipeline_e2e.py, test_api_and_shadow.py, test_config_and_scorecard.py, test_stage2_advisories.py. | Stage 1 & 2 |
| app.py | Streamlit pilot interface featuring Assisted Pilot triage, Stage 2 Security Advisory Digest, live Pilot Scorecard, and Governance. | Stage 1 & 2 |

## Pilot Proof-of-Concept Benchmarks

| Metric | Synthetic Hold-out (n=600) | Hand-written Dev (n=40) | Blind Test (n=30) |
|---|---|---|---|
| Category Accuracy | 97.3% | 75.0% | 83.3% |
| Keyword Baseline | 71.3% | 67.5% | 50.0% |
| P1 Recall | 75.3% | 80.0% | 80.0% |
| KB Hit@3 (Hybrid) | 99.3% | 80.0% | 86.7% |
| Security Miss Rate | 3.0% | 0.0% | 0.0% |
| PII Redaction Test Suite | 100% Pass | 100% Pass | 100% Pass |
| Prompt-Injection Guardrail | 100% Pass | 100% Pass | 100% Pass |
| Hybrid Retrieval Test Suite | 100% Pass | 100% Pass | 100% Pass |
| API and Shadow Test Suite | 100% Pass | 100% Pass | 100% Pass |
| Policy & Scorecard Test Suite | 100% Pass | 100% Pass | 100% Pass |
| Stage 2 Advisory Digest Suite | 100% Pass | 100% Pass | 100% Pass |
