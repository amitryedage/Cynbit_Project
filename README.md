# AI Service-Desk Ticket Triage Copilot: Stage 1 Pilot for Cybit

Production-grade pilot implementation for the AI Service-Desk Copilot at Cybit (UK managed IT and cybersecurity provider).

What it does: takes a support ticket -> redacts PII and credentials (FR-5) -> inspects for prompt injection and adversarial inputs (FR-14) -> predicts category and priority -> retrieves verified runbooks via hybrid dense/sparse search (FR-10, FR-11) -> drafts a grounded reply with citation verification (FR-12) -> decides human-in-the-loop routing (SOC, duty manager, or L1 approval).

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

# 3. Run all automated test suites
uv run pytest -v

# 4. Run model benchmarking comparison (Sparse vs Dense vs Hybrid)
uv run python benchmark_models.py

# 5. Launch the interactive Copilot Demo
uv run streamlit run app.py
```

Optional LLM-generated replies:
```bash
$env:ANTHROPIC_API_KEY="sk-ant-..."   # PowerShell
# export ANTHROPIC_API_KEY=...       # Bash
```

## System Architecture

| Module | Purpose | PRD Requirement |
|---|---|---|
| redaction.py | PII Redaction Engine: masks emails, UK phone numbers, IP/MAC addresses, credentials, and personal names. Supports safe rehydration. | FR-5 (UK GDPR / DPIA) |
| guardrails.py | Prompt Injection Guard and Grounding Verifier: detects adversarial overrides, enforces XML input containment, and blocks dangerous system directives. | FR-12, FR-14 |
| embeddings.py | Semantic Embedding Engine: dense vector representations via sentence-transformers or calibrated dense semantic projector. | FR-10, FR-11 |
| retrieval.py | Hybrid Runbook Retriever: blends dense semantic vectors with lexical TF-IDF matching and historical symptom memory. | FR-10, FR-11 |
| triage.py | Core pipeline: text sanitization, hybrid classification, heuristic safety floors, runbook retrieval, and grounded reply drafting. | FR-2, FR-3, FR-6, FR-7 |
| benchmark_models.py | Comparative evaluation harness measuring category accuracy, P1 recall, and Hit@K across sparse, dense, and hybrid modes. | FR-19, FR-22 |
| tests/ | Automated test suites: test_redaction.py, test_prompt_injection.py, test_robustness.py, test_retrieval_and_embeddings.py, test_pipeline_e2e.py. | Section 9 |
| app.py | Streamlit pilot interface featuring PII audit views, prompt-injection risk banners, retrieval mode selector, and draft grounding verification. | FR-15 - FR-18 |

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
