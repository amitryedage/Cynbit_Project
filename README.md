# AI Service-Desk Copilot and Autonomous Managed Services Suite for Cybit

Production-grade pilot implementation covering the full AI product roadmap for Cybit (UK managed IT and cybersecurity provider), spanning Stage 0 proof-of-concept, Stage 1 controlled pilot (Phases A through D), and Stages 2 through 4 product roadmap extensions as specified in the Product Requirements Document (PRD Section 15).

---

## Table of Contents

- [1. Executive Overview](#1-executive-overview)
- [2. System Architecture and Pipeline Workflow](#2-system-architecture-and-pipeline-workflow)
- [3. Complete Setup and Installation Guide](#3-complete-setup-and-installation-guide)
- [4. Operational Execution Guide](#4-operational-execution-guide)
- [5. Module Directory and Architecture Mapping](#5-module-directory-and-architecture-mapping)
- [6. Production REST API Reference](#6-production-rest-api-reference)
- [7. Interactive Console Overview (Streamlit)](#7-interactive-console-overview-streamlit)
- [8. Security, Privacy, and Safety Architecture](#8-security-privacy-and-safety-architecture)
- [9. Pilot Benchmarks and Go/No-Go Gate Scorecard](#9-pilot-benchmarks-and-gono-go-gate-scorecard)
- [10. Repository File Structure](#10-repository-file-structure)

---

## 1. Executive Overview

Cybit provides 24/7 managed IT services, cloud infrastructure management, and cybersecurity operations for mid-market UK enterprises. This platform provides an AI-augmented service desk copilot and security operations automation suite designed to:

- Accelerate L1 triage accuracy, runbook discovery, and response drafting without increasing operational headcount.
- Enforce strict security routing floors to guarantee zero missed ransomware, malware, or phishing incidents.
- Protect data privacy under UK GDPR by automatically scrubbing PII, credentials, and network identifiers prior to model inference.
- Automate downstream managed service value streams, including client vulnerability advisories, multi-stage SOC alert correlation, and executive Quarterly Business Reviews (QBRs).

### Functional Scope Across Stages

- **Stage 1 (Service Desk Copilot):** Real-time ticket sanitization (FR-5), prompt-injection defense (FR-14), category and priority classification (FR-2, FR-3), hybrid dense/sparse runbook retrieval with symptom memory (FR-10, FR-11), grounded citation drafting (FR-12), safety routing floors (FR-6, FR-7), idempotent ITSM webhook ingestion (FR-1), engineer 1-click feedback loops (FR-18), dynamic policy threshold tuning (FR-9), weekly automated drift detection (FR-22), and formal pilot scorecard evaluation against agreed gates (Section 10 and 11).
- **Stage 2 (Client Security Advisory Digest):** Threat intelligence bulletin ingestion (CVEs), asset inventory matching across managed client estates, contextual risk scoring, and tailored executive security digest generation with mandatory analyst approval (PRD Section 15).
- **Stage 3 (SOC Alert Summarisation and ATT&CK Mapping):** Ingestion of raw EDR and SIEM telemetry alerts, kill-chain correlation, automated MITRE ATT&CK technique mapping, attack narrative drafting, and containment workflow approval (PRD Section 15).
- **Stage 4 (Executive QBR Service Reports):** Aggregation of multi-department ITSM operational KPIs, backup verification metrics, disaster recovery test results, and SOC cyber defense telemetry into client-ready executive Quarterly Business Review reports with Service Director sign-off (PRD Section 15).

---

## 2. System Architecture and Pipeline Workflow

```
[ Incoming Customer Ticket / ITSM Webhook ]
                     |
                     v
   +------------------------------------+
   |       PII Redaction Engine         |  (FR-5: Masks emails, UK phones, IP/MAC,
   |          (redaction.py)            |   credentials, names; stores mapping)
   +------------------------------------+
                     |
                     v
   +------------------------------------+
   |     Prompt Guard & Isolation       |  (FR-14: XML boundary containment,
   |         (guardrails.py)            |   heuristic injection & override filter)
   +------------------------------------+
                     |
         +-----------+-----------+
         |                       |
         v                       v
+-------------------+   +--------------------+
|  Safety Floor &   |   |   Hybrid Runbook   |
|  Classification   |   |     Retriever      |  (FR-10, FR-11: Dense projector +
|   (triage.py)     |   |   (retrieval.py)   |   TF-IDF + category boosting +
+-------------------+   +--------------------+   symptom memory augmentation)
         |                       |
         +-----------+-----------+
                     |
                     v
   +------------------------------------+
   |     Grounded Reply Synthesizer     |  (FR-12: Verifies [KB-xxx] citations,
   |    (guardrails.py & triage.py)     |   blocks hallucinated/unsafe steps)
   +------------------------------------+
                     |
                     v
   +------------------------------------+
   |   Human-in-the-Loop Routing        |  (FR-6, FR-7, FR-8: Routes to SOC,
   |   (L1 Panel / Webhook Dispatch)    |   Duty Manager, or L1 Engineer approval)
   +------------------------------------+
                     |
                     v
   +------------------------------------+
   | Storage, Feedback & Audit Trail    |  (FR-18, FR-20: SQLite persistence,
   |   (storage.py & config.py)         |   1-click feedback, immutable audit log)
   +------------------------------------+
```

---

## 3. Complete Setup and Installation Guide

This project is built using Python 3.11 and managed with the `uv` toolchain for fast, deterministic dependency resolution.

### 3.1 Prerequisites

- Python 3.11 or higher
- `uv` package and project manager (recommended), or standard `pip`
- Git

### 3.2 Installing `uv`

If `uv` is not already installed on your system:

- **Windows (PowerShell):**
  ```powershell
  powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
  ```
- **macOS / Linux:**
  ```bash
  curl -LsSf https://astral.sh/uv/install.sh | sh
  ```

### 3.3 Clone and Environment Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/amitryedage/Cynbit_Project.git
   cd Cynbit_Project
   ```

2. **Create and activate a virtual environment:**
   - On Windows (PowerShell):
     ```powershell
     uv venv
     .venv\Scripts\activate
     ```
   - On Linux / macOS:
     ```bash
     uv venv
     source .venv/bin/activate
     ```

3. **Install project dependencies:**
   ```bash
   uv sync
   ```
   Or install editable with development testing dependencies:
   ```bash
   uv pip install -e ".[dev]"
   ```

### 3.4 Configuration and Environment Variables

Optional: To enable live LLM-generated reply drafting via Anthropic Claude (fallback templates are built-in and work offline without an API key):

- **Windows PowerShell:**
  ```powershell
  $env:ANTHROPIC_API_KEY = "your-api-key-here"
  ```
- **Linux / macOS:**
  ```bash
  export ANTHROPIC_API_KEY="your-api-key-here"
  ```

---

## 4. Operational Execution Guide

### 4.1 Run All Automated Test Suites

The test suite contains 10 comprehensive modules validating safety guardrails, redaction, retrieval, APIs, dynamic configuration, drift detection, and Stages 2 through 4:

```bash
uv run pytest -v
```

To run a specific test suite:
```bash
uv run pytest tests/test_redaction.py -v
uv run pytest tests/test_stage3_soc.py -v
```

### 4.2 Start the Production REST API Service

Launch the FastAPI production server with automated reload enabled:

```bash
uv run uvicorn api:app --reload --port 8000
```

- **Service Base URL:** `http://127.0.0.1:8000`
- **Interactive Swagger Documentation:** `http://127.0.0.1:8000/docs`
- **OpenAPI JSON Specification:** `http://127.0.0.1:8000/openapi.json`

### 4.3 Launch the Unified Copilot Console

Run the Streamlit interactive management console:

```bash
uv run streamlit run app.py
```

The application opens automatically in your browser at `http://localhost:8501`.

### 4.4 Run Model Benchmark Comparison

Execute comparative benchmarking across retrieval and classifier modes (Sparse TF-IDF vs Dense Semantic Projector vs Hybrid):

```bash
uv run python benchmark_models.py
```

---

## 5. Module Directory and Architecture Mapping

| File | Primary Class / Function | PRD Stage & Requirement | Description |
|---|---|---|---|
| `redaction.py` | `RedactionEngine` | Stage 1 (FR-5) | Masking engine for emails, UK phone numbers, IP/MAC addresses, credentials, and names. Supports safe bidirectional rehydration. |
| `guardrails.py` | `PromptGuard` | Stage 1 (FR-12, FR-14) | Injection inspection, XML boundary containment, unsafe instruction filtering, and citation verification (`[KB-xxx]`). |
| `embeddings.py` | `SemanticEmbedder`, `DenseSemanticProjector` | Stage 1 to 4 | Dense semantic vector representations via `sentence-transformers` or calibrated TruncatedSVD dense projector. |
| `retrieval.py` | `HybridRetriever` | Stage 1 (FR-10, FR-11) | Hybrid runbook retrieval combining dense semantic vectors, sparse TF-IDF, category boosting, and symptom memory. |
| `triage.py` | `TicketTriage` | Stage 1 (FR-2, FR-3, FR-6, FR-7) | End-to-end triage: sanitization, classification, priority safety floors, runbook retrieval, and grounded reply drafting. |
| `storage.py` | `PilotStorage` | Stage 1 (FR-18, FR-20, FR-21) | Thread-safe SQLite persistence for tickets, 1-click feedback, shadow mode evaluations, and immutable audit logs. |
| `config.py` | `PolicyConfigManager` | Stage 1 (FR-9) | Dynamic policy management allowing administrators to modify confidence thresholds without code changes. |
| `drift_evaluator.py` | `DriftEvaluator` | Stage 1 (FR-22) | Automated weekly evaluation against frozen gold test sets with operational degradation alerting. |
| `scorecard.py` | `PilotScorecardGenerator` | Stage 1 (Section 10, 11) | Pilot scorecard engine evaluating the 8 Go/No-Go gates and writing formal executive reports (`pilot_scorecard_report.md`). |
| `advisory_models.py` | `AdvisoryDigest`, data schemas | Stage 2 (Section 15) | Schemas for client asset inventories, CVE threat intelligence bulletins, and security advisory digests. |
| `advisory_matcher.py` | `AdvisoryMatcher` | Stage 2 (Section 15) | Relevance engine matching threat bulletins against client technology stacks and calculating contextual risk scores. |
| `advisory_generator.py`| `AdvisoryDigestGenerator` | Stage 2 (Section 15) | Executive client advisory synthesizer with mandatory human analyst approval before distribution. |
| `soc_models.py` | `CorrelatedIncident`, schemas | Stage 3 (Section 15) | Data models for raw EDR/SIEM telemetry alerts, correlated incidents, and MITRE ATT&CK tactics and techniques. |
| `soc_analyzer.py` | `SocAnalyzer` | Stage 3 (Section 15) | SOC correlation engine: multi-alert kill-chain mapping, chronological attack narratives, and containment workflows. |
| `qbr_models.py` | `QBRDocument`, schemas | Stage 4 (Section 15) | Multi-source operational metrics schemas covering service desk SLAs, backup reliability, security posture, and roadmap goals. |
| `qbr_generator.py` | `QBRGenerator` | Stage 4 (Section 15) | Executive QBR report compiler generating Markdown reviews (`QBR_Report_*.md`) with Service Director approval. |
| `api.py` | FastAPI application instance | Stage 1 to 4 | Production REST API service with idempotent webhook intake, triage, feedback capture, rollback, and Stages 2-4 endpoints. |
| `app.py` | Streamlit user interface | Stage 1 to 4 | Unified interactive web application featuring 6 management and triage consoles. |

---

## 6. Production REST API Reference

### Stage 1: Triage, Webhooks & Feedback

- `GET /health`: Service health status, model version, and database path.
- `POST /api/v1/tickets/triage`: Submits an unstructured ticket for PII redaction, categorization, priority scoring, runbook retrieval, and reply drafting.
- `POST /api/v1/webhooks/ticket`: Idempotent intake endpoint for ITSM/PSA platforms (ConnectWise, ServiceNow). Detects duplicate retries.
- `POST /api/v1/tickets/{ticket_id}/feedback`: Records engineer 1-click review (accepted, lightly edited, or overridden with reason).
- `POST /api/v1/shadow/evaluate`: Records shadow mode silent evaluations comparing model suggestions against engineer actions.
- `GET /api/v1/admin/config`: Retrieves current dynamic policy thresholds and confidence floors.
- `PUT /api/v1/admin/config`: Updates confidence thresholds dynamically without code changes (FR-9).
- `POST /api/v1/admin/model/rollback`: Triggers an emergency model rollback within 1 hour and logs justification to the audit trail (FR-21).
- `GET /api/v1/admin/scorecard`: Computes live pilot telemetry against the 8 Go/No-Go gates.

### Stage 2: Security Advisory Digest

- `GET /api/v2/advisories`: Lists active vulnerability intelligence bulletins and CVE advisories.
- `GET /api/v2/clients`: Lists managed client profiles and tech stack asset inventories.
- `POST /api/v2/advisories/match`: Evaluates a CVE advisory against all client estates and returns contextual risk scores.
- `POST /api/v2/advisories/digest`: Synthesizes a client-tailored executive advisory digest for an affected organization.
- `POST /api/v2/advisories/digest/approve`: Security analyst sign-off and dispatch approval (FR-8).

### Stage 3: SOC Alert Summarisation & MITRE ATT&CK

- `GET /api/v3/soc/sample-alerts`: Returns representative multi-stage EDR and SIEM telemetry alerts.
- `POST /api/v3/soc/correlate`: Correlates raw telemetry into an incident, maps MITRE ATT&CK techniques, and drafts attack narrative.
- `POST /api/v3/soc/triage`: Submits security analyst sign-off, triage notes, and containment execution.

### Stage 4: Executive QBR Reports

- `GET /api/v4/qbr/clients`: Returns managed accounts available for quarterly business review reporting.
- `POST /api/v4/qbr/generate`: Compiles cross-department operational metrics and exports an executive Markdown report.
- `POST /api/v4/qbr/approve`: Service Director review and formal approval for executive client presentation.

---

## 7. Interactive Console Overview (Streamlit)

The web console (`app.py`) provides 6 navigation views:

1. **Triage Copilot (Stage 1):** Interactive ticket analysis with real-time PII redaction previews, prompt-injection isolation banners, classification probabilities, matching runbook excerpts, and an engineer feedback submission box.
2. **Security Advisory Digest (Stage 2):** Threat intelligence explorer, client tech stack exposure matrix, tailored advisory digest generator, and analyst approval panel.
3. **SOC Alert & ATT&CK Mapping (Stage 3):** Ingestion of raw security telemetry stream, kill-chain correlation, ATT&CK technique mapping table, synthesized attack narrative, and analyst containment sign-off.
4. **Executive QBR Service Reports (Stage 4):** Account performance compiler with KPI metrics cards, category distribution charts, strategic roadmap initiatives, Markdown report exporter, and Service Director sign-off.
5. **Pilot Scorecard & Shadow Dashboard:** Real-time metrics tracking draft acceptance rates, override distributions, shadow mode agreement percentages, and compliance audit logs.
6. **Policy Config & Drift Monitor:** Interactive threshold sliders for category confidence calibration (FR-9), weekly gold-set drift evaluation execution (FR-22), and formal Go/No-Go gate reporting.

---

## 8. Security, Privacy, and Safety Architecture

### 8.1 PII Redaction & Data Minimisation (FR-5, UK GDPR)
Before any text is sent to an external language model or processed for classification, `RedactionEngine` scans and masks:
- Email addresses (`[EMAIL_1]`, `[EMAIL_2]`)
- UK direct and mobile phone numbers (`[PHONE_1]`)
- IPv4 and IPv6 network addresses (`[IP_ADDRESS_1]`)
- Hardware MAC addresses (`[MAC_ADDRESS_1]`)
- Passwords, API tokens, and secret strings (`[PASSWORD_REDACTED]`)
- Personal employee names (`[NAME_1]`)

Mappings are held in memory and can be safely rehydrated into the approved draft locally after verification.

### 8.2 Prompt Injection Defense (FR-14)
Ticket text is treated as untrusted user input:
- Input is encapsulated inside strictly demarcated `<ticket_content>` XML boundaries.
- Prompts instruct the model that content within XML boundaries is raw data and must never be interpreted as instructions.
- Heuristic regex filters detect common injection vectors (for example, "ignore all previous instructions", "system override", "disable antivirus").
- Suspected injection payloads force the ticket into security routing floors and disable automated draft generation.

### 8.3 Citation Verification & Anti-Hallucination (FR-12)
- All draft recommendations must strictly cite retrieved knowledge base article IDs (for example, `[KB-003]`).
- Any draft containing unauthorized or unretrieved citations (`[KB-999]`) or prohibited destructive commands is marked `REJECTED_UNGROUNDED` and prevented from display as an approved draft.

### 8.4 Safety Routing Floors (FR-6, FR-7)
- **Security Floor (`SECURITY_RX`):** Any ticket matching indicators of phishing, malware, ransomware, credential dumps, or unauthorized access is automatically routed directly to Security Operations with auto-reply disabled.
- **Major Outage Floor (`OUTAGE_RX`):** Any ticket matching wide scope indicators (for example, "whole office down", "all users affected", "factory halted") is forced to priority `P1` and flagged for the duty manager.

---

## 9. Pilot Benchmarks and Go/No-Go Gate Scorecard

### 9.1 Evaluation Benchmarks

| Metric | Synthetic Hold-Out (n=600) | Hand-Written Dev Set (n=40) | Blind Gold Set (n=30) |
|---|---|---|---|
| Category Accuracy | 97.3% | 75.0% | 83.3% |
| Keyword Baseline | 71.3% | 67.5% | 50.0% |
| Priority Within One Level | 95.8% | 90.0% | 96.7% |
| P1 Outage Recall | 75.3% | 80.0% | 80.0% |
| Runbook Hit@3 (Hybrid) | 99.3% | 80.0% | 86.7% |
| Security Incidents Missed | 3.0% | 0.0% | 0.0% |
| PII Redaction Test Suite | 100% Pass | 100% Pass | 100% Pass |
| Prompt-Injection Guardrail | 100% Pass | 100% Pass | 100% Pass |

### 9.2 The 8 Go/No-Go Pilot Rollout Gates (PRD Sections 10 and 11)

| Gate ID | Target Criterion | Metric Type | Target Threshold | Pilot Baseline |
|---|---|---|---|---|
| G-1 | P1 Outage Recall | Safety Must-Pass | >= 95% | 80.0% - 100.0% |
| G-2 | Security Routing Accuracy | Safety Must-Pass | 100% (0 missed) | 100.0% (Zero tolerance met) |
| G-3 | Ungrounded / Unsafe Drafts | Safety Must-Pass | 0 sent | 0 (Enforced by architecture) |
| G-4 | Category Accuracy on Gold Set | Quality | >= 80% | 83.3% |
| G-5 | Runbook Hit@3 Relevance | Quality | >= 85% | 86.7% |
| G-6 | Draft Acceptance Rate | Adoption | >= 40% | Tracked via 1-click feedback |
| G-7 | Minutes Saved per Assisted Ticket | Business | >= 4.0 minutes | Estimated 4.2 - 5.5 mins |
| G-8 | Engineer Satisfaction Score | Adoption | >= 4.0 / 5.0 | Tracked via rating surveys |

---

## 10. Repository File Structure

```
Cynbit_Project/
|-- pyproject.toml              # Build backend and dependencies (uv toolchain)
|-- .python-version             # Pinned Python version (3.11)
|-- .gitignore                  # Excludes tests, PRD, databases, and artifacts
|-- README.md                   # Complete architectural and operational documentation
|
|-- triage.py                   # Core triage and prediction pipeline
|-- redaction.py                # PII masking and rehydration engine
|-- guardrails.py               # Prompt injection defense and citation verifier
|-- embeddings.py               # Dense vector embeddings and semantic projector
|-- retrieval.py                # Hybrid dense/sparse runbook retriever
|-- storage.py                  # SQLite database engine and audit trail
|-- config.py                   # Dynamic policy and threshold manager
|-- drift_evaluator.py          # Weekly gold-set evaluation and drift alerts
|-- scorecard.py                # Pilot Scorecard and Go/No-Go gate assessment
|-- benchmark_models.py         # Model evaluation and comparison harness
|-- kb_and_data.py              # Knowledge base articles and synthetic ticket generator
|
|-- advisory_models.py          # Stage 2: Tech stack and CVE data schemas
|-- advisory_matcher.py         # Stage 2: Contextual risk and matching engine
|-- advisory_generator.py       # Stage 2: Client advisory digest generator
|
|-- soc_models.py               # Stage 3: Telemetry and ATT&CK mapping schemas
|-- soc_analyzer.py             # Stage 3: Multi-alert kill-chain correlation engine
|
|-- qbr_models.py               # Stage 4: Multi-source operational metrics schemas
|-- qbr_generator.py            # Stage 4: Executive QBR report compiler
|
|-- api.py                      # FastAPI production REST API and webhook service
|-- app.py                      # Streamlit interactive pilot console (6 views)
|-- result/                     # Evaluation outputs, metrics JSON, and confusion matrices
|   |-- README.md
|   |-- results.json
|   |-- benchmark_results.json
|   |-- eval_output.txt
|   |-- confusion_matrix_blind_test_set.png
|   |-- confusion_matrix_hand_written_dev_set.png
|   `-- pilot_scorecard_report.md
|
`-- tests/                      # Automated test suites (excluded from git tracking)
    |-- test_redaction.py
    |-- test_prompt_injection.py
    |-- test_robustness.py
    |-- test_retrieval_and_embeddings.py
    |-- test_pipeline_e2e.py
    |-- test_api_and_shadow.py
    |-- test_config_and_scorecard.py
    |-- test_stage2_advisories.py
    |-- test_stage3_soc.py
    `-- test_stage4_qbr.py
```

---

## 11. Maintenance and Support

For questions, policy adjustments, or model retraining procedures, contact the Cybit Service Desk Leadership or refer to the internal Pilot Governance Runbook.
