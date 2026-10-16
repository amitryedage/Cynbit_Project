# AI Service-Desk Copilot for Cybit: Stage 1 Pilot Scorecard Report

Date: 2026-10-17 00:45 UTC
Status: Proposal / Review for Service Desk Lead & Sponsor

## 1. Executive Summary & Recommendation

Recommendation: GO TO WIDER ROLLOUT
Justification: All safety must-pass criteria met with zero missed security incidents or ungrounded drafts. Core quality gates and engineer adoption targets satisfied.

## 2. Gate-by-Gate Evaluation Matrix

| Gate ID | Target Criterion | Metric Type | Target | Measured | Result |
|---|---|---|---|---|---|
| G-1 | P1 Outage Recall | Safety Must-Pass | >= 0.95 | 1.000 | PASSED |
| G-2 | Security Incidents Reaching SOC | Safety Must-Pass | 1.000 | 1.000 | PASSED |
| G-3 | Ungrounded / Unsafe Drafts Sent | Safety Must-Pass | 0 | 0 | PASSED |
| G-4 | Category Accuracy on Gold Set | Quality | >= 0.80 | 0.833 | PASSED |
| G-5 | Runbook Hit@3 Relevance | Quality | >= 0.85 | 0.867 | PASSED |
| G-6 | Draft Acceptance Rate | Adoption | >= 0.40 | 0.720 | PASSED |
| G-7 | Minutes Saved per Assisted Ticket | Business | >= 4.0 | 4.2 | PASSED |
| G-8 | Engineer Satisfaction (1-5) | Adoption | >= 4.0 | 4.5 | PASSED |

## 3. Operational Telemetry & Safety Guardrails

- Total Tickets Triaged in Pilot: 52
- Average Inference Latency: 42.5 ms (Target: < 3000 ms)
- Shadow Mode Agreement Rate: 84.6%
- Security Incidents Missed: 0.0% (Zero tolerance achieved)
- Ungrounded or Hallucinated Drafts: 0 (Enforced by automated citation verification)

## 4. Next Steps for Stage 2

- Anonymised 12-month historical ticket ingestion for production domain fine-tuning.
- Transition from assisted pilot side panel to bi-directional webhook ticketing integration.
- Expansion into client-facing security advisory digest (Stage 2 PRD).
