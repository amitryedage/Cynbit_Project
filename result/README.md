# Project Output and Evaluation Results

This directory contains the consolidated evaluation outputs, benchmark metrics, confusion matrices, and formal scorecard records for the Cybit AI Service-Desk Copilot suite.

---

## Output Manifest

| File | Type | Description |
|---|---|---|
| `results.json` | JSON Data | Comprehensive evaluation results across Synthetic Holdout (n=600), Hand-written Dev Set (n=40), and Blind Test Set (n=30). Includes accuracy, macro F1, Wilson 95% confidence intervals, P1 recall, and security miss rates. |
| `benchmark_results.json` | JSON Data | Comparative retrieval and classifier benchmark comparing Sparse TF-IDF, Dense Semantic Projector, and Hybrid retrieval across all datasets. |
| `eval_output.txt` | Text Log | Detailed classification reports, precision/recall/F1 per category, and misclassification error analysis logs. |
| `confusion_matrix_blind_test_set.png` | Image (PNG) | 10x10 category confusion matrix visualization evaluated on the 30 hand-written blind test tickets. |
| `confusion_matrix_hand_written_dev_set.png` | Image (PNG) | 10x10 category confusion matrix visualization evaluated on the 40 hand-written development tickets. |
| `pilot_scorecard_report.md` | Markdown Report | Formal executive pilot scorecard evaluating the 8 Go/No-Go rollout gates defined in PRD Section 10 and Section 11. |

---

## Summary of Key Results

- **Blind Set Category Accuracy:** 83.3% (Keyword Baseline: 50.0%)
- **P1 Major Outage Recall:** 80.0% (Recall-first rule achieves 100% on safety routing)
- **Security Incident Miss Rate:** 0.0% (Zero confirmed incidents missed)
- **Hybrid Runbook Hit@3:** 86.7% (vs 56.7% sparse TF-IDF baseline)
- **PII Scrubbing Pass Rate:** 100% across emails, UK phone numbers, IP/MAC addresses, credentials, and names.
