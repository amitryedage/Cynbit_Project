# AI Service-Desk Ticket Triage: PoC for Cybit

Proof of concept for the "Identify an AI Opportunity for Cybit" assessment (AI/ML Engineer Intern).

**What it does:** takes a support ticket → predicts category and priority → retrieves the best knowledge-base (KB) articles →
drafts a reply grounded only in those articles → decides routing (security team, duty manager, or L1 with human approval).

## Run it
```bash
pip install -r requirements.txt
python evaluate.py            # prints metrics, writes results.json + confusion matrices
streamlit run app.py          # interactive demo
export ANTHROPIC_API_KEY=...  # optional: LLM-written replies (otherwise a safe template is used)
```
Or open `Cybit_Ticket_Triage_PoC.ipynb` in Google Colab and run all cells (executed outputs are included).

## Files
| File | Purpose |
|---|---|
| `kb_and_data.py` | 20-article KB, synthetic ticket generator, 40-ticket hand-written dev set |
| `blind_testset.py` | 30 further hand-written tickets, used only for final reporting |
| `triage.py` | Pipeline: TF-IDF (word + char n-gram) logistic regression, hybrid retrieval, safety rules, grounded reply drafting |
| `evaluate.py` | Baselines, accuracy/F1, P1 recall, KB hit-rate, Wilson CIs, confusion matrices |
| `app.py` | Streamlit demo |

## Results (see Technical Approach Report for discussion)
| | Synthetic hold-out (n=600) | Hand-written dev (n=40) | Blind test (n=30) |
|---|---|---|---|
| Category accuracy | 97.3% | 75.0% | 83.3% |
| Keyword baseline | 71.3% | 67.5% | 50.0% |
| P1 recall | 75.3% | 80.0% | 80.0% |
| KB hit@3 (hybrid) | 99.3% | 80.0% | 86.7% |
| Security tickets missed | 3.0% | 0% | 0% |

## Honest limitations
- **All training data is synthetic.** Cybit's real tickets are private. Real-world accuracy is unknown until measured on real data.
- Hand-written sets are small (n=40, n=30) so confidence intervals are wide (e.g. blind-set accuracy 66-93%).
- The dev set was used to design the safety rules. The blind set was run twice (once before fixing a regex escaping bug), never used to design rules.
- Knowledge base is illustrative, not Cybit's real runbooks. Every reply is a draft for human approval.
