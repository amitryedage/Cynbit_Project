
from typing import Dict, List, Any
import json
import numpy as np
from sklearn.metrics import accuracy_score, f1_score
from sklearn.model_selection import train_test_split
from kb_and_data import generate, HAND_TESTSET, KB, PRIORITIES
from blind_testset import BLIND_TESTSET
from triage import TicketTriage, clean

KEYWORDS = {
    "account_access": ["password", "locked", "mfa", "authenticator", "account", "log in", "login"],
    "email_m365": ["outlook", "email", "mailbox", "inbox", "calendar"],
    "network_vpn": ["vpn", "wifi", "wi-fi", "internet", "network", "dns"],
    "hardware": ["laptop", "monitor", "dock", "headset", "keyboard", "mouse", "screen"],
    "software": ["install", "licence", "excel", "office", "application"],
    "security_incident": ["phishing", "malware", "virus", "ransom", "suspicious", "antivirus"],
    "cloud_azure": ["azure", "vm"],
    "backup_storage": ["backup", "restore", "shared drive", "deleted"],
    "printing": ["print", "scan", "copier"],
    "data_bi": ["power bi", "dashboard", "refresh", "report"]
}

def keyword_baseline(text: str) -> str:
    t = clean(text)
    best, bs = "software", 0
    for c, kws in KEYWORDS.items():
        s = sum(k in t for k in kws)
        if s > bs:
            best, bs = c, s
    return best

def pri_within_one(y, p):
    return float(np.mean([abs(PRIORITIES.index(a) - PRIORITIES.index(b)) <= 1 for a, b in zip(y, p)]))

def run_benchmark():
    # 1. Prepare data
    print("Generating synthetic corpus (n=3000)...")
    data = generate(3000, seed=42)
    train_data, test_data = train_test_split(
        data, test_size=0.2, random_state=1, stratify=[d["category"] for d in data]
    )
    hand_data = [{"text": t, "category": c, "priority": p, "kb_id": k} for t, c, p, k in HAND_TESTSET]
    blind_data = [{"text": t, "category": c, "priority": p, "kb_id": k} for t, c, p, k in BLIND_TESTSET]

    # 2. Train Model
    print("Training TicketTriage pipeline with Hybrid Retrieval...")
    model = TicketTriage().fit(train_data)

    datasets = [
        ("Synthetic Holdout", test_data),
        ("Hand-written Dev Set", hand_data),
        ("Blind Test Set", blind_data)
    ]

    all_results = {}

    print("\n" + "=" * 80)
    print("MODEL AND RETRIEVAL BENCHMARK RESULTS")
    print("=" * 80)

    for ds_name, ds in datasets:
        texts = [t["text"] for t in ds]
        actual_cat = [t["category"] for t in ds]
        actual_pri = [t["priority"] for t in ds]
        actual_kb = [t["kb_id"] for t in ds]

        # Baselines
        kw_preds = [keyword_baseline(x) for x in texts]
        kw_acc = accuracy_score(actual_cat, kw_preds)

        # Predict across retrieval modes
        preds_hybrid = [model.predict(x, mode="hybrid") for x in texts]
        preds_sparse = [model.predict(x, mode="sparse") for x in texts]
        preds_dense = [model.predict(x, mode="dense") for x in texts]

        pred_cat = [p["category"] for p in preds_hybrid]
        pred_pri = [p["priority"] for p in preds_hybrid]

        # Category metrics
        cat_acc = accuracy_score(actual_cat, pred_cat)
        cat_f1 = f1_score(actual_cat, pred_cat, average="macro")

        # Priority metrics
        pri_acc = accuracy_score(actual_pri, pred_pri)
        pri_one = pri_within_one(actual_pri, pred_pri)
        p1_cases = [p == "P1" for a, p in zip(actual_pri, pred_pri) if a == "P1"]
        p1_rec = float(np.mean(p1_cases)) if p1_cases else 1.0

        # Retrieval Hit@K metrics across modes
        def hit_at_k(pred_list, k):
            return float(np.mean([
                act in [h["kb_id"] for h in p["kb"][:k]]
                for act, p in zip(actual_kb, pred_list)
            ]))

        hit1_sparse = hit_at_k(preds_sparse, 1)
        hit3_sparse = hit_at_k(preds_sparse, 3)
        hit1_dense = hit_at_k(preds_dense, 1)
        hit3_dense = hit_at_k(preds_dense, 3)
        hit1_hybrid = hit_at_k(preds_hybrid, 1)
        hit3_hybrid = hit_at_k(preds_hybrid, 3)

        ds_summary = {
            "n": len(ds),
            "keyword_baseline_accuracy": round(kw_acc, 3),
            "category_accuracy": round(cat_acc, 3),
            "category_macro_f1": round(cat_f1, 3),
            "priority_accuracy": round(pri_acc, 3),
            "priority_within_one": round(pri_one, 3),
            "p1_recall": round(p1_rec, 3),
            "hit1_sparse": round(hit1_sparse, 3),
            "hit3_sparse": round(hit3_sparse, 3),
            "hit1_dense": round(hit1_dense, 3),
            "hit3_dense": round(hit3_dense, 3),
            "hit1_hybrid": round(hit1_hybrid, 3),
            "hit3_hybrid": round(hit3_hybrid, 3)
        }
        all_results[ds_name] = ds_summary

        print(f"\nDataset: {ds_name} (n={len(ds)})")
        print(f"  Category Accuracy:      {cat_acc * 100:.1f}% (Keyword Baseline: {kw_acc * 100:.1f}%)")
        print(f"  Category Macro F1:      {cat_f1 * 100:.1f}%")
        print(f"  Priority Accuracy:      {pri_acc * 100:.1f}% (Within 1 Level: {pri_one * 100:.1f}%)")
        print(f"  P1 Outage Recall:       {p1_rec * 100:.1f}%")
        print(f"  KB Hit@1 [Sparse]:      {hit1_sparse * 100:.1f}%  |  Hit@3 [Sparse]: {hit3_sparse * 100:.1f}%")
        print(f"  KB Hit@1 [Dense]:       {hit1_dense * 100:.1f}%  |  Hit@3 [Dense]:  {hit3_dense * 100:.1f}%")
        print(f"  KB Hit@1 [Hybrid]:      {hit1_hybrid * 100:.1f}%  |  Hit@3 [Hybrid]: {hit3_hybrid * 100:.1f}%")

    import os
    os.makedirs("result", exist_ok=True)
    out_path = os.path.join("result", "benchmark_results.json")
    with open(out_path, "w") as f:
        json.dump(all_results, f, indent=2)
    print(f"\nBenchmark results saved to {out_path}")

if __name__ == "__main__":
    run_benchmark()
