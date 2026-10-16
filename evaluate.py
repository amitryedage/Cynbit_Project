
import json, collections
import numpy as np, matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from sklearn.metrics import accuracy_score, f1_score, confusion_matrix, classification_report
from sklearn.model_selection import train_test_split
from kb_and_data import generate, HAND_TESTSET, CATEGORIES, PRIORITIES
from triage import TicketTriage, clean
from blind_testset import BLIND_TESTSET

KEYWORDS = {"account_access": ["password", "locked", "mfa", "authenticator", "account", "log in", "login"],
 "email_m365": ["outlook", "email", "mailbox", "inbox", "calendar"], "network_vpn": ["vpn", "wifi", "wi-fi", "internet", "network", "dns"],
 "hardware": ["laptop", "monitor", "dock", "headset", "keyboard", "mouse", "screen"], "software": ["install", "licence", "excel", "office", "application"],
 "security_incident": ["phishing", "malware", "virus", "ransom", "suspicious", "antivirus"], "cloud_azure": ["azure", "vm"],
 "backup_storage": ["backup", "restore", "shared drive", "deleted"], "printing": ["print", "scan", "copier"], "data_bi": ["power bi", "dashboard", "refresh", "report"]}

def keyword_baseline(text):
    t = clean(text); best, bs = "software", 0
    for c, kws in KEYWORDS.items():
        s = sum(k in t for k in kws)
        if s > bs: best, bs = c, s
    return best

def pri_within_one(y, p):
    return float(np.mean([abs(PRIORITIES.index(a) - PRIORITIES.index(b)) <= 1 for a, b in zip(y, p)]))

def evaluate(model, tickets, name):
    texts = [t["text"] for t in tickets]
    preds = [model.predict(x) for x in texts]
    yc = [t["category"] for t in tickets]; pc = [p["category"] for p in preds]
    yp = [t["priority"] for t in tickets]; pp = [p["priority"] for p in preds]
    plain = [model.predict(x, mode="plain")["kb"] for x in texts]
    hyb = [p["kb"] for p in preds]
    hit = lambda hl, k: float(np.mean([t["kb_id"] in [h["kb_id"] for h in hs[:k]] for t, hs in zip(tickets, hl)]))
    r = {"n": len(tickets),
         "category_accuracy": accuracy_score(yc, pc), "category_macro_f1": f1_score(yc, pc, average="macro"),
         "keyword_baseline_accuracy": accuracy_score(yc, [keyword_baseline(x) for x in texts]),
         "majority_baseline_accuracy": float(np.mean([c == collections.Counter(yc).most_common(1)[0][0] for c in yc])),
         "priority_accuracy": accuracy_score(yp, pp), "priority_within_one_level": pri_within_one(yp, pp),
         "p1_recall": float(np.mean([p == "P1" for a, p in zip(yp, pp) if a == "P1"])) if "P1" in yp else None,
         "kb_hit_at1_tfidf_only": hit(plain, 1), "kb_hit_at3_tfidf_only": hit(plain, 3),
         "kb_hit_at1_hybrid": hit(hyb, 1), "kb_hit_at3_hybrid": hit(hyb, 3)}
    k = int(round(r["category_accuracy"] * len(tickets))); n_ = len(tickets); z = 1.96
    ph = k / n_; den = 1 + z*z/n_; ctr = (ph + z*z/(2*n_)) / den; hw = z*np.sqrt(ph*(1-ph)/n_ + z*z/(4*n_*n_)) / den
    r["category_accuracy_95ci"] = [round(ctr-hw, 3), round(ctr+hw, 3)]   # Wilson interval
    # safety metric: security tickets that were NOT routed to security (should be ~0)
    sec = [(t, p) for t, p in zip(tickets, preds) if t["category"] == "security_incident"]
    r["false_p1_rate"] = float(np.mean([p != "P1" and q == "P1" for p, q in zip(yp, pp)]))
    r["security_override_false_positive_rate"] = float(np.mean([("security_keyword_override" in p["flags"]) and t["category"] != "security_incident" for t, p in zip(tickets, preds)]))
    r["security_miss_rate"] = float(np.mean([p["category"] != "security_incident" for _, p in sec])) if sec else None
    return r, yc, pc, classification_report(yc, pc, zero_division=0)

if __name__ == "__main__":
    data = generate(3000, seed=42)
    train, test = train_test_split(data, test_size=0.2, random_state=1, stratify=[d["category"] for d in data])
    model = TicketTriage().fit(train)
    hand = [{"text": t, "category": c, "priority": p, "kb_id": k} for t, c, p, k in HAND_TESTSET]
    res = {}
    blind = [{"text": t, "category": c, "priority": p, "kb_id": k} for t, c, p, k in BLIND_TESTSET]
    for name, ds in [("synthetic_holdout", test), ("hand_written_dev_set", hand), ("blind_test_set", blind)]:
        r, yc, pc, rep = evaluate(model, ds, name); res[name] = r
        print(f"\n=== {name} (n={r['n']}) ==="); print(json.dumps({k: round(v, 3) if isinstance(v, float) else v for k, v in r.items()}, indent=1))
        if name in ("hand_written_dev_set", "blind_test_set"):
            print(rep)
            cm = confusion_matrix(yc, pc, labels=CATEGORIES)
            fig, ax = plt.subplots(figsize=(8, 6.5)); ax.imshow(cm, cmap="Blues")
            ax.set_xticks(range(10)); ax.set_yticks(range(10)); ax.set_xticklabels(CATEGORIES, rotation=60, ha="right"); ax.set_yticklabels(CATEGORIES)
            for i in range(10):
                for j in range(10):
                    if cm[i, j]: ax.text(j, i, cm[i, j], ha="center", va="center", color="white" if cm[i, j] > cm.max() / 2 else "black")
            import os
            os.makedirs("result", exist_ok=True)
            plt.tight_layout(); plt.savefig(os.path.join("result", f"confusion_matrix_{name}.png"), dpi=140)
            for t, a, b in zip(ds, yc, pc):
                if a != b: print("MISS:", t["text"][:70], "| actual", a, "| pred", b)
    import os
    os.makedirs("result", exist_ok=True)
    json.dump(res, open(os.path.join("result", "results.json"), "w"), indent=2)
