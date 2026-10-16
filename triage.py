"""Core ticket-triage pipeline: classify -> prioritise -> retrieve KB -> draft reply -> route."""
import os, re
import numpy as np
from scipy.sparse import hstack
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics.pairwise import cosine_similarity
from kb_and_data import KB, KB_BY_ID
from redaction import RedactionEngine
from guardrails import PromptGuard
from retrieval import HybridRetriever

SECURITY_RX = re.compile(r"ransom|malware|trojan|virus|phish|fake (login|page|site|invoice|email)|suspicious|scam|dodgy|bitcoin|crypto|"
    r"\.locked|encrypt|(clicked|opened|followed).{0,30}(link|attachment)|(gave|entered|typed).{0,25}password|pretending to be|"
    r"quarantined a (trojan|virus|malware)|acting (weird|strange|odd)|spoof", re.I)
URG = [re.compile(p, re.I) for p in [
    r"everyone|all users|all staff|everybody|entire (office|team|company|department|site)|whole (office|site|branch|floor|company)|"
    r"production|business.critical|customers? (cannot|can't|unable)|all visitors|\d{2,} (people|staff|users|homeworkers)|ransom|encrypt|"
    r"\.locked|completely (lost|down)|branch.*(lost|down)|staff idle|none of the|nobody|no one can",
    r"several|my (whole )?team|few (colleagues|of us)|department|deadline|cannot work|can't work|unable to work|whole floor|failing for|for \d days|"
    r"all week|stale|stalled|all (scheduled|reports)|since (this )?morning",
    r"just me|only me|intermittent|workaround|annoying|only on my|sometimes|a few minutes|every time",
    r"no rush|whenever|when you get a chance|not urgent|low priority|would it be possible|could i get|can we get|can i be given|please can you|"
    r"request|new starter|approval|approved|temp worker|second keyboard"]]

def urgency_feats(text):
    return np.array([[1.0 if r.search(text) else 0.0 for r in URG]]) * 2.0

def clean(t: str) -> str:
    return re.sub(r"\s+", " ", t.lower()).strip()

class TicketTriage:
    def __init__(self, low_conf=0.45):
        self.low_conf = low_conf
        self.redaction_engine = RedactionEngine()
        self.prompt_guard = PromptGuard()
        self.retriever = HybridRetriever(KB)
        # word n-grams capture meaning; char n-grams make the model robust to typos
        self.w = TfidfVectorizer(ngram_range=(1, 2), sublinear_tf=True, min_df=1)
        self.c = TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), sublinear_tf=True, min_df=2)
        self.cat_clf = LogisticRegression(max_iter=2000, C=8)
        self.pri_clf = LogisticRegression(max_iter=2000, C=4)
        # Fallback sparse structures for legacy calls
        self.kb_vec = self.retriever.sparse_vectorizer
        self.kb_mat = self.retriever.sparse_matrix

    def _X(self, texts, fit=False):
        texts = [clean(t) for t in texts]
        if fit:
            return hstack([self.w.fit_transform(texts), self.c.fit_transform(texts)]).tocsr()
        return hstack([self.w.transform(texts), self.c.transform(texts)]).tocsr()

    def _Xp(self, X, texts):
        from scipy.sparse import csr_matrix, vstack
        return hstack([X, vstack([csr_matrix(urgency_feats(x)) for x in texts])]).tocsr()

    def fit(self, tickets):
        texts = [t["text"] for t in tickets]
        X = self._X(texts, fit=True)
        self.cat_clf.fit(X, [t["category"] for t in tickets])
        self.pri_clf.fit(self._Xp(X, texts), [t["priority"] for t in tickets])
        # Fit hybrid retrieval symptom memory
        self.retriever.fit_symptom_memory(tickets)
        return self

    def predict(self, text, mode="hybrid"):
        X = self._X([text])
        cp = self.cat_clf.predict_proba(X)[0]; pp = self.pri_clf.predict_proba(self._Xp(X, [text]))[0]
        cat = self.cat_clf.classes_[cp.argmax()]; pri = self.pri_clf.classes_[pp.argmax()]
        flags = []
        
        # Check for untrusted prompt injection or malicious input attempts (FR-14)
        inj_check = self.prompt_guard.inspect_ticket_input(text)
        if inj_check.is_suspicious:
            flags.append(f"prompt_injection_risk_{inj_check.risk_level}")
            if inj_check.risk_level == "high" and cat != "security_incident":
                cat = "security_incident"
                flags.append("security_injection_override")

        # safety nets (recall-first): a missed security incident or major outage costs far more than an extra escalation
        if SECURITY_RX.search(text) and cat != "security_incident":
            cat = "security_incident"; flags.append("security_keyword_override")
        if URG[0].search(text) and pri != "P1":
            pri = "P1"; flags.append("p1_rule_floor")
        hits = self.retrieve(text, cat, cp.max(), mode=mode)
        return {"category": cat, "cat_conf": float(cp.max()), "priority": pri, "pri_conf": float(pp.max()),
                "cat_probs": dict(zip(self.cat_clf.classes_, map(float, cp))), "kb": hits, "flags": flags,
                "injection_check": inj_check.to_dict()}

    def retrieve(self, text, cat=None, conf=0.0, k=3, mode="hybrid"):
        # Map legacy mode names
        target_mode = "sparse" if mode in ("plain", "sparse") else ("dense" if mode == "dense" else "hybrid")
        return self.retriever.retrieve(
            query=text,
            category=cat,
            category_conf=conf,
            k=k,
            mode=target_mode
        )

    # ---------------------------------------------------------------- routing / guardrails
    def route(self, pred):
        reasons = []
        if any("prompt_injection" in f for f in pred.get("flags", [])):
            reasons.append("Prompt injection / adversarial input detected: inspect in security queue")
        if pred["category"] == "security_incident":
            reasons.append("Security category: always handled by SOC / security team")
        if pred["priority"] == "P1":
            reasons.append("P1 priority: major incident process")
        if pred["cat_conf"] < self.low_conf:
            reasons.append(f"Low classification confidence ({pred['cat_conf']:.2f}): human review")
        if reasons:
            team = "Security Operations" if (pred["category"] == "security_incident" or any("injection" in f for f in pred.get("flags", []))) else "Senior engineer / duty manager"
            return {"auto_reply_allowed": False, "escalate_to": team, "reasons": reasons}
        return {"auto_reply_allowed": True, "escalate_to": "Service desk L1", "reasons": ["Routine ticket: draft for L1 approval"]}

    # ---------------------------------------------------------------- generation
    def draft_reply(self, text, pred, use_llm=True):
        # FR-5: Redact all PII / credentials before passing to any external model or drafting
        redaction_res = self.redaction_engine.redact(text)
        sanitized_text = redaction_res.sanitized_text

        if pred["cat_conf"] < self.low_conf:   # guardrail: never paste unrelated KB steps for a vague ticket
            return {
                "text": "Hello,\n\nThanks for contacting us. To help quickly, could you tell us: (1) what exactly you were trying to do, "
                        "(2) any error message you see, (3) when it started, and (4) how many people are affected?\n\nAn engineer will pick this up as soon as we hear back.",
                "mode": "Clarification request (low confidence)",
                "grounded": True,
                "status": "APPROVED_DRAFT",
                "redaction": redaction_res.to_dict()
            }
        
        top = pred["kb"][0]
        art = KB_BY_ID[top["kb_id"]]
        sources = [KB_BY_ID[h["kb_id"]] for h in pred["kb"][:2]]
        key = os.environ.get("ANTHROPIC_API_KEY")

        if use_llm and key:
            try:
                import anthropic
                client = anthropic.Anthropic(api_key=key)
                prompt = self.prompt_guard.build_defensive_llm_prompt(
                    sanitized_ticket=sanitized_text,
                    category=pred["category"],
                    priority=pred["priority"],
                    retrieved_articles=sources
                )
                r = client.messages.create(
                    model=os.environ.get("CLAUDE_MODEL", "claude-sonnet-5-5"),
                    max_tokens=400,
                    messages=[{"role": "user", "content": prompt}]
                )
                out = r.content[0].text
                verification = self.prompt_guard.verify_draft_output(out, sources)
                if not verification["is_grounded"]:
                    fallback_text = (
                        "Hello,\n\nThanks for contacting Cybit support. Your ticket has been logged and assigned "
                        "to an engineer for manual review."
                    )
                    return {
                        "text": fallback_text,
                        "mode": "LLM (Blocked by guardrails)",
                        "grounded": False,
                        "status": "DO NOT SEND - FAILED GUARDRAIL",
                        "verification": verification,
                        "redaction": redaction_res.to_dict()
                    }
                return {
                    "text": out,
                    "mode": "LLM (grounded in KB)",
                    "grounded": True,
                    "status": "APPROVED_DRAFT",
                    "verification": verification,
                    "redaction": redaction_res.to_dict()
                }
            except Exception as e:  # fall back safely
                err = f" (LLM unavailable: {type(e).__name__})"
        else:
            err = ""

        steps = re.split(r"\s*\d\)\s*", art[3]); steps = [s for s in steps if s][:4]
        out = ("Hello,\n\nThanks for getting in touch. Here are the first steps we suggest:\n"
               + "\n".join(f"{i+1}. {s} [{art[0]}]" for i, s in enumerate(steps))
               + "\n\nIf this doesn't resolve it, reply and an engineer will pick it up.")
        
        verification = self.prompt_guard.verify_draft_output(out, sources)
        return {
            "text": out,
            "mode": "Template (no LLM key)" + err,
            "grounded": verification["is_grounded"],
            "status": "APPROVED_DRAFT" if verification["is_grounded"] else "DO NOT SEND",
            "verification": verification,
            "redaction": redaction_res.to_dict()
        }

    def run(self, text, use_llm=True):
        pred = self.predict(text)
        pred["route"] = self.route(pred)
        pred["reply"] = self.draft_reply(text, pred, use_llm=use_llm)   # always a DRAFT: a human approves before sending
        return pred
