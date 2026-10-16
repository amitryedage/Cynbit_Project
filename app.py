# Basic start point to start with work 
import streamlit as st, pandas as pd
from kb_and_data import generate, KB_BY_ID
from triage import TicketTriage

st.set_page_config(page_title="Cybit Ticket Triage PoC", page_icon="🎫", layout="wide")

@st.cache_resource
def load_model():
    return TicketTriage().fit(generate(3000, seed=42))

model = load_model()
st.title("🎫 AI Service Desk Triage – Proof of Concept")
st.caption("Classifies a ticket, sets priority, finds the matching knowledge-base article, drafts a grounded reply and decides routing. "
           "Trained on SYNTHETIC tickets: not production-ready. Every reply is a draft for human approval.")

EXAMPLES = {
 "Routine: software request": "Hi, can you install Visio on my laptop please? No rush, my manager approved it.",
 "Major outage": "Our Belfast branch has completely lost internet, around 40 staff cannot work.",
 "Security incident": "Our file server shows all documents renamed .locked and there is a text file demanding bitcoin",
 "Phishing": "I think I just entered my Microsoft password on a fake login page after clicking a link in an email",
 "Ambiguous / vague": "Something is wrong again, it's not working",
 "Power BI": "The board pack dashboard still shows last month's figures, refresh failed this morning",
}
c1, c2 = st.columns([1, 1])
with c1:
    pick = st.selectbox("Load an example", ["(write your own)"] + list(EXAMPLES))
    text = st.text_area("Ticket text", value=EXAMPLES.get(pick, ""), height=140, placeholder="Paste a support ticket here...")
    use_llm = st.toggle("Use LLM for reply (needs ANTHROPIC_API_KEY)", value=False)
    go = st.button("Triage ticket", type="primary", disabled=not text.strip())

if go:
    r = model.run(text, use_llm=use_llm)
    with c2:
        m1, m2, m3 = st.columns(3)
        m1.metric("Category", r["category"], f"{r['cat_conf']:.0%} conf")
        m2.metric("Priority", r["priority"], f"{r['pri_conf']:.0%} conf")
        m3.metric("Route to", r["route"]["escalate_to"])
        for reason in r["route"]["reasons"]:
            (st.error if r["route"]["auto_reply_allowed"] is False else st.success)(reason)
        if r["flags"]:
            st.warning("Safety rule fired: " + ", ".join(r["flags"]))
    st.subheader("Suggested knowledge-base articles")
    st.dataframe(pd.DataFrame(r["kb"]).rename(columns={"kb_id": "Article", "title": "Title", "category": "Category", "score": "Score"}), hide_index=True, width="stretch")
    with st.expander("Top article steps"):
        st.write(KB_BY_ID[r["kb"][0]["kb_id"]][3])
    st.subheader("Draft reply (for human approval)")
    st.caption(f"Mode: {r['reply']['mode']}  |  Grounded in KB: {'yes' if r['reply']['grounded'] else 'NO – do not send'}")
    st.code(r["reply"]["text"], language=None)
    with st.expander("Category probabilities"):
        st.bar_chart(pd.Series(r["cat_probs"]).sort_values())
