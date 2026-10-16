
from typing import List, Dict, Any, Optional, Tuple
import re
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
from embeddings import SemanticEmbedder

def clean_text(t: str) -> str:
    return re.sub(r"\s+", " ", t.lower()).strip()

class HybridRetriever:
    def __init__(self, runbooks: List[Tuple[str, str, str, str]], embedder: Optional[SemanticEmbedder] = None):
        self.runbooks = runbooks
        self.kb_ids = [r[0] for r in runbooks]
        self.kb_categories = [r[1] for r in runbooks]
        self.kb_titles = [r[2] for r in runbooks]
        self.kb_procedures = [r[3] for r in runbooks]
        
        # Raw runbook document text: title + procedure
        self.doc_texts = [f"{r[2]} {r[3]}" for r in runbooks]
        
        # 1. Sparse Lexical Index (TF-IDF)
        self.sparse_vectorizer = TfidfVectorizer(
            ngram_range=(1, 2),
            sublinear_tf=True,
            stop_words="english"
        )
        self.sparse_matrix = self.sparse_vectorizer.fit_transform(self.doc_texts)
        self.sparse_aug_matrix = None

        # 2. Dense Semantic Index
        self.embedder = embedder or SemanticEmbedder()
        self.embedder.fit_fallback(self.doc_texts)
        self.dense_vectors = self.embedder.encode(self.doc_texts)
        self.dense_aug_vectors = None

    def fit_symptom_memory(self, tickets: List[Dict[str, Any]]):
        """
        Augments the retrieval index with historical closed tickets mapped to each runbook.
        Learns real user phrasings and symptom vocabulary from past resolutions.
        """
        by_kb = {kb_id: [] for kb_id in self.kb_ids}
        for t in tickets:
            if t.get("kb_id") in by_kb:
                by_kb[t["kb_id"]].append(clean_text(t["text"]))

        # Build augmented corpus
        aug_texts = []
        for i, kb_id in enumerate(self.kb_ids):
            historical_symptoms = " ".join(by_kb[kb_id][:50])
            combined = f"{self.doc_texts[i]} {historical_symptoms}"
            aug_texts.append(combined)

        # Update sparse augmented index
        self.sparse_aug_matrix = self.sparse_vectorizer.transform(aug_texts)
        
        # Update dense augmented index
        self.embedder.fit_fallback(aug_texts)
        self.dense_aug_vectors = self.embedder.encode(aug_texts)

    def retrieve(self,
                 query: str,
                 category: Optional[str] = None,
                 category_conf: float = 0.0,
                 k: int = 3,
                 mode: str = "hybrid",
                 alpha: float = 0.5,
                 category_boost: float = 0.15) -> List[Dict[str, Any]]:
        """
        Retrieves top-k runbooks using sparse, dense, or hybrid ranking.
        - mode 'sparse': lexical TF-IDF matching only
        - mode 'dense': semantic embedding similarity only
        - mode 'hybrid': weighted blend of dense semantic and sparse lexical scoring
        """
        cleaned_query = clean_text(query)
        
        # Compute Sparse Score
        query_sparse = self.sparse_vectorizer.transform([cleaned_query])
        sparse_sim = cosine_similarity(query_sparse, self.sparse_matrix)[0]
        if self.sparse_aug_matrix is not None:
            sparse_aug_sim = cosine_similarity(query_sparse, self.sparse_aug_matrix)[0]
            sparse_score = 0.4 * sparse_sim + 0.6 * sparse_aug_sim
        else:
            sparse_score = sparse_sim

        # Compute Dense Score
        query_dense = self.embedder.encode(cleaned_query)
        dense_sim = self.embedder.compute_similarity(query_dense, self.dense_vectors)
        if self.dense_aug_vectors is not None:
            dense_aug_sim = self.embedder.compute_similarity(query_dense, self.dense_aug_vectors)
            dense_score = 0.4 * dense_sim + 0.6 * dense_aug_sim
        else:
            dense_score = dense_sim

        # Normalize scores to [0, 1] range for stable blending
        def _minmax(arr):
            rng = arr.max() - arr.min()
            return (arr - arr.min()) / (rng + 1e-8) if rng > 0 else arr

        norm_sparse = _minmax(sparse_score)
        norm_dense = _minmax(dense_score)

        if mode == "sparse":
            final_score = norm_sparse.copy()
        elif mode == "dense":
            final_score = norm_dense.copy()
        else:  # hybrid
            final_score = alpha * norm_dense + (1.0 - alpha) * norm_sparse

        # Optional category alignment boost
        if category and category_conf >= 0.45:
            cat_mask = np.array([1.0 if c == category else 0.0 for c in self.kb_categories])
            final_score = final_score + category_boost * cat_mask

        top_indices = np.argsort(-final_score)[:k]

        results = []
        for idx in top_indices:
            idx = int(idx)
            results.append({
                "kb_id": self.kb_ids[idx],
                "title": self.kb_titles[idx],
                "category": self.kb_categories[idx],
                "score": float(round(final_score[idx], 4)),
                "dense_score": float(round(norm_dense[idx], 4)),
                "sparse_score": float(round(norm_sparse[idx], 4)),
                "mode": mode
            })
        return results
