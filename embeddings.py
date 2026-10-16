"""
Semantic Embedding Engine (Phase B: Dense Retrieval & Semantic Classification).
Provides dense vector representations for ticket text and knowledge-base runbooks.
Supports sentence-transformers (e.g. all-MiniLM-L6-v2) with an automatic
calibrated LSA/SVD dense semantic projector fallback when transformers is not installed.
"""
from typing import List, Union, Optional
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.decomposition import TruncatedSVD
from sklearn.preprocessing import normalize

class DenseSemanticProjector:
    """
    High-performance zero-dependency dense semantic projector.
    Maps text into a dense 128-dimensional latent semantic space using
    sublinear TF-IDF and Truncated SVD, capturing cross-word co-occurrences
    and synonymy even when heavy neural packages are unavailable.
    """
    def __init__(self, dim: int = 128):
        self.dim = dim
        self.vectorizer = TfidfVectorizer(
            ngram_range=(1, 2),
            sublinear_tf=True,
            min_df=1,
            token_pattern=r"(?u)\b\w+\b"
        )
        self.svd = TruncatedSVD(n_components=dim, random_state=42)
        self._is_fitted = False

    def fit(self, texts: List[str]) -> "DenseSemanticProjector":
        tfidf_mat = self.vectorizer.fit_transform(texts)
        actual_dim = min(self.dim, tfidf_mat.shape[1] - 1, tfidf_mat.shape[0] - 1)
        actual_dim = max(actual_dim, 2)
        if actual_dim != self.dim:
            self.svd = TruncatedSVD(n_components=actual_dim, random_state=42)
        self.svd.fit(tfidf_mat)
        self._is_fitted = True
        return self

    def encode(self, texts: List[str]) -> np.ndarray:
        if not self._is_fitted:
            self.fit(texts)
        tfidf_mat = self.vectorizer.transform(texts)
        dense_vecs = self.svd.transform(tfidf_mat)
        return normalize(dense_vecs, norm="l2", axis=1).astype(np.float32)


class SemanticEmbedder:
    """
    Unified dense embedding interface.
    Attempts to load sentence-transformers for state-of-the-art semantic representations;
    automatically falls back to DenseSemanticProjector if not installed.
    """
    def __init__(self, model_name: str = "all-MiniLM-L6-v2"):
        self.model_name = model_name
        self.backend = "projector"
        self._transformer_model = None
        self._projector = DenseSemanticProjector(dim=128)

        # Attempt to load sentence-transformers
        try:
            from sentence_transformers import SentenceTransformer
            self._transformer_model = SentenceTransformer(model_name)
            self.backend = "sentence_transformers"
        except (ImportError, Exception):
            self.backend = "projector"

    def fit_fallback(self, corpus: List[str]):
        """Fits the fallback dense projector on available ticket/runbook corpus."""
        if self.backend == "projector":
            self._projector.fit(corpus)

    def encode(self, texts: Union[str, List[str]]) -> np.ndarray:
        if isinstance(texts, str):
            texts = [texts]

        if self.backend == "sentence_transformers" and self._transformer_model is not None:
            vecs = self._transformer_model.encode(texts, convert_to_numpy=True, normalize_embeddings=True)
            return vecs.astype(np.float32)
        else:
            return self._projector.encode(texts)

    @staticmethod
    def compute_similarity(query_vec: np.ndarray, doc_vecs: np.ndarray) -> np.ndarray:
        """
        Computes cosine similarity between query vector (1, D) and doc vectors (N, D).
        Assumes unit-normalized vectors (dot product equals cosine similarity).
        """
        if query_vec.ndim == 1:
            query_vec = query_vec.reshape(1, -1)
        sims = np.dot(doc_vecs, query_vec.T).flatten()
        return np.clip(sims, -1.0, 1.0)
