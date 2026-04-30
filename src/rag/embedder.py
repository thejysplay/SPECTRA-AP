from __future__ import annotations

from dataclasses import dataclass
from typing import List
import numpy as np

@dataclass
class EmbedderConfig:
    model_name_or_path: str = "sentence-transformers/all-MiniLM-L6-v2"
    normalize: bool = True

class Embedder:
    """SentenceTransformer-based embedder (pass a local path to use an offline model)."""
    def __init__(self, cfg: EmbedderConfig):
        self.cfg = cfg
        from sentence_transformers import SentenceTransformer
        self.model = SentenceTransformer(cfg.model_name_or_path)

    def encode(self, texts: List[str]) -> np.ndarray:
        vecs = self.model.encode(texts, convert_to_numpy=True, show_progress_bar=False)
        vecs = vecs.astype("float32")
        if self.cfg.normalize:
            norms = np.linalg.norm(vecs, axis=1, keepdims=True) + 1e-12
            vecs = vecs / norms
        return vecs
