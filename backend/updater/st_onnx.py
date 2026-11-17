"""Sentence-Transformers models run with ONNX Runtime instead of PyTorch.

The model files come from the same Hugging Face repository the sentence-transformers
library uses (``onnx/model.onnx``, ``tokenizer.json`` and the pooling configuration),
so the vectors match the library's output (cosine 1.000000 for all-MiniLM-L6-v2 in
our check) while the process needs roughly half the memory: about 280 MB for the
whole backend instead of about 600 MB with PyTorch. That is what lets the backend
run on a 512 MB free host.

The class mimics the two ``SentenceTransformer`` methods the backend calls, so the
embedding client can use either runtime.
"""
from __future__ import annotations

import json
import os
from typing import Sequence


class OnnxSentenceEncoder:
    def __init__(self, repo_id: str, threads: int | None = None):
        try:
            import numpy as np
            import onnxruntime as ort
            from huggingface_hub import hf_hub_download
            from tokenizers import Tokenizer
        except ImportError as exc:  # pragma: no cover - depends on the installation
            raise ImportError("the ONNX embedding runtime needs onnxruntime, tokenizers, "
                              "huggingface_hub and numpy (pip install -r "
                              "backend/requirements.txt)") from exc
        self._np = np

        def fetch(name: str) -> str | None:
            try:
                return hf_hub_download(repo_id, name)
            except Exception:  # missing optional file  # noqa: BLE001
                return None

        model_path = fetch("onnx/model.onnx")
        tokenizer_path = fetch("tokenizer.json")
        if not model_path or not tokenizer_path:
            raise ValueError(f"{repo_id} has no onnx/model.onnx and tokenizer.json; "
                             "set EMBEDDING_RUNTIME=torch to use this model")

        pooling = {}
        pooling_path = fetch("1_Pooling/config.json")
        if pooling_path:
            with open(pooling_path, encoding="utf-8") as handle:
                pooling = json.load(handle)
        self._cls_pooling = bool(pooling.get("pooling_mode_cls_token"))
        self._dimension = int(pooling.get("word_embedding_dimension") or 0)

        max_length = 256
        config_path = fetch("sentence_bert_config.json")
        if config_path:
            with open(config_path, encoding="utf-8") as handle:
                max_length = int(json.load(handle).get("max_seq_length") or max_length)

        self._tokenizer = Tokenizer.from_file(tokenizer_path)
        self._tokenizer.enable_truncation(max_length)
        self._tokenizer.enable_padding()

        options = ort.SessionOptions()
        options.intra_op_num_threads = threads or int(os.environ.get("OMP_NUM_THREADS") or 0)
        self._session = ort.InferenceSession(model_path, options,
                                             providers=["CPUExecutionProvider"])
        self._inputs = {item.name for item in self._session.get_inputs()}

    def get_sentence_embedding_dimension(self) -> int:
        if not self._dimension:
            self._dimension = len(self.encode(["dimension probe"])[0])
        return self._dimension

    def encode(self, texts: Sequence[str], batch_size: int = 32, normalize_embeddings: bool = True,
               convert_to_numpy: bool = True, show_progress_bar: bool = False):
        np = self._np
        batches = []
        for start in range(0, len(texts), batch_size):
            encoded = self._tokenizer.encode_batch(list(texts[start:start + batch_size]))
            ids = np.array([e.ids for e in encoded], dtype=np.int64)
            mask = np.array([e.attention_mask for e in encoded], dtype=np.int64)
            feed = {"input_ids": ids, "attention_mask": mask}
            if "token_type_ids" in self._inputs:
                feed["token_type_ids"] = np.zeros_like(ids)
            tokens = self._session.run(None, feed)[0]
            if self._cls_pooling:
                pooled = tokens[:, 0]
            else:
                weights = mask[..., None].astype(np.float32)
                pooled = (tokens * weights).sum(axis=1) / np.clip(weights.sum(axis=1), 1e-9, None)
            if normalize_embeddings:
                pooled = pooled / np.clip(np.linalg.norm(pooled, axis=1, keepdims=True), 1e-12, None)
            batches.append(pooled.astype(np.float32))
        if not batches:
            return np.zeros((0, self._dimension or 0), dtype=np.float32)
        return np.concatenate(batches)
