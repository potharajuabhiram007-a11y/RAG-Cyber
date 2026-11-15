"""Pydantic request / response models for the REST API."""
from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator


class ChatRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    message: str = Field(..., min_length=1, max_length=2000,
                         description="The user's question or message.")

    @field_validator("message")
    @classmethod
    def _clean(cls, value: str) -> str:
        # Drop control characters, collapse whitespace.
        cleaned = "".join(ch if ch.isprintable() or ch in "\n\t" else " " for ch in value)
        cleaned = " ".join(cleaned.split())
        if not cleaned:
            raise ValueError("message must contain visible text")
        return cleaned


class Metrics(BaseModel):
    """Offline benchmark metrics.  ``None`` is rendered as ``--`` by the UI."""
    precision: Optional[float] = None
    f1_score: Optional[float] = None
    accuracy: Optional[float] = None
    recall: Optional[float] = None
    scope: Optional[str] = None           # "offline_benchmark" when values are present
    category: Optional[str] = None
    sample_size: Optional[int] = None
    evaluated_at: Optional[str] = None
    note: Optional[str] = None


class SourceRef(BaseModel):
    source: str                           # e.g. "MITRE CWE"
    identifier: Optional[str] = None      # e.g. "CWE-89"
    title: Optional[str] = None
    url: Optional[str] = None
    page_number: Optional[int] = None


class RelatedEntity(BaseModel):
    id: str
    type: str
    name: Optional[str] = None
    relation: Optional[str] = None
    via: list[str] = Field(default_factory=list)


class GraphRelationship(BaseModel):
    source: str
    type: str
    target: str


class EvidenceItem(BaseModel):
    kind: str                             # "entity" | "term" | "document" | "statistic"
    source: str
    identifier: Optional[str] = None
    title: Optional[str] = None
    text: str
    score: Optional[float] = None
    page_number: Optional[int] = None


class ChatResponse(BaseModel):
    answer: str
    category: str
    supported: bool
    result_found: bool
    identifiers: list[str] = Field(default_factory=list)
    sources: list[SourceRef] = Field(default_factory=list)
    related_entities: list[RelatedEntity] = Field(default_factory=list)
    relationships: list[GraphRelationship] = Field(default_factory=list)
    missing_relationships: list[str] = Field(default_factory=list)
    mitigations: list[str] = Field(default_factory=list)
    evidence: list[EvidenceItem] = Field(default_factory=list)
    metrics: Metrics = Field(default_factory=Metrics)
    hint: str
    hint_applicable: bool
    retrieval_status: str
    generation_mode: str = "none"         # none | template | extractive | llm | llm_knowledge | extractive_fallback
    timestamp: str


class SyncRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    sources: list[str] = Field(default_factory=lambda: ["all"], max_length=6)
    full: bool = False


class ApiError(BaseModel):
    detail: Any
