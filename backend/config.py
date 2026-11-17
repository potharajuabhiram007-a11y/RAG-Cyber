"""Central configuration for RAG-Cyber.

Every tunable value is read from environment variables (optionally loaded from a
``.env`` file in the project root or in ``backend/``).  Nothing secret is ever
hardcoded, and ``Settings.safe_summary()`` is the only representation that is
logged or returned by the API.
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

from dotenv import load_dotenv

BACKEND_DIR = Path(__file__).resolve().parent
PROJECT_DIR = BACKEND_DIR.parent
DATA_DIR = BACKEND_DIR / "data"
LOG_DIR = BACKEND_DIR / "logs"
FRONTEND_DIR = PROJECT_DIR / "frontend"

# The five knowledge categories plus the two non-knowledge outcomes.
CATEGORY_CVE = "CVE"
CATEGORY_CWE = "CWE"
CATEGORY_CAPEC = "CAPEC"
CATEGORY_ATTACK = "ATTACK"
CATEGORY_FUNDAMENTALS = "FUNDAMENTALS"
CATEGORY_GENERAL = "GENERAL"
CATEGORY_UNSUPPORTED = "UNSUPPORTED"
DATASET_CATEGORIES = (CATEGORY_CVE, CATEGORY_CWE, CATEGORY_CAPEC, CATEGORY_ATTACK)

RESULT_NOT_FOUND = "RESULT NOT FOUND"
NO_SOLUTION_HINT = "THERE IS NO SOLUTION FOR THIS QUESTION"

SOURCE_NAMES = {
    CATEGORY_CVE: "NVD (National Vulnerability Database, CVE API 2.0)",
    CATEGORY_CWE: "MITRE CWE",
    CATEGORY_CAPEC: "MITRE CAPEC",
    CATEGORY_ATTACK: "MITRE ATT&CK",
    CATEGORY_FUNDAMENTALS: "Foundational cybersecurity collection",
}


class ConfigurationError(RuntimeError):
    """Raised when required configuration is missing or invalid."""


def _env(name: str, default: str = "") -> str:
    value = os.getenv(name)
    return default if value is None or value.strip() == "" else value.strip()


def _env_int(name: str, default: int, minimum: int | None = None) -> int:
    raw = _env(name)
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ConfigurationError(f"{name} must be an integer, got {raw!r}") from exc
    if minimum is not None and value < minimum:
        raise ConfigurationError(f"{name} must be >= {minimum}, got {value}")
    return value


def _env_float(name: str, default: float) -> float:
    raw = _env(name)
    if not raw:
        return default
    try:
        return float(raw)
    except ValueError as exc:
        raise ConfigurationError(f"{name} must be a number, got {raw!r}") from exc


def _env_bool(name: str, default: bool) -> bool:
    raw = _env(name).lower()
    if not raw:
        return default
    if raw in {"1", "true", "yes", "on"}:
        return True
    if raw in {"0", "false", "no", "off"}:
        return False
    raise ConfigurationError(f"{name} must be true or false, got {raw!r}")


def _env_list(name: str, default: str) -> list[str]:
    return [item.strip() for item in _env(name, default).split(",") if item.strip()]


@dataclass(frozen=True)
class Settings:
    # --- Neo4j -----------------------------------------------------------
    neo4j_uri: str
    neo4j_username: str
    neo4j_password: str = field(repr=False)
    neo4j_database: str = "neo4j"

    # --- NVD -------------------------------------------------------------
    nvd_api_key: str = field(default="", repr=False)
    nvd_api_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    nvd_results_per_page: int = 2000
    nvd_overlap_minutes: int = 15
    nvd_window_days: int = 120          # NVD rejects ranges longer than 120 days
    nvd_sync_start_date: str = ""       # optional ISO date: limit the initial load

    # --- MITRE -----------------------------------------------------------
    cwe_xml_url: str = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
    capec_xml_url: str = "https://capec.mitre.org/data/xml/capec_latest.xml"
    attack_stix_urls: tuple[str, ...] = (
        "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
        "enterprise-attack/enterprise-attack.json",
    )

    # --- LLM -------------------------------------------------------------
    llm_provider: str = "none"          # none | anthropic | openai | ollama
    llm_api_key: str = field(default="", repr=False)
    llm_model: str = ""
    llm_base_url: str = ""
    llm_timeout_seconds: float = 120.0

    # --- Embeddings ------------------------------------------------------
    embedding_provider: str = "local"   # local | sentence-transformers | openai | ollama
    embedding_api_key: str = field(default="", repr=False)
    embedding_model: str = ""
    embedding_base_url: str = ""
    embedding_dimensions: int = 256     # only used by the local provider
    embedding_runtime: str = "onnx"     # sentence-transformers only: onnx | torch
    embed_cves: bool = True

    # --- Scheduling ------------------------------------------------------
    update_interval_hours: int = 24     # MITRE sources
    nvd_update_interval_hours: int = 2
    scheduler_enabled: bool = True
    run_initial_sync: bool = True

    # --- API / security --------------------------------------------------
    admin_api_key: str = field(default="", repr=False)
    cors_origins: tuple[str, ...] = ("http://localhost:8000", "http://127.0.0.1:8000",
                                     "http://localhost:5500", "http://127.0.0.1:5500")
    max_message_chars: int = 2000
    max_request_bytes: int = 16_384
    http_timeout_seconds: float = 60.0
    http_max_retries: int = 5

    # --- Retrieval -------------------------------------------------------
    vector_min_score: float = 0.0       # 0 => provider-specific default
    tuning_config: str = ""             # path of a tuned-configuration file ("" => defaults)
    reference_docs_dir: str = str(DATA_DIR / "reference_docs")
    log_level: str = "INFO"

    # ------------------------------------------------------------------
    @property
    def effective_vector_min_score(self) -> float:
        """Cosine-score floor (Neo4j normalises cosine to 0..1) for semantic hits."""
        if self.vector_min_score > 0:
            return self.vector_min_score
        # The local hashing embedder is lexical, so genuine matches score lower
        # than with a neural model; both floors are deliberately conservative
        # because evidence validation also requires lexical agreement.
        return 0.56 if self.embedding_provider == "local" else 0.66

    @property
    def llm_enabled(self) -> bool:
        return self.llm_provider != "none"

    def safe_summary(self) -> dict:
        """Configuration overview with every secret removed."""
        return {
            "neo4j_uri": self.neo4j_uri,
            "neo4j_database": self.neo4j_database,
            "nvd_api_key_configured": bool(self.nvd_api_key),
            "llm_provider": self.llm_provider,
            "llm_model": self.llm_model or None,
            "embedding_provider": self.embedding_provider,
            "embedding_model": self.embedding_model or None,
            "embedding_runtime": (self.embedding_runtime
                                  if self.embedding_provider == "sentence-transformers" else None),
            "embed_cves": self.embed_cves,
            "scheduler_enabled": self.scheduler_enabled,
            "mitre_update_interval_hours": self.update_interval_hours,
            "nvd_update_interval_hours": self.nvd_update_interval_hours,
            "admin_sync_enabled": bool(self.admin_api_key),
        }


_DEFAULT_LLM_MODELS = {"anthropic": "claude-opus-5-5", "openai": "gpt-4o-mini", "ollama": "llama3"}
_DEFAULT_EMBED_MODELS = {"openai": "text-embedding-3-small", "ollama": "nomic-embed-text",
                         "sentence-transformers": "sentence-transformers/all-MiniLM-L6-v2"}
EMBEDDING_PROVIDERS = ("sentence-transformers", "local", "openai", "ollama")


def load_settings(require_neo4j: bool = True) -> Settings:
    """Build ``Settings`` from the environment, failing loudly on bad config."""
    load_dotenv(PROJECT_DIR / ".env")
    load_dotenv(BACKEND_DIR / ".env")

    missing = [n for n in ("NEO4J_URI", "NEO4J_USERNAME", "NEO4J_PASSWORD") if not _env(n)]
    if missing and require_neo4j:
        raise ConfigurationError(
            "Missing required configuration: " + ", ".join(missing) + ". "
            "Copy .env.example to .env in the RAG-Cyber folder and fill in your Neo4j "
            "connection details (see README.md, section 'Creating and configuring .env')."
        )

    llm_provider = _env("LLM_PROVIDER", "none").lower()
    if llm_provider not in {"none", "anthropic", "openai", "ollama"}:
        raise ConfigurationError(
            f"LLM_PROVIDER must be one of none, anthropic, openai, ollama (got {llm_provider!r})")
    llm_key = _env("LLM_API_KEY")
    llm_base = _env("LLM_BASE_URL")
    if llm_provider == "openai" and not llm_key and not llm_base:
        raise ConfigurationError(
            "LLM_PROVIDER=openai needs LLM_API_KEY (or LLM_BASE_URL for a local "
            "OpenAI-compatible server such as LM Studio).")

    emb_provider = _env("EMBEDDING_PROVIDER", "sentence-transformers").lower()
    if emb_provider in {"sentence_transformers", "sentence-transformer", "st"}:
        emb_provider = "sentence-transformers"
    if emb_provider not in EMBEDDING_PROVIDERS:
        raise ConfigurationError(
            f"EMBEDDING_PROVIDER must be one of {', '.join(EMBEDDING_PROVIDERS)} "
            f"(got {emb_provider!r})")
    emb_runtime = _env("EMBEDDING_RUNTIME", "onnx").lower()
    if emb_runtime not in {"onnx", "torch"}:
        raise ConfigurationError(f"EMBEDDING_RUNTIME must be onnx or torch (got {emb_runtime!r})")
    emb_key = _env("EMBEDDING_API_KEY")
    emb_base = _env("EMBEDDING_BASE_URL")
    if emb_provider == "openai" and not emb_key and not emb_base:
        raise ConfigurationError(
            "EMBEDDING_PROVIDER=openai needs EMBEDDING_API_KEY (or EMBEDDING_BASE_URL "
            "for a local OpenAI-compatible server).")

    mitre_hours = _env_int("UPDATE_INTERVAL_HOURS", 24, minimum=1)
    attack_urls = tuple(_env_list("ATTACK_STIX_URLS", ",".join(Settings.attack_stix_urls)))
    return Settings(
        neo4j_uri=_env("NEO4J_URI"),
        neo4j_username=_env("NEO4J_USERNAME"),
        neo4j_password=_env("NEO4J_PASSWORD"),
        neo4j_database=_env("NEO4J_DATABASE", "neo4j"),
        nvd_api_key=_env("NVD_API_KEY"),
        nvd_api_url=_env("NVD_API_URL", Settings.nvd_api_url),
        nvd_results_per_page=min(_env_int("NVD_RESULTS_PER_PAGE", 2000, minimum=1), 2000),
        nvd_overlap_minutes=_env_int("NVD_OVERLAP_MINUTES", 15, minimum=0),
        nvd_sync_start_date=_env("NVD_SYNC_START_DATE"),
        cwe_xml_url=_env("CWE_XML_URL", Settings.cwe_xml_url),
        capec_xml_url=_env("CAPEC_XML_URL", Settings.capec_xml_url),
        attack_stix_urls=attack_urls,
        llm_provider=llm_provider,
        llm_api_key=llm_key,
        llm_model=_env("LLM_MODEL", _DEFAULT_LLM_MODELS.get(llm_provider, "")),
        llm_base_url=llm_base,
        llm_timeout_seconds=_env_float("LLM_TIMEOUT_SECONDS", 120.0),
        embedding_provider=emb_provider,
        embedding_api_key=emb_key,
        embedding_model=_env("EMBEDDING_MODEL", _DEFAULT_EMBED_MODELS.get(emb_provider, "")),
        embedding_base_url=emb_base,
        embedding_dimensions=_env_int("EMBEDDING_DIMENSIONS", 256, minimum=32),
        embedding_runtime=emb_runtime,
        embed_cves=_env_bool("EMBED_CVES", True),
        update_interval_hours=mitre_hours,
        nvd_update_interval_hours=_env_int("NVD_UPDATE_INTERVAL_HOURS", min(2, mitre_hours),
                                           minimum=1),
        scheduler_enabled=_env_bool("SCHEDULER_ENABLED", True),
        run_initial_sync=_env_bool("RUN_INITIAL_SYNC", True),
        admin_api_key=_env("ADMIN_API_KEY"),
        cors_origins=tuple(_env_list("CORS_ORIGINS", ",".join(Settings.cors_origins))),
        max_message_chars=_env_int("MAX_MESSAGE_CHARS", 2000, minimum=10),
        http_timeout_seconds=_env_float("HTTP_TIMEOUT_SECONDS", 60.0),
        http_max_retries=_env_int("HTTP_MAX_RETRIES", 5, minimum=0),
        vector_min_score=_env_float("VECTOR_MIN_SCORE", 0.0),
        tuning_config=_env("TUNING_CONFIG"),
        reference_docs_dir=_env("REFERENCE_DOCS_DIR", Settings.reference_docs_dir),
        log_level=_env("LOG_LEVEL", "INFO").upper(),
    )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return load_settings()


def configure_logging(level: str = "INFO") -> None:
    """Console + rotating file logging.  Secrets are never passed to loggers."""
    from logging.handlers import RotatingFileHandler

    root = logging.getLogger()
    if getattr(root, "_rag_cyber_configured", False):
        return
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    fmt = logging.Formatter("%(asctime)s %(levelname)-7s %(name)s: %(message)s")
    root.setLevel(getattr(logging, level, logging.INFO))
    console = logging.StreamHandler()
    console.setFormatter(fmt)
    root.addHandler(console)
    file_handler = RotatingFileHandler(LOG_DIR / "rag_cyber.log", maxBytes=5_000_000,
                                       backupCount=3, encoding="utf-8")
    file_handler.setFormatter(fmt)
    root.addHandler(file_handler)
    # httpx logs full request URLs at INFO; keep them out of the logs.
    for noisy in ("httpx", "httpcore", "neo4j.notifications", "apscheduler.executors"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
    # The server warns about labels / types that do not exist yet on an empty graph.
    logging.getLogger("neo4j.notifications").setLevel(logging.ERROR)
    root._rag_cyber_configured = True  # type: ignore[attr-defined]
