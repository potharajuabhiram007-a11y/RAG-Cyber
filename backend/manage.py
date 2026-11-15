"""Command-line management for RAG-Cyber.

    python -m backend.manage check                 # verify configuration + Neo4j
    python -m backend.manage init-db               # constraints and indexes
    python -m backend.manage sync [all|mitre|nvd|cwe|capec|attack|foundation] [--full]
    python -m backend.manage ingest [--force]      # reference documents only
    python -m backend.manage evaluate              # run the labelled benchmark
    python -m backend.manage ask "What is CWE-89?"
    python -m backend.manage reembed               # after changing the embedding model
"""
from __future__ import annotations

import argparse
import json
import sys

from backend.config import ConfigurationError, configure_logging, load_settings
from backend.database import NODE_LABELS, Neo4jDatabase
from backend.evaluation import EvaluationStore, run_evaluation
from backend.rag.generator import Assistant, Generator
from backend.rag.retriever import Retriever
from backend.rag.tuning import DEFAULT_TUNING, Tuning
from backend.updater.data_processor import (
    EMBEDDING_TEXT, EmbeddingClient, content_hash,
)
from backend.updater.scheduler import SyncManager


def reembed(db: Neo4jDatabase, embedder: EmbeddingClient, embed_cves: bool) -> None:
    """Drop the vector indexes and recompute every embedding with the current model."""
    db.drop_vector_indexes()
    for label in NODE_LABELS:
        db.clear_embeddings(label)
    db.init_schema(embedder.dimensions)
    for label in NODE_LABELS:
        if label == "CVE" and not embed_cves:
            continue
        after, done = "", 0
        while True:
            nodes = db.page_nodes(label, after, 500)
            if not nodes:
                break
            texts = [EMBEDDING_TEXT[label](node) for node in nodes]
            rows = [{"id": node["id"], "embedding": vector,
                     "embedding_hash": content_hash([embedder.signature, text])}
                    for node, text, vector in zip(nodes, texts, embedder.embed(texts)) if vector]
            db.upsert_nodes(label, rows)
            after, done = nodes[-1]["id"], done + len(nodes)
            print(f"  {label}: {done} nodes re-embedded", end="\r")
        print(f"  {label}: {done} nodes re-embedded")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m backend.manage", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("check")
    sub.add_parser("init-db")
    sync = sub.add_parser("sync")
    sync.add_argument("sources", nargs="*", default=["all"])
    sync.add_argument("--full", action="store_true", help="ignore checkpoints / unchanged hashes")
    ingest = sub.add_parser("ingest")
    ingest.add_argument("--force", action="store_true")
    sub.add_parser("evaluate")
    ask = sub.add_parser("ask")
    ask.add_argument("question")
    sub.add_parser("reembed")
    args = parser.parse_args(argv)

    try:
        settings = load_settings()
    except ConfigurationError as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return 2
    configure_logging(settings.log_level)
    db = Neo4jDatabase(settings)
    embedder = EmbeddingClient(settings)
    try:
        if args.command == "check":
            print(json.dumps(settings.safe_summary(), indent=2))
            if not db.verify():
                print("Neo4j: NOT reachable - check NEO4J_URI / credentials", file=sys.stderr)
                return 1
            print("Neo4j: connected", db.server_info())
            return 0
        if args.command == "reembed":
            reembed(db, embedder, settings.embed_cves)
            return 0
        db.init_schema(embedder.dimensions)
        if args.command == "init-db":
            print("Schema ready.", json.dumps(db.counts(), indent=2))
            return 0
        manager = SyncManager(db, embedder, settings)
        if args.command in {"sync", "ingest"}:
            sources = ["foundation"] if args.command == "ingest" else args.sources
            full = args.force if args.command == "ingest" else args.full
            results = manager.run_many(sources, full=full)
            for result in results:
                print(json.dumps(result.as_dict(), default=str)[:1200])
            return 0 if all(r.ok for r in results) else 1
        tuning = Tuning.from_file(settings.tuning_config) if settings.tuning_config else DEFAULT_TUNING
        assistant = Assistant(Retriever(db, embedder, settings, tuning),
                              Generator(settings, tuning=tuning), EvaluationStore())
        if args.command == "ask":
            response = assistant.ask(args.question)
            print(response.answer)
            print(f"\n[category={response.category} status={response.retrieval_status} "
                  f"mode={response.generation_mode}]\nHINT: {response.hint}")
            return 0
        if args.command == "evaluate":
            results = run_evaluation(assistant, environment={
                **settings.safe_summary(), "tuning": tuning.to_dict(), "graph": db.counts()["nodes"]})
            print(json.dumps({"overall": results["overall"],
                              "by_difficulty": results["by_difficulty"],
                              "by_category": results["by_category"]}, indent=2))
            failed = [c for c in results["cases"] if c["outcome"] in {"FP", "FN"}]
            for case in failed:
                print(f"  {case['outcome']} {case['id']}: {case['question']} "
                      f"missing_ids={case['missing_ids']} missing_facts={case['missing_facts']}"
                      + (f" answered_about={case['primary_got']}" if case["wrong_primary"] else "")
                      + (" unverified_identifiers" if case["unverified_identifiers"] else ""))
            return 0
    finally:
        db.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
