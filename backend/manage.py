"""Command-line management for RAG-Cyber.

    python -m backend.manage check                 # verify configuration + Neo4j
    python -m backend.manage init-db               # constraints and indexes
    python -m backend.manage sync [all|mitre|nvd|cwe|capec|attack|foundation] [--full]
    python -m backend.manage ingest [--force]      # reference documents only
    python -m backend.manage evaluate              # run the labelled benchmark
    python -m backend.manage ask "What is CWE-89?"
    python -m backend.manage reembed [--resume]    # after changing the embedding model
    python -m backend.manage copy-to aura.txt [--max-cves N]   # copy to e.g. AuraDB Free
"""
from __future__ import annotations

import argparse
import json
import sys

from backend.config import ConfigurationError, configure_logging, load_settings
from backend.database import NODE_LABELS, REL_CVE_CWE, REL_TYPES, Neo4jDatabase
from backend.evaluation import DATASET_PATH, EvaluationStore, run_evaluation
from backend.rag.generator import Assistant, Generator
from backend.rag.retriever import Retriever
from backend.rag.tuning import DEFAULT_TUNING, Tuning
from backend.updater.data_processor import (
    EMBEDDING_TEXT, EmbeddingClient, content_hash,
)
from backend.updater.scheduler import SyncManager


def reembed(db: Neo4jDatabase, embedder: EmbeddingClient, embed_cves: bool,
            resume: bool = False) -> None:
    """Recompute every embedding with the current model.

    Without ``resume`` the vector indexes and all stored vectors are dropped first.
    With ``resume`` nothing is dropped: nodes whose stored vector already comes from
    the current model and text are skipped, so an interrupted run continues where it
    stopped.
    """
    dims = embedder.dimensions          # resolved first: may fail, and must precede any drop
    if not resume:
        db.drop_vector_indexes()
        for label in NODE_LABELS:
            if label == "CVE" and not embed_cves:
                continue
            db.clear_embeddings(label)
    db.init_schema(dims)
    for label in NODE_LABELS:
        if label == "CVE" and not embed_cves:
            continue
        after, done, skipped = "", 0, 0
        while True:
            nodes = db.page_nodes(label, after, 500)
            if not nodes:
                break
            after = nodes[-1]["id"]
            texts = [EMBEDDING_TEXT[label](node) for node in nodes]
            hashes = [content_hash([embedder.signature, text]) for text in texts]
            todo = [i for i, node in enumerate(nodes) if node.get("embedding_hash") != hashes[i]]
            skipped += len(nodes) - len(todo)
            if todo:
                vectors = embedder.embed([texts[i] for i in todo])
                rows = [{"id": nodes[i]["id"], "embedding": vector, "embedding_hash": hashes[i]}
                        for i, vector in zip(todo, vectors) if vector]
                db.upsert_nodes(label, rows)
            done += len(todo)
            print(f"  {label}: {done} nodes re-embedded, {skipped} already current", end="\r")
        print(f"  {label}: {done} nodes re-embedded, {skipped} already current")


def target_settings(settings, env_file: str):
    """Settings for the copy target, read from a credentials file such as the one
    Neo4j Aura offers for download (NEO4J_URI, NEO4J_USERNAME, NEO4J_PASSWORD)."""
    from dataclasses import replace
    from dotenv import dotenv_values

    values = {k: (v or "").strip() for k, v in dotenv_values(env_file).items()}
    missing = [n for n in ("NEO4J_URI", "NEO4J_USERNAME", "NEO4J_PASSWORD") if not values.get(n)]
    if missing:
        raise ConfigurationError(f"{env_file} is missing {', '.join(missing)}")
    return replace(settings, neo4j_uri=values["NEO4J_URI"], neo4j_username=values["NEO4J_USERNAME"],
                   neo4j_password=values["NEO4J_PASSWORD"],
                   neo4j_database=values.get("NEO4J_DATABASE") or "neo4j")


def copy_to(source: Neo4jDatabase, target: Neo4jDatabase, dimensions: int, max_cves: int,
            batch: int = 250) -> dict:
    """Copy the graph to another (e.g. AuraDB Free) database, embeddings included.

    Only the newest ``max_cves`` CVEs are copied (0 = all).  Relationships are rebuilt
    on the target from the identifier lists on the nodes, exactly as a sync does, and
    the sync checkpoints are copied so the target continues with incremental updates.
    Nothing is re-downloaded or re-embedded.  Safe to re-run: every write is a MERGE.
    """
    target.init_schema(dimensions)
    floor = source.cve_retention_floor(max_cves) if max_cves else None
    copied = {}
    for label in [l for l in NODE_LABELS if l != "CVE"] + ["CVE"]:   # CWEs before CVE links
        after, done = "", 0
        while True:
            rows = source.export_nodes(label, after, batch,
                                       published_from=floor if label == "CVE" else None)
            if not rows:
                break
            target.upsert_nodes(label, rows, batch_size=batch)
            after, done = rows[-1]["id"], done + len(rows)
            print(f"  {label}: {done} copied", end="\r", flush=True)
        print(f"  {label}: {done} copied          ")
        copied[label] = done
    rebuilt = target.rebuild_relationships([r for r in REL_TYPES if r != REL_CVE_CWE], "copy")
    target.link_cves_to_cwes()
    removed = target.prune_cves(max_cves) if max_cves else 0   # ties at the floor date
    for state in source.all_sync_states():
        state = dict(state)
        target.save_sync_state(state.pop("source"), **state)
    return {"copied": copied, "relationships": rebuilt, "pruned_on_target": removed,
            "target": target.counts()}


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
    reemb = sub.add_parser("reembed")
    reemb.add_argument("--resume", action="store_true",
                       help="keep stored vectors that already match the model (continue a run)")
    copy = sub.add_parser("copy-to", help="copy the graph to another Neo4j (e.g. AuraDB Free)")
    copy.add_argument("target_env", help="credentials file of the target (NEO4J_URI, ...)")
    copy.add_argument("--max-cves", type=int, default=None,
                      help="copy only the newest N CVEs (default: MAX_CVES, 0 = all)")
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
            reembed(db, embedder, settings.embed_cves, resume=args.resume)
            return 0
        if args.command == "copy-to":
            try:
                target = Neo4jDatabase(target_settings(settings, args.target_env))
            except ConfigurationError as exc:
                print(f"Configuration error: {exc}", file=sys.stderr)
                return 2
            if not target.verify():
                print("Target Neo4j is NOT reachable - check the credentials file", file=sys.stderr)
                return 1
            cap = settings.max_cves if args.max_cves is None else args.max_cves
            try:
                summary = copy_to(db, target, embedder.dimensions, cap)
            finally:
                target.close()
            print(json.dumps(summary, indent=2))
            return 0
        db.init_schema(embedder.dimensions)
        if args.command == "init-db":
            print("Schema ready.", json.dumps(db.counts(), indent=2))
            return 0
        manager = SyncManager(db, embedder, settings)
        if args.command in {"sync", "ingest"}:
            sources = ["foundation"] if args.command == "ingest" else args.sources
            full = args.force if args.command == "ingest" else args.full
            try:
                results = manager.run_many(sources, full=full)
            except ValueError as exc:
                print(str(exc), file=sys.stderr)
                return 2
            for result in results:
                print(json.dumps(result.as_dict(), default=str)[:1200])
            return 0 if all(r.ok for r in results) else 1
        tuning = Tuning.from_file(settings.tuning_config) if settings.tuning_config else DEFAULT_TUNING
        assistant = Assistant(Retriever(db, embedder, settings, tuning),
                              Generator(settings, tuning=tuning),
                              EvaluationStore(
                                  current={"llm_provider": settings.llm_provider,
                                           "llm_model": settings.llm_model or None,
                                           "tuning": tuning.to_dict()},
                                  dataset_path=DATASET_PATH))
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
