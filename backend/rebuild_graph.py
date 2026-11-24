"""Delete the knowledge graph and rebuild it from an export of its own records.

    python -m backend.rebuild_graph plan  <export-folder>          # reads every record, writes nothing
    python -m backend.rebuild_graph embed <export-folder>          # computes all vectors (resumable)
    python -m backend.rebuild_graph load  <export-folder> --yes    # wipes the LOCAL graph and reloads it

``plan`` judges every exported record (backend/curation.py) and writes
``curation_report.json`` and ``excluded.csv.gz`` (one line per excluded record with its
reasons) into the export folder.  ``load`` refuses any database that is not on this machine.
"""
from __future__ import annotations

import argparse
import csv
import gzip
import json
import sys
import time
from collections import Counter
from pathlib import Path

import numpy as np

from backend.config import configure_logging, load_settings
from backend.curation import (
    NODE_LIMIT, PINNED_CVES, REL_LIMIT, TARGET_CVES, build_attack_entities, build_products,
    cve_problems, product_ids, record_problems,
)
from backend.database import NODE_LABELS, REL_AFFECTS, REL_CVE_CWE, REL_TYPES, Neo4jDatabase, utc_now_iso
from backend.updater.data_processor import EMBEDDING_TEXT, EmbeddingClient, content_hash

STALE = ("embedding", "embedding_hash")


def read(folder: Path, label: str):
    with gzip.open(folder / f"{label}.jsonl.gz", "rt", encoding="utf-8") as handle:
        for line in handle:
            row = json.loads(line)
            for key in STALE:
                row.pop(key, None)
            yield row


def curate(folder: Path, report: bool = True) -> dict[str, list[dict]]:
    reasons: dict[str, Counter] = {}
    excluded: list[tuple[str, str, str]] = []
    read_count: Counter = Counter()

    def drop(label, row, why):
        excluded.append((label, row["id"], "; ".join(why)))
        reasons.setdefault(label, Counter()).update(why)

    out: dict[str, list[dict]] = {label: [] for label in NODE_LABELS}
    # weaknesses that CVEs depend on stay even when MITRE marks them "Incomplete"
    used: Counter = Counter()
    for row in read(folder, "CVE"):
        if not cve_problems(row):
            used.update(row["related_cwe_ids"])
    for label in ("CWE", "CAPEC", "ATTACK", "CyberTerm", "CyberDocument"):
        for row in read(folder, label):
            read_count[label] += 1
            why = record_problems(label, row)
            if label == "CWE" and used[row["id"]] and why and all(w.startswith("incomplete:") for w in why):
                why = []
            drop(label, row, why) if why else out[label].append(row)
    cwe_ids = {r["id"] for r in out["CWE"]}
    candidates = []
    for row in read(folder, "CVE"):
        read_count["CVE"] += 1
        why = cve_problems(row, cwe_ids)
        drop("CVE", row, why) if why else candidates.append(row)
    candidates.sort(key=lambda r: (r["id"] in PINNED_CVES, r["published"], r["id"]), reverse=True)
    out["CVE"] = candidates[:TARGET_CVES]
    for row in candidates[TARGET_CVES:]:
        drop("CVE", row, ["complete, but older than the newest "f"{TARGET_CVES:,}"])
    out["Product"], out["Vendor"] = build_products(out["CVE"])
    known = {r["id"] for r in out["Product"]}
    for row in out["CVE"]:
        row["product_ids"] = product_ids(row, known)
        row["related_cwe_ids"] = [i for i in row["related_cwe_ids"] if i in cwe_ids]
        if row["id"] in PINNED_CVES:
            row["pinned"] = True
    out["Tactic"], out["Mitigation"] = build_attack_entities(out["ATTACK"])

    nodes = sum(len(v) for v in out.values()) + 5                  # + SyncState
    links = sum(len(r["related_cwe_ids"]) + len(r["product_ids"]) for r in out["CVE"])
    summary = {"generated_at": utc_now_iso(), "records_read": dict(read_count),
               "kept": {k: len(v) for k, v in out.items()}, "nodes": nodes, "cve_links": links,
               "oldest_cve": min(r["published"] for r in out["CVE"] if not r.get("pinned")),
               "newest_cve": max(r["published"] for r in out["CVE"]),
               "pinned": sorted(r["id"] for r in out["CVE"] if r.get("pinned")),
               "excluded": {k: {"records": sum(1 for e in excluded if e[0] == k), "reasons": dict(v.most_common())}
                            for k, v in reasons.items()}}
    if report:
        (folder / "curation_report.json").write_text(json.dumps(summary, indent=1), encoding="utf-8")
        with gzip.open(folder / "excluded.csv.gz", "wt", encoding="utf-8", newline="") as handle:
            csv.writer(handle).writerows([("label", "id", "reasons"), *excluded])
        print(json.dumps(summary, indent=1))
    assert nodes < NODE_LIMIT and links < REL_LIMIT - 12_000, "the plan does not fit the limits"
    return out


def embed_all(folder: Path, data: dict[str, list[dict]], embedder: EmbeddingClient) -> dict:
    """{label: float32 matrix}, cached in <folder>/vectors_<model>/ in parts of 5,000."""
    cache = folder / ("vectors_" + embedder.signature.split("/")[-1])
    cache.mkdir(exist_ok=True)
    result = {}
    for label, rows in data.items():
        texts = [EMBEDDING_TEXT[label](r) for r in rows]
        order = sorted(range(len(texts)), key=lambda i: len(texts[i]))   # little padding: faster
        matrix = np.zeros((len(rows), embedder.dimensions), dtype=np.float32)
        for start in range(0, len(order), 5000):
            part = order[start:start + 5000]
            key = content_hash([embedder.signature, [texts[i] for i in part]])[:24]
            path = cache / f"{label}_{key}.npy"
            if path.exists():
                matrix[part] = np.load(path)
                continue
            began = time.time()
            vectors = embedder.embed([texts[i] for i in part])
            assert all(vectors), f"{label}: a record produced no vector"
            block = np.array(vectors, dtype=np.float32)
            np.save(path, block)
            matrix[part] = block
            print(f"{label}: {start + len(part):,}/{len(rows):,} "
                  f"({len(part) / (time.time() - began):.0f}/s)", flush=True)
        result[label] = matrix
    return result


def wipe(db: Neo4jDatabase) -> None:
    with db._session() as session:
        for r in session.run("SHOW CONSTRAINTS YIELD name RETURN name").data():
            session.run(f"DROP CONSTRAINT `{r['name']}` IF EXISTS").consume()
        for r in session.run("SHOW INDEXES YIELD name, type WHERE type <> 'LOOKUP' RETURN name").data():
            session.run(f"DROP INDEX `{r['name']}` IF EXISTS").consume()
        session.run("MATCH ()-[r]->() CALL (r) { DELETE r } IN TRANSACTIONS OF 10000 ROWS").consume()
        session.run("MATCH (n) CALL (n) { DETACH DELETE n } IN TRANSACTIONS OF 2000 ROWS").consume()
    print("graph wiped:", db.size(), flush=True)
    assert db.size() == (0, 0)


def load(db: Neo4jDatabase, folder: Path, data: dict, vectors: dict, embedder: EmbeddingClient) -> None:
    wipe(db)
    db.init_schema(embedder.dimensions)
    db.drop_vector_indexes()              # built once, after the data is in
    now = utc_now_iso()
    for label in [l for l in NODE_LABELS if l != "CVE"] + ["CVE"]:
        rows, began = data[label], time.time()
        for start in range(0, len(rows), 1000):
            batch = []
            for i in range(start, min(start + 1000, len(rows))):
                row = dict(rows[i])
                text = EMBEDDING_TEXT[label](row)
                row["embedding"] = [round(float(v), 6) for v in vectors[label][i]]
                row["embedding_hash"] = content_hash([embedder.signature, text])
                row.setdefault("content_hash", content_hash(rows[i]))
                row["synced_at"] = row.get("synced_at") or now
                batch.append(row)
            (db.upsert_cves if label == "CVE" else lambda r: db.upsert_nodes(label, r))(batch)
            if label == "CVE" and start % 10000 == 0:
                print(f"CVE {start:,}", db.size(), flush=True)
        print(f"{label}: {len(rows):,} in {time.time() - began:.0f}s", flush=True)
    print(db.rebuild_relationships([r for r in REL_TYPES if r not in (REL_CVE_CWE, REL_AFFECTS)], "rebuild"))
    for state in read(folder, "SyncState"):
        state = dict(state)
        db.save_sync_state(state.pop("source"), **state)
    db.init_schema(embedder.dimensions)
    with db._session() as session:
        session.run("CALL db.awaitIndexes(3000)").consume()
    print(json.dumps(db.counts(), indent=1), "total", db.size())


def replace_remote(settings, credentials: str, confirm: str, resume: bool = False) -> int:
    """Wipe the database of ``credentials`` and fill it with the local graph. Refuses when
    the host was not typed out, or while another machine is connected to it."""
    from backend.manage import copy_to, target_settings

    remote = target_settings(settings, credentials)
    host = remote.neo4j_uri.split("//")[-1].split(":")[0]
    if confirm != host:
        print(f"refusing: pass --confirm {host} to replace that database", file=sys.stderr)
        return 2
    source, target = Neo4jDatabase(settings), Neo4jDatabase(remote)
    try:
        others = [r["a"] for r in target._read(
            "CALL dbms.listConnections() YIELD userAgent RETURN userAgent AS a") if "win32" not in r["a"]]
        if others:
            print(f"refusing: the live backend is still connected ({others[0]})", file=sys.stderr)
            return 3
        assert source.size()[0] < NODE_LIMIT and source.size()[1] < REL_LIMIT
        if not resume:
            wipe(target)
        dims = source._read("MATCH (n:CWE) RETURN size(n.embedding) AS d LIMIT 1")[0]["d"]
        print(json.dumps(copy_to(source, target, dims, 0, resume=resume), indent=1))
        print("local", source.size(), "remote", target.size())
        return 0 if source.size() == target.size() else 1
    finally:
        source.close(), target.close()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("plan", "embed", "load", "replace-remote"))
    parser.add_argument("folder", type=Path)
    parser.add_argument("--confirm", default="", help="replace-remote: host name of the target")
    parser.add_argument("--resume", action="store_true", help="replace-remote: continue, do not wipe")
    parser.add_argument("--yes", action="store_true")
    args = parser.parse_args()
    settings = load_settings()
    configure_logging(settings.log_level)
    if args.action == "replace-remote":      # folder = credentials file
        return replace_remote(settings, str(args.folder), args.confirm, args.resume)
    data = curate(args.folder, report=args.action == "plan")
    if args.action == "plan":
        return 0
    embedder = EmbeddingClient(settings)
    vectors = embed_all(args.folder, data, embedder)
    if args.action == "embed":
        return 0
    if not any(h in settings.neo4j_uri for h in ("//localhost", "//127.0.0.1")):
        print("refusing: NEO4J_URI is not a database on this machine", file=sys.stderr)
        return 2
    if not args.yes:
        print("refusing to delete the graph without --yes", file=sys.stderr)
        return 2
    db = Neo4jDatabase(settings)
    try:
        load(db, args.folder, data, vectors, embedder)
    finally:
        db.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
