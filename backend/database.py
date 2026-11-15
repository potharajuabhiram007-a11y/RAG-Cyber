"""Neo4j access layer for RAG-Cyber.

Neo4j is the single source of truth: the knowledge graph (CVE, CWE, CAPEC,
ATTACK), the foundational collection (CyberTerm, CyberDocument), their
embeddings and the synchronisation checkpoints all live here.

Safety rules followed throughout this module:

* every value coming from a user or an external feed is passed as a Cypher
  **parameter**;
* labels, relationship types and index names cannot be parameterised in Cypher,
  so they are only ever taken from the whitelists below (never from input);
* multi-statement writes run inside one managed transaction, so a failure rolls
  the whole batch back and never leaves half-written data behind.
"""
from __future__ import annotations

import logging
import re
import threading
from datetime import datetime, timezone
from typing import Any, Iterable, Sequence

from neo4j import GraphDatabase
from neo4j.exceptions import AuthError, Neo4jError, ServiceUnavailable, SessionExpired

from backend.config import Settings

log = logging.getLogger(__name__)

# --------------------------------------------------------------------------- #
# Schema whitelists
# --------------------------------------------------------------------------- #
LABEL_CVE, LABEL_CWE, LABEL_CAPEC, LABEL_ATTACK = "CVE", "CWE", "CAPEC", "ATTACK"
LABEL_TERM, LABEL_DOC = "CyberTerm", "CyberDocument"
NODE_LABELS = (LABEL_CVE, LABEL_CWE, LABEL_CAPEC, LABEL_ATTACK, LABEL_TERM, LABEL_DOC)
GRAPH_LABELS = (LABEL_CVE, LABEL_CWE, LABEL_CAPEC, LABEL_ATTACK)

REL_CVE_CWE = "CVE_CWE"                 # (CVE)-[:CVE_CWE]->(CWE)
REL_CWE_CHILD = "CWE_CHILD"             # (child CWE)-[:CWE_CHILD]->(parent CWE)
REL_CWE_CAPEC = "CWE_CAPEC"             # (CWE)-[:CWE_CAPEC]->(CAPEC)
REL_CAPEC_CHILD = "CAPEC_CHILD"         # (child CAPEC)-[:CAPEC_CHILD]->(parent CAPEC)
REL_CAN_PRECEDE = "CAN_PRECEDE"         # (earlier CAPEC)-[:CAN_PRECEDE]->(later CAPEC)
REL_CAPEC_ATTACK = "CAPEC_ATTACK"       # (CAPEC)-[:CAPEC_ATTACK]->(ATTACK)
REL_SUBTECHNIQUE_OF = "SUBTECHNIQUE_OF" # (sub-technique)-[:SUBTECHNIQUE_OF]->(technique)
REL_TYPES = (REL_CVE_CWE, REL_CWE_CHILD, REL_CWE_CAPEC, REL_CAPEC_CHILD,
             REL_CAN_PRECEDE, REL_CAPEC_ATTACK, REL_SUBTECHNIQUE_OF)

# End-point labels of every relationship type: rel -> (start label, end label).
REL_ENDPOINTS = {
    REL_CVE_CWE: (LABEL_CVE, LABEL_CWE),
    REL_CWE_CHILD: (LABEL_CWE, LABEL_CWE),
    REL_CWE_CAPEC: (LABEL_CWE, LABEL_CAPEC),
    REL_CAPEC_CHILD: (LABEL_CAPEC, LABEL_CAPEC),
    REL_CAN_PRECEDE: (LABEL_CAPEC, LABEL_CAPEC),
    REL_CAPEC_ATTACK: (LABEL_CAPEC, LABEL_ATTACK),
    REL_SUBTECHNIQUE_OF: (LABEL_ATTACK, LABEL_ATTACK),
}

# How each MITRE relationship type is derived from identifier lists that the
# updaters copy verbatim from the official feeds onto the nodes.  A rule is
# (owner label, list property, other label, owner_is_start).  Edges are *only*
# created from these official cross references - never from text similarity.
REL_RULES: dict[str, tuple[tuple[str, str, str, bool], ...]] = {
    REL_CWE_CHILD: ((LABEL_CWE, "child_of_ids", LABEL_CWE, True),),
    REL_CWE_CAPEC: ((LABEL_CWE, "related_capec_ids", LABEL_CAPEC, True),
                    (LABEL_CAPEC, "related_cwe_ids", LABEL_CWE, False)),
    REL_CAPEC_CHILD: ((LABEL_CAPEC, "childOf", LABEL_CAPEC, True),),
    REL_CAN_PRECEDE: ((LABEL_CAPEC, "can_precede_ids", LABEL_CAPEC, True),
                      (LABEL_CAPEC, "can_follow_ids", LABEL_CAPEC, False)),
    REL_CAPEC_ATTACK: ((LABEL_CAPEC, "attack_ids", LABEL_ATTACK, True),
                       (LABEL_ATTACK, "capec_ids", LABEL_CAPEC, False)),
    REL_SUBTECHNIQUE_OF: ((LABEL_ATTACK, "parent_ids", LABEL_ATTACK, True),),
}

VECTOR_INDEXES = {label: f"{label.lower()}_embedding" for label in NODE_LABELS}
# v2 also indexes the alternate names ("SQL Injection" for CWE-89), not just the title
FULLTEXT_INDEX = "entity_names_v2"
FULLTEXT_LABELS = (LABEL_CWE, LABEL_CAPEC, LABEL_ATTACK)
CVE_TEXT_INDEX = "cve_descriptions"

Hop = tuple[str, str, str]  # (relationship type, "out" | "in", label reached)

# Identifier shapes -> node label, used by the knowledge-graph explorer to pick the
# right (indexed) label before any query is built.
_ID_SHAPES = ((re.compile(r"^CVE-\d{4}-\d{4,}$"), LABEL_CVE), (re.compile(r"^CWE-\d{1,5}$"), LABEL_CWE),
              (re.compile(r"^CAPEC-\d{1,5}$"), LABEL_CAPEC), (re.compile(r"^T\d{4}(\.\d{3})?$"), LABEL_ATTACK))
_HIDDEN_PROPS = {"embedding", "embedding_hash", "content_hash", "stix_id"}


def label_for_id(identifier: str) -> str | None:
    """Return the node label an identifier belongs to, or None if it is not one."""
    candidate = (identifier or "").strip().upper()
    for pattern, label in _ID_SHAPES:
        if pattern.match(candidate):
            return label
    return None


class DatabaseUnavailable(RuntimeError):
    """Neo4j cannot be reached or rejected the credentials."""


class SchemaMismatch(RuntimeError):
    """The stored vector indexes do not match the configured embedding size."""


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _check_label(label: str) -> str:
    if label not in NODE_LABELS:
        raise ValueError(f"Unknown node label: {label!r}")
    return label


def _check_rel(rel: str) -> str:
    if rel not in REL_TYPES:
        raise ValueError(f"Unknown relationship type: {rel!r}")
    return rel


def strip_embedding(props: dict | None) -> dict | None:
    """Embeddings are never needed outside the database (paper, Fig. 19)."""
    if props is None:
        return None
    return {k: v for k, v in props.items() if k != "embedding" and v is not None}


def chunked(items: Sequence, size: int) -> Iterable[Sequence]:
    for start in range(0, len(items), size):
        yield items[start:start + size]


class Neo4jDatabase:
    """Thin, safe wrapper around the official Neo4j Python driver."""

    def __init__(self, settings: Settings):
        self._settings = settings
        self._driver = None
        self._lock = threading.Lock()
        self.vector_search_available = True

    # ------------------------------------------------------------------ #
    # Connection management
    # ------------------------------------------------------------------ #
    def _get_driver(self):
        with self._lock:
            if self._driver is None:
                try:
                    self._driver = GraphDatabase.driver(
                        self._settings.neo4j_uri,
                        auth=(self._settings.neo4j_username, self._settings.neo4j_password),
                        connection_timeout=15,
                        max_transaction_retry_time=30,
                    )
                except Exception as exc:  # malformed URI etc.
                    raise DatabaseUnavailable(
                        f"Could not create the Neo4j driver for {self._settings.neo4j_uri}: "
                        f"{type(exc).__name__}") from exc
            return self._driver

    def _session(self):
        return self._get_driver().session(database=self._settings.neo4j_database)

    def _wrap(self, exc: Exception) -> Exception:
        if isinstance(exc, AuthError):
            return DatabaseUnavailable(
                "Neo4j rejected the credentials. Check NEO4J_USERNAME / NEO4J_PASSWORD.")
        if isinstance(exc, (ServiceUnavailable, SessionExpired, OSError)):
            return DatabaseUnavailable(
                f"Neo4j is not reachable at {self._settings.neo4j_uri}. "
                "Is the database running and is NEO4J_URI correct?")
        return exc

    def _read(self, query: str, **params) -> list[dict]:
        try:
            with self._session() as session:
                return session.execute_read(lambda tx: [r.data() for r in tx.run(query, **params)])
        except (AuthError, ServiceUnavailable, SessionExpired, OSError) as exc:
            raise self._wrap(exc) from exc

    def _write(self, work) -> Any:
        """Run ``work(tx)`` in one managed (auto-retried, atomic) transaction."""
        try:
            with self._session() as session:
                return session.execute_write(work)
        except (AuthError, ServiceUnavailable, SessionExpired, OSError) as exc:
            raise self._wrap(exc) from exc

    def verify(self) -> bool:
        try:
            self._get_driver().verify_connectivity()
            return True
        except Exception as exc:
            log.warning("Neo4j connectivity check failed: %s", type(exc).__name__)
            return False

    def close(self) -> None:
        with self._lock:
            if self._driver is not None:
                self._driver.close()
                self._driver = None

    # ------------------------------------------------------------------ #
    # Schema
    # ------------------------------------------------------------------ #
    def init_schema(self, embedding_dimensions: int) -> None:
        """Create uniqueness constraints and indexes (idempotent)."""
        dims = int(embedding_dimensions)
        statements = [
            f"CREATE CONSTRAINT {label.lower()}_id IF NOT EXISTS "
            f"FOR (n:{label}) REQUIRE n.id IS UNIQUE"
            for label in NODE_LABELS
        ]
        statements.append("CREATE CONSTRAINT syncstate_source IF NOT EXISTS "
                          "FOR (n:SyncState) REQUIRE n.source IS UNIQUE")
        statements.append(
            f"CREATE FULLTEXT INDEX {FULLTEXT_INDEX} IF NOT EXISTS "
            f"FOR (n:{'|'.join(FULLTEXT_LABELS)}) ON EACH [n.name, n.alternate_terms]")
        statements.append(
            f"CREATE FULLTEXT INDEX {CVE_TEXT_INDEX} IF NOT EXISTS "
            f"FOR (n:{LABEL_CVE}) ON EACH [n.description]")
        statements.append("CREATE INDEX cyberterm_source IF NOT EXISTS "
                          "FOR (n:CyberTerm) ON (n.source_file)")
        statements.append("CREATE INDEX cyberdocument_source IF NOT EXISTS "
                          "FOR (n:CyberDocument) ON (n.source_file)")
        try:
            with self._session() as session:
                for statement in statements:
                    session.run(statement).consume()
                self._init_vector_indexes(session, dims)
        except (AuthError, ServiceUnavailable, SessionExpired, OSError) as exc:
            raise self._wrap(exc) from exc
        log.info("Neo4j schema initialised (vector search available: %s)",
                 self.vector_search_available)

    def _init_vector_indexes(self, session, dims: int) -> None:
        try:
            existing = {
                r["name"]: r["options"] for r in session.run(
                    "SHOW INDEXES YIELD name, type, options WHERE type = 'VECTOR' "
                    "RETURN name, options")
            }
        except Neo4jError:
            existing = {}
        for label, index in VECTOR_INDEXES.items():
            config = (existing.get(index) or {}).get("indexConfig") or {}
            current = config.get("vector.dimensions")
            if current is not None and int(current) != dims:
                raise SchemaMismatch(
                    f"Vector index {index} was built for {current}-dimensional embeddings "
                    f"but the configured embedding model produces {dims}. Run "
                    "'python -m backend.manage reembed' after changing the embedding "
                    "provider or model.")
            try:
                session.run(
                    f"CREATE VECTOR INDEX {index} IF NOT EXISTS FOR (n:{label}) "
                    "ON (n.embedding) OPTIONS {indexConfig: {"
                    f"`vector.dimensions`: {dims}, `vector.similarity_function`: 'cosine'"
                    "}}").consume()
            except Neo4jError as exc:
                # Neo4j < 5.11 has no vector indexes; retrieval then falls back to
                # exact identifier, term and full-text lookups.
                self.vector_search_available = False
                log.warning("Vector index %s could not be created (%s). Semantic "
                            "vector search is disabled; upgrade to Neo4j 5.11+.",
                            index, exc.code)
                return

    def drop_vector_indexes(self) -> None:
        with self._session() as session:
            for index in VECTOR_INDEXES.values():
                session.run(f"DROP INDEX {index} IF EXISTS").consume()

    # ------------------------------------------------------------------ #
    # Node writes
    # ------------------------------------------------------------------ #
    def upsert_nodes(self, label: str, rows: Sequence[dict], batch_size: int = 500) -> int:
        """MERGE nodes on ``id`` and update their properties.

        A key that is absent from ``row`` keeps its stored value (so an unchanged
        record keeps its embedding); a key set to ``None`` removes the property.
        """
        _check_label(label)
        query = (f"UNWIND $rows AS row MERGE (n:{label} {{id: row.id}}) "
                 "SET n += row RETURN count(n) AS written")
        total = 0
        for batch in chunked(list(rows), batch_size):
            payload = [dict(r) for r in batch]
            total += self._write(lambda tx, p=payload: tx.run(query, rows=p).single()["written"])
        return total

    def upsert_cves(self, rows: Sequence[dict], batch_size: int = 500) -> int:
        """Upsert CVE nodes and their CVE_CWE edges atomically per batch.

        Links are only made to CWE nodes that already exist; the edge set of each
        written CVE is replaced so a weakness NVD has withdrawn disappears too.
        """
        node_q = ("UNWIND $rows AS row MERGE (n:CVE {id: row.id}) SET n += row "
                  "RETURN count(n) AS written")
        prune_q = ("UNWIND $rows AS row MATCH (n:CVE {id: row.id})-[r:CVE_CWE]->(w:CWE) "
                   "WHERE NOT w.id IN coalesce(row.related_cwe_ids, []) DELETE r")
        link_q = ("UNWIND $rows AS row MATCH (n:CVE {id: row.id}) "
                  "UNWIND coalesce(row.related_cwe_ids, []) AS wid "
                  "MATCH (w:CWE {id: wid}) MERGE (n)-[r:CVE_CWE]->(w) "
                  "SET r.source = 'NVD', r.updated_at = $now")
        total = 0
        now = utc_now_iso()
        for batch in chunked(list(rows), batch_size):
            payload = [dict(r) for r in batch]

            def work(tx, p=payload):
                written = tx.run(node_q, rows=p).single()["written"]
                tx.run(prune_q, rows=p).consume()
                tx.run(link_q, rows=p, now=now).consume()
                return written

            total += self._write(work)
        return total

    def get_property_map(self, label: str, ids: Sequence[str], prop: str) -> dict[str, Any]:
        """Return ``{id: value}`` of one whitelisted bookkeeping property."""
        _check_label(label)
        if prop not in {"content_hash", "embedding_hash"}:
            raise ValueError(f"Property {prop!r} cannot be read through this method")
        result: dict[str, Any] = {}
        for batch in chunked(list(ids), 2000):
            rows = self._read(
                f"MATCH (n:{label}) WHERE n.id IN $ids RETURN n.id AS id, n.{prop} AS value",
                ids=list(batch))
            result.update({r["id"]: r["value"] for r in rows})
        return result

    def link_cves_to_cwes(self) -> None:
        """(Re)connect stored CVEs to CWE nodes, e.g. after the first CWE load."""
        query = ("MATCH (c:CVE) WHERE size(coalesce(c.related_cwe_ids, [])) > 0 "
                 "CALL (c) { UNWIND c.related_cwe_ids AS wid MATCH (w:CWE {id: wid}) "
                 "MERGE (c)-[r:CVE_CWE]->(w) ON CREATE SET r.source = 'NVD', r.updated_at = $now } "
                 "IN TRANSACTIONS OF 5000 ROWS")
        legacy = query.replace("CALL (c) {", "CALL { WITH c")
        try:
            with self._session() as session:
                try:
                    session.run(query, now=utc_now_iso()).consume()
                except Neo4jError:
                    session.run(legacy, now=utc_now_iso()).consume()  # Neo4j < 5.23 syntax
        except (AuthError, ServiceUnavailable, SessionExpired, OSError) as exc:
            raise self._wrap(exc) from exc

    def rebuild_relationships(self, rel_types: Sequence[str], sync_id: str) -> dict[str, int]:
        """Re-derive MITRE relationships from the official id lists on the nodes.

        Each type is rebuilt in one transaction: edges are MERGEd (no duplicates),
        stamped with ``sync_id``, and edges that the current official data no
        longer supports are removed.  If anything fails the transaction rolls back
        and the previous edges stay untouched.
        """
        counts: dict[str, int] = {}
        now = utc_now_iso()
        for rel in rel_types:
            _check_rel(rel)
            rules = REL_RULES[rel]

            def work(tx, rel=rel, rules=rules):
                for owner, prop, other, owner_is_start in rules:
                    pattern = (f"(o)-[r:{rel}]->(x)" if owner_is_start else f"(x)-[r:{rel}]->(o)")
                    tx.run(
                        f"MATCH (o:{owner}) UNWIND coalesce(o.{prop}, []) AS oid "
                        f"MATCH (x:{other} {{id: oid}}) MERGE {pattern} "
                        "SET r.sync_id = $sync_id, r.updated_at = $now, r.source = $source",
                        sync_id=sync_id, now=now, source=f"{owner}.{prop}").consume()
                tx.run(f"MATCH ()-[r:{rel}]->() WHERE coalesce(r.sync_id, '') <> $sync_id "
                       "DELETE r", sync_id=sync_id).consume()
                return tx.run(f"MATCH ()-[r:{rel}]->() RETURN count(r) AS c").single()["c"]

            counts[rel] = self._write(work)
        return counts

    # ------------------------------------------------------------------ #
    # Foundational collection maintenance
    # ------------------------------------------------------------------ #
    def delete_stale_foundation(self, source_file: str, keep_ids: Sequence[str]) -> int:
        """Remove chunks/terms of a re-ingested document that no longer exist."""
        def work(tx):
            removed = 0
            for label in (LABEL_TERM, LABEL_DOC):
                removed += tx.run(
                    f"MATCH (n:{label} {{source_file: $source}}) WHERE NOT n.id IN $keep "
                    "WITH n, n.id AS id DETACH DELETE n RETURN count(id) AS c",
                    source=source_file, keep=list(keep_ids)).single()["c"]
            return removed
        return self._write(work)

    def list_terms(self) -> list[dict]:
        rows = self._read(
            "MATCH (t:CyberTerm) RETURN t {.*, embedding: null} AS node ORDER BY t.term")
        return [strip_embedding(r["node"]) for r in rows]

    def list_document_sections(self) -> list[dict]:
        rows = self._read(
            "MATCH (d:CyberDocument) RETURN d {.*, embedding: null} AS node "
            "ORDER BY d.source_file, d.chunk_index")
        return [strip_embedding(r["node"]) for r in rows]

    def foundation_version(self) -> str:
        """Cheap fingerprint used to cache the term lexicon in the retriever."""
        rows = self._read(
            "MATCH (n) WHERE n:CyberTerm OR n:CyberDocument "
            "RETURN count(n) AS c, max(n.synced_at) AS latest")
        return f"{rows[0]['c']}:{rows[0]['latest']}" if rows else "0:"

    # ------------------------------------------------------------------ #
    # Embedding maintenance (used by `manage reembed`)
    # ------------------------------------------------------------------ #
    def clear_embeddings(self, label: str) -> None:
        _check_label(label)
        query = (f"MATCH (n:{label}) WHERE n.embedding IS NOT NULL "
                 "CALL (n) { REMOVE n.embedding, n.embedding_hash } IN TRANSACTIONS OF 2000 ROWS")
        legacy = query.replace("CALL (n) {", "CALL { WITH n")
        with self._session() as session:
            try:
                session.run(query).consume()
            except Neo4jError:
                session.run(legacy).consume()

    def page_nodes(self, label: str, after_id: str, limit: int) -> list[dict]:
        _check_label(label)
        rows = self._read(
            f"MATCH (n:{label}) WHERE n.id > $after RETURN n {{.*, embedding: null}} AS node "
            "ORDER BY n.id LIMIT $limit", after=after_id, limit=int(limit))
        return [strip_embedding(r["node"]) for r in rows]

    # ------------------------------------------------------------------ #
    # Synchronisation state (checkpoints)
    # ------------------------------------------------------------------ #
    def get_sync_state(self, source: str) -> dict:
        rows = self._read("MATCH (s:SyncState {source: $source}) RETURN properties(s) AS state",
                          source=source)
        return rows[0]["state"] if rows else {"source": source, "status": "never_run"}

    def save_sync_state(self, source: str, **fields) -> None:
        """Persist checkpoint fields atomically (single-statement transaction)."""
        fields = {k: v for k, v in fields.items()}
        self._write(lambda tx: tx.run(
            "MERGE (s:SyncState {source: $source}) SET s += $fields",
            source=source, fields=fields).consume())

    def all_sync_states(self) -> list[dict]:
        rows = self._read("MATCH (s:SyncState) RETURN properties(s) AS state ORDER BY s.source")
        return [r["state"] for r in rows]

    # ------------------------------------------------------------------ #
    # Reads: exact lookup, traversal, search
    # ------------------------------------------------------------------ #
    def get_node(self, label: str, node_id: str) -> dict | None:
        _check_label(label)
        rows = self._read(
            f"MATCH (n:{label} {{id: $id}}) RETURN n {{.*, embedding: null}} AS node LIMIT 1",
            id=node_id)
        return strip_embedding(rows[0]["node"]) if rows else None

    def traverse(self, start_label: str, start_id: str, hops: Sequence[Hop],
                 limit: int = 15) -> dict:
        """Follow a fixed chain of whitelisted relationships from one node.

        Returns ``{"nodes": [...], "total": n}`` where every node carries ``via``:
        the ids of the nodes of the previous hop that lead to it (the start id
        for a single hop).  Mirrors the paper's CVE -> CWE -> CAPEC -> ATTACK
        Cypher traversals (Figs. 14, 15, 17).
        """
        _check_label(start_label)
        if not hops:
            raise ValueError("At least one hop is required")
        pattern = f"(n0:{start_label} {{id: $id}})"
        for index, (rel, direction, label) in enumerate(hops, start=1):
            _check_rel(rel)
            _check_label(label)
            if direction == "out":
                pattern += f"-[:{rel}]->(n{index}:{label})"
            elif direction == "in":
                pattern += f"<-[:{rel}]-(n{index}:{label})"
            else:
                raise ValueError(f"Invalid direction {direction!r}")
        last, prev = f"n{len(hops)}", f"n{len(hops) - 1}"
        rows = self._read(
            f"MATCH {pattern} WHERE {last} <> n0 "
            f"WITH {last} AS node, collect(DISTINCT {prev}.id) AS via "
            "ORDER BY node.id "
            "WITH collect({node: node {.*, embedding: null}, via: via}) AS items "
            "RETURN size(items) AS total, items[0..$limit] AS items",
            id=start_id, limit=int(limit))
        if not rows:
            return {"nodes": [], "total": 0}
        nodes = []
        for item in rows[0]["items"]:
            node = strip_embedding(item["node"]) or {}
            node["via"] = sorted(item["via"])
            nodes.append(node)
        nodes.sort(key=lambda n: _natural_key(n.get("id", "")))
        return {"nodes": nodes, "total": rows[0]["total"]}

    def count_related(self, start_label: str, start_id: str, hop: Hop) -> int:
        rel, direction, label = hop
        _check_label(start_label), _check_rel(rel), _check_label(label)
        arrow = f"-[:{rel}]->" if direction == "out" else f"<-[:{rel}]-"
        rows = self._read(
            f"MATCH (n:{start_label} {{id: $id}}){arrow}(m:{label}) RETURN count(DISTINCT m) AS c",
            id=start_id)
        return rows[0]["c"] if rows else 0

    def vector_search(self, label: str, vector: Sequence[float], k: int = 5) -> list[dict]:
        """Top-k cosine neighbours via the Neo4j vector index. [] if unavailable."""
        _check_label(label)
        if not self.vector_search_available or not vector:
            return []
        try:
            rows = self._read(
                "CALL db.index.vector.queryNodes($index, $k, $vector) YIELD node, score "
                "RETURN node {.*, embedding: null} AS node, score ORDER BY score DESC",
                index=VECTOR_INDEXES[label], k=int(k), vector=list(vector))
        except Neo4jError as exc:
            log.warning("Vector search on %s failed: %s", label, exc.code)
            return []
        return [{**(strip_embedding(r["node"]) or {}), "_score": float(r["score"]),
                 "_label": label} for r in rows]

    def name_search(self, text: str, labels: Sequence[str] = FULLTEXT_LABELS,
                    k: int = 5) -> list[dict]:
        """Full-text search over CWE / CAPEC / ATT&CK names."""
        wanted = [_check_label(label) for label in labels]
        tokens = re.findall(r"[A-Za-z0-9]{2,}", text)[:24]   # strips all Lucene syntax
        if not tokens:
            return []
        try:
            rows = self._read(
                "CALL db.index.fulltext.queryNodes($index, $q, {limit: $k}) YIELD node, score "
                "WHERE any(l IN labels(node) WHERE l IN $labels) "
                "RETURN node {.*, embedding: null} AS node, score, "
                "[l IN labels(node) WHERE l IN $labels][0] AS label",
                index=FULLTEXT_INDEX, q=" ".join(tokens), k=int(k) * 3, labels=wanted)
        except Neo4jError as exc:
            log.warning("Full-text search failed: %s", exc.code)
            return []
        return [{**(strip_embedding(r["node"]) or {}), "_score": float(r["score"]),
                 "_label": r["label"]} for r in rows][:k]

    def cve_text_search(self, required: Sequence[Sequence[str]],
                        optional: Sequence[str] = (), k: int = 8) -> dict:
        """Full-text search over CVE descriptions.

        ``required`` is a list of groups; every group must match and a group matches
        when any of its alternatives (a word or a phrase) occurs in the description.
        ``optional`` words only raise the ranking.  Returns {"total", "nodes"}.
        """
        def clause(text: str) -> str:
            words = re.findall(r"[A-Za-z0-9]+", text.lower())[:6]   # strips all Lucene syntax
            if not words:
                return ""
            return words[0] if len(words) == 1 else '"' + " ".join(words) + '"'

        parts = []
        for group in list(required)[:12]:
            alternatives = [c for c in (clause(a) for a in list(group)[:6]) if c]
            if alternatives:
                parts.append("+(" + " ".join(alternatives) + ")")
        if not parts:
            return {"total": 0, "nodes": []}
        parts += [c for c in (clause(o) for o in list(optional)[:8]) if c]
        query = " ".join(parts)
        try:
            rows = self._read(
                "CALL db.index.fulltext.queryNodes($index, $q, {limit: $k}) YIELD node, score "
                "RETURN node {.*, embedding: null} AS node, score",
                index=CVE_TEXT_INDEX, q=query, k=int(k))
            total = self._read(
                "CALL db.index.fulltext.queryNodes($index, $q, {limit: 1000}) YIELD node "
                "RETURN count(node) AS c", index=CVE_TEXT_INDEX, q=query)
        except Neo4jError as exc:
            log.warning("CVE description search failed: %s", exc.code)
            return {"total": 0, "nodes": []}
        nodes = [{**(strip_embedding(r["node"]) or {}), "_score": float(r["score"]),
                  "_label": LABEL_CVE} for r in rows]
        return {"total": max(total[0]["c"] if total else 0, len(nodes)), "nodes": nodes}

    # ------------------------------------------------------------------ #
    # Knowledge-graph explorer
    # ------------------------------------------------------------------ #
    @staticmethod
    def _brief(node: dict, label: str) -> dict:
        return {"id": node.get("id"), "label": label, "name": node.get("name") or node.get("id"),
                "severity": node.get("severity"), "base_score": node.get("base_score")}

    def graph_search(self, text: str, limit: int = 8) -> list[dict]:
        """Find entities by identifier (prefix) or by name. Parameterised, label whitelisted."""
        query = (text or "").strip()[:80]
        if not query:
            return []
        upper = query.upper()
        results: list[dict] = []
        prefix = None
        if re.fullmatch(r"(CVE|CWE|CAPEC)-?[0-9-]*", upper):
            label = upper.split("-")[0] if "-" in upper else re.match(r"[A-Z]+", upper).group(0)
            digits = upper[len(label):].lstrip("-")
            prefix = (label, f"{label}-{digits}")
        elif re.fullmatch(r"T\d{0,4}(\.\d{0,3})?", upper):
            prefix = (LABEL_ATTACK, upper)
        elif upper.isdigit():
            for label in (LABEL_CWE, LABEL_CAPEC):
                results += self._prefix_lookup(label, f"{label}-{upper}", limit)
        if prefix:
            results += self._prefix_lookup(prefix[0], prefix[1], limit)
        if len(results) < limit:
            seen = {r["id"] for r in results}
            for hit in self.name_search(query, GRAPH_LABELS, k=limit):
                if hit.get("id") not in seen:
                    results.append(self._brief(hit, hit["_label"]))
        return results[:limit]

    def _prefix_lookup(self, label: str, prefix: str, limit: int) -> list[dict]:
        _check_label(label)
        rows = self._read(
            f"MATCH (n:{label}) WHERE n.id STARTS WITH $p "
            "RETURN n {.id, .name, .severity, .base_score} AS node ORDER BY n.id LIMIT $limit",
            p=prefix, limit=int(limit) * 4)
        nodes = sorted((r["node"] for r in rows), key=lambda n: _natural_key(n["id"]))
        return [self._brief(n, label) for n in nodes[:limit]]

    def graph_entity(self, node_id: str, per_group: int = 10) -> dict | None:
        """Details of one entity plus a bounded sample of its neighbours, grouped by relation."""
        label = label_for_id(node_id)
        if label is None:
            return None
        node_id = node_id.strip().upper()
        node = self.get_node(label, node_id)
        if node is None:
            return None
        rels = list(REL_TYPES)
        rows = self._read(
            f"MATCH (n:{label} {{id: $id}})-[r]-(m) WHERE type(r) IN $rels AND m <> n "
            "RETURN type(r) AS rel, startNode(r) = n AS outgoing, [l IN labels(m) WHERE l IN $labels][0] AS label, "
            "count(DISTINCT m) AS total", id=node_id, rels=rels, labels=list(GRAPH_LABELS))
        groups = []
        for row in sorted(rows, key=lambda r: (r["rel"], not r["outgoing"])):
            rel, outgoing, other = row["rel"], bool(row["outgoing"]), row["label"]
            if other is None:
                continue
            _check_rel(rel), _check_label(other)
            arrow = f"-[:{rel}]->" if outgoing else f"<-[:{rel}]-"
            sample = self._read(
                f"MATCH (n:{label} {{id: $id}}){arrow}(m:{other}) WHERE m <> n "
                "RETURN m {.id, .name, .severity, .base_score} AS node "
                "ORDER BY coalesce(m.base_score, 0) DESC, m.id LIMIT $limit",
                id=node_id, limit=int(per_group))
            nodes = [self._brief(r["node"], other) for r in sample]
            groups.append({"rel": rel, "outgoing": outgoing, "label": other, "total": row["total"],
                           "nodes": sorted(nodes, key=lambda n: _natural_key(n["id"]))})
        props = {k: (v[:40] if isinstance(v, list) else v) for k, v in node.items()
                 if k not in _HIDDEN_PROPS and v not in (None, "", [])}
        list_sizes = {k: len(v) for k, v in node.items() if isinstance(v, list) and len(v) > 40}
        return {"id": node_id, "label": label, "properties": props, "list_sizes": list_sizes, "groups": groups}

    def graph_overview(self, per_label: int = 3) -> list[dict]:
        """The best-connected CWE / CAPEC / ATT&CK entities: a sensible place to start exploring."""
        cached = getattr(self, "_overview_cache", None)
        if cached and (datetime.now(timezone.utc) - cached[0]).total_seconds() < 600:
            return cached[1]
        out: list[dict] = []
        for label in (LABEL_CWE, LABEL_CAPEC, LABEL_ATTACK):
            rows = self._read(
                f"MATCH (n:{label}) WITH n, size([(n)--() | 1]) AS degree ORDER BY degree DESC LIMIT $k "
                "RETURN n {.id, .name} AS node", k=int(per_label))
            out += [self._brief(r["node"], label) for r in rows]
        if out:
            self._overview_cache = (datetime.now(timezone.utc), out)
        return out

    # ------------------------------------------------------------------ #
    # Statistics
    # ------------------------------------------------------------------ #
    def counts(self) -> dict:
        nodes = {label: self._read(f"MATCH (n:{label}) RETURN count(n) AS c")[0]["c"]
                 for label in NODE_LABELS}
        rels = {rel: self._read(f"MATCH ()-[r:{rel}]->() RETURN count(r) AS c")[0]["c"]
                for rel in REL_TYPES}
        return {"nodes": nodes, "relationships": rels}

    def server_info(self) -> dict:
        rows = self._read("CALL dbms.components() YIELD name, versions, edition "
                          "RETURN name, versions[0] AS version, edition")
        return rows[0] if rows else {}


def _natural_key(identifier: str):
    return [int(part) if part.isdigit() else part for part in re.split(r"(\d+)", identifier)]
