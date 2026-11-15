"""In-memory stand-in for ``Neo4jDatabase`` used by the automated tests.

It implements the same public methods with plain dictionaries so the updaters,
retriever, generator and API can be tested without a running Neo4j server.  The
relationship rules are imported from ``backend.database`` (``REL_RULES``), so
the graph-building logic under test is the production logic; only the Cypher
execution itself is replaced.
"""
from __future__ import annotations

import math
import re
from typing import Sequence

from backend.database import (
    GRAPH_LABELS, label_for_id,
    FULLTEXT_LABELS, NODE_LABELS, REL_CVE_CWE, REL_ENDPOINTS, REL_RULES, REL_TYPES, Hop,
    strip_embedding,
)


class InMemoryGraph:
    vector_search_available = True

    def __init__(self):
        self.nodes: dict[str, dict[str, dict]] = {label: {} for label in NODE_LABELS}
        self.edges: dict[str, dict[tuple[str, str], dict]] = {rel: {} for rel in REL_TYPES}
        self.sync_states: dict[str, dict] = {}
        self.fail_writes_after: int | None = None     # raise once this many writes happened
        self.write_calls = 0
        self.schema_dimensions: int | None = None

    # -- helpers --------------------------------------------------------- #
    def _count_write(self) -> None:
        self.write_calls += 1
        if self.fail_writes_after is not None and self.write_calls > self.fail_writes_after:
            raise RuntimeError("simulated Neo4j write failure")

    # -- connection / schema --------------------------------------------- #
    def verify(self) -> bool:
        return True

    def close(self) -> None:
        pass

    def init_schema(self, embedding_dimensions: int) -> None:
        self.schema_dimensions = embedding_dimensions

    def server_info(self) -> dict:
        return {"name": "in-memory test graph", "version": "test", "edition": "test"}

    # -- writes ---------------------------------------------------------- #
    def upsert_nodes(self, label: str, rows: Sequence[dict], batch_size: int = 500) -> int:
        self._count_write()
        for row in rows:
            node = self.nodes[label].setdefault(row["id"], {})
            for key, value in row.items():
                if value is None:
                    node.pop(key, None)
                else:
                    node[key] = value
        return len(rows)

    def upsert_cves(self, rows: Sequence[dict], batch_size: int = 500) -> int:
        written = self.upsert_nodes("CVE", rows)
        for row in rows:
            wanted = set(row.get("related_cwe_ids") or [])
            for key in [k for k in self.edges[REL_CVE_CWE] if k[0] == row["id"] and k[1] not in wanted]:
                del self.edges[REL_CVE_CWE][key]
            for cwe_id in wanted:
                if cwe_id in self.nodes["CWE"]:
                    self.edges[REL_CVE_CWE][(row["id"], cwe_id)] = {"source": "NVD"}
        return written

    def link_cves_to_cwes(self) -> None:
        for cve_id, node in self.nodes["CVE"].items():
            for cwe_id in node.get("related_cwe_ids") or []:
                if cwe_id in self.nodes["CWE"]:
                    self.edges[REL_CVE_CWE].setdefault((cve_id, cwe_id), {"source": "NVD"})

    def get_property_map(self, label: str, ids: Sequence[str], prop: str) -> dict:
        return {i: self.nodes[label][i].get(prop) for i in ids if i in self.nodes[label]}

    def rebuild_relationships(self, rel_types: Sequence[str], sync_id: str) -> dict[str, int]:
        self._count_write()
        counts = {}
        for rel in rel_types:
            rebuilt: dict[tuple[str, str], dict] = {}
            for owner, prop, other, owner_is_start in REL_RULES[rel]:
                for owner_id, node in self.nodes[owner].items():
                    for other_id in node.get(prop) or []:
                        if other_id in self.nodes[other]:
                            key = (owner_id, other_id) if owner_is_start else (other_id, owner_id)
                            rebuilt[key] = {"sync_id": sync_id, "source": f"{owner}.{prop}"}
            self.edges[rel] = rebuilt
            counts[rel] = len(rebuilt)
        return counts

    def delete_stale_foundation(self, source_file: str, keep_ids: Sequence[str]) -> int:
        keep, removed = set(keep_ids), 0
        for label in ("CyberTerm", "CyberDocument"):
            for node_id in [i for i, n in self.nodes[label].items()
                            if n.get("source_file") == source_file and i not in keep]:
                del self.nodes[label][node_id]
                removed += 1
        return removed

    # -- sync state ------------------------------------------------------ #
    def get_sync_state(self, source: str) -> dict:
        return dict(self.sync_states.get(source) or {"source": source, "status": "never_run"})

    def save_sync_state(self, source: str, **fields) -> None:
        self._count_write()
        state = self.sync_states.setdefault(source, {"source": source})
        for key, value in fields.items():
            if value is None:
                state.pop(key, None)
            else:
                state[key] = value

    def all_sync_states(self) -> list[dict]:
        return [dict(self.sync_states[key]) for key in sorted(self.sync_states)]

    # -- reads ----------------------------------------------------------- #
    def list_terms(self) -> list[dict]:
        return [strip_embedding(n) for n in self.nodes["CyberTerm"].values()]

    def list_document_sections(self) -> list[dict]:
        return [strip_embedding(n) for n in self.nodes["CyberDocument"].values()]

    def foundation_version(self) -> str:
        return f"{len(self.nodes['CyberTerm'])}:{len(self.nodes['CyberDocument'])}"

    def get_node(self, label: str, node_id: str) -> dict | None:
        node = self.nodes[label].get(node_id)
        return strip_embedding(node) if node else None

    def _step(self, node_id: str, hop: Hop) -> list[str]:
        rel, direction, _ = hop
        if direction == "out":
            return [b for (a, b) in self.edges[rel] if a == node_id]
        return [a for (a, b) in self.edges[rel] if b == node_id]

    def traverse(self, start_label: str, start_id: str, hops: Sequence[Hop], limit: int = 15) -> dict:
        if start_id not in self.nodes[start_label]:
            return {"nodes": [], "total": 0}
        frontier = {start_id: {start_id}}            # node id -> ids of the previous hop
        for hop in hops:
            reached: dict[str, set[str]] = {}
            for node_id in frontier:
                for target in self._step(node_id, hop):
                    reached.setdefault(target, set()).add(node_id)
            frontier = reached
        frontier.pop(start_id, None)
        label = hops[-1][2]
        ordered = sorted(frontier, key=lambda i: [int(p) if p.isdigit() else p
                                                  for p in re.split(r"(\d+)", i)])
        nodes = [{**(strip_embedding(self.nodes[label][i]) or {}), "via": sorted(frontier[i])}
                 for i in ordered[:limit]]
        return {"nodes": nodes, "total": len(ordered)}

    def count_related(self, start_label: str, start_id: str, hop: Hop) -> int:
        return len(set(self._step(start_id, hop)))

    def vector_search(self, label: str, vector: Sequence[float], k: int = 5) -> list[dict]:
        if not vector:
            return []
        hits = []
        for node in self.nodes[label].values():
            other = node.get("embedding")
            if not other or len(other) != len(vector):
                continue
            dot = sum(a * b for a, b in zip(vector, other))
            norm = math.sqrt(sum(a * a for a in vector)) * math.sqrt(sum(b * b for b in other))
            if norm:
                hits.append({**(strip_embedding(node) or {}), "_score": (1 + dot / norm) / 2,
                             "_label": label})
        return sorted(hits, key=lambda h: -h["_score"])[:k]

    def cve_text_search(self, required, optional=(), k: int = 8) -> dict:
        def norm(text: str) -> str:
            return " " + " ".join(re.findall(r"[a-z0-9]+(?:\.[0-9]+)*", text.lower())) + " "

        groups = [[norm(a) for a in group] for group in required if group]
        if not groups:
            return {"total": 0, "nodes": []}
        hits = []
        for node in self.nodes["CVE"].values():
            text = norm(node.get("description") or "")
            if all(any(a in text for a in group) for group in groups):
                score = 1.0 + sum(norm(o) in text for o in optional)
                hits.append({**(strip_embedding(node) or {}), "_score": score, "_label": "CVE"})
        hits.sort(key=lambda h: (-h["_score"], h["id"]))
        return {"total": len(hits), "nodes": hits[:k]}

    def name_search(self, text: str, labels: Sequence[str] = FULLTEXT_LABELS, k: int = 5) -> list[dict]:
        tokens = {t.lower() for t in re.findall(r"[A-Za-z0-9]{2,}", text)}
        hits = []
        for label in labels:
            for node in self.nodes[label].values():
                name_tokens = {t.lower() for t in re.findall(r"[A-Za-z0-9]{2,}", node.get("name") or "")}
                overlap = len(tokens & name_tokens)
                if overlap:
                    hits.append({**(strip_embedding(node) or {}), "_label": label,
                                 "_score": overlap / math.sqrt(len(name_tokens) or 1)})
        return sorted(hits, key=lambda h: -h["_score"])[:k]

    # -- knowledge-graph explorer (same shapes as Neo4jDatabase) ---------- #
    @staticmethod
    def _brief(node: dict, label: str) -> dict:
        return {"id": node.get("id"), "label": label, "name": node.get("name") or node.get("id"),
                "severity": node.get("severity"), "base_score": node.get("base_score")}

    def graph_search(self, text: str, limit: int = 8) -> list[dict]:
        query = (text or "").strip().upper()
        if not query:
            return []
        hits = [self._brief(node, label) for label in GRAPH_LABELS
                for node_id, node in sorted(self.nodes[label].items()) if node_id.startswith(query)]
        seen = {h["id"] for h in hits}
        hits += [self._brief(h, h["_label"]) for h in self.name_search(text, GRAPH_LABELS, k=limit)
                 if h.get("id") not in seen]
        return hits[:limit]

    def graph_entity(self, node_id: str, per_group: int = 10) -> dict | None:
        label = label_for_id(node_id)
        node_id = node_id.strip().upper()
        if label is None or node_id not in self.nodes[label]:
            return None
        groups = []
        for rel in REL_TYPES:
            start, end = REL_ENDPOINTS[rel]
            for outgoing, other in ((True, end), (False, start)):
                if label != (start if outgoing else end):
                    continue
                ids = sorted(set(self._step(node_id, (rel, "out" if outgoing else "in", other))) - {node_id})
                if ids:
                    groups.append({"rel": rel, "outgoing": outgoing, "label": other, "total": len(ids),
                                   "nodes": [self._brief(self.nodes[other][i], other) for i in ids[:per_group]]})
        props = {k: v for k, v in (strip_embedding(self.nodes[label][node_id]) or {}).items()
                 if v not in (None, "", [])}
        return {"id": node_id, "label": label, "properties": props, "list_sizes": {}, "groups": groups}

    def graph_overview(self, per_label: int = 3) -> list[dict]:
        return [self._brief(node, label) for label in ("CWE", "CAPEC", "ATTACK")
                for node in list(self.nodes[label].values())[:per_label]]

    def counts(self) -> dict:
        return {"nodes": {label: len(self.nodes[label]) for label in NODE_LABELS},
                "relationships": {rel: len(self.edges[rel]) for rel in REL_TYPES}}

    # -- test conveniences ------------------------------------------------ #
    def edge_set(self, rel: str) -> set[tuple[str, str]]:
        assert rel in REL_ENDPOINTS
        return set(self.edges[rel])
