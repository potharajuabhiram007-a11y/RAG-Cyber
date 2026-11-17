"""MAX_CVES: keep only the most recently published CVEs (fits AuraDB Free)."""
from __future__ import annotations

from backend.database import REL_CVE_CWE
from backend.tests.conftest import Harness, make_settings, nvd_item


def cve(n: int, year: int, desc: str = "Buffer overflow in a parser.", cwes=("CWE-89",)):
    return nvd_item(f"CVE-{year}-{n:04d}", desc, cwes=list(cwes),
                    published=f"{year}-0{1 + n % 9}-01T00:00:00.000")


def capped(cap: int) -> Harness:
    h = Harness(make_settings(max_cves=cap))
    for updater in (h.cwe, h.capec, h.attack):
        assert updater.sync().ok
    return h


def test_without_a_cap_every_cve_is_kept():
    h = capped(0)
    h.sources.nvd_items = [cve(i, 2020 + i % 5) for i in range(10)]
    assert h.cve.sync().ok
    assert h.db.cve_count() == 10


def test_cap_keeps_the_newest_cves_and_their_edges_only():
    h = capped(4)
    h.sources.nvd_items = [cve(i, 2020 + i % 5) for i in range(10)]
    result = h.cve.sync()
    assert result.ok and result.details["pruned"] == 6
    kept = set(h.db.nodes["CVE"])
    assert len(kept) == 4
    assert all(cve_id.startswith(("CVE-2024", "CVE-2023")) for cve_id in kept), kept
    assert {a for a, _ in h.db.edge_set(REL_CVE_CWE)} <= kept      # no edges to deleted CVEs


def test_old_cves_modified_later_are_not_stored_once_the_cap_is_full():
    h = capped(3)
    h.sources.nvd_items = [cve(i, 2025) for i in range(3)]
    assert h.cve.sync().ok
    before = set(h.db.nodes["CVE"])
    # the next update reports an old CVE (NVD modifies old records) and a new one
    h.clock_now = h.clock_now.replace(day=20)
    h.sources.nvd_items = [cve(7, 2015), cve(9, 2026)]
    result = h.cve.sync()
    assert result.ok
    assert "CVE-2015-0007" not in h.db.nodes["CVE"]               # skipped, never embedded
    assert "CVE-2026-0009" in h.db.nodes["CVE"]
    assert h.db.cve_count() == 3 and len(before & set(h.db.nodes["CVE"])) == 2


def test_kept_cves_are_still_updated():
    h = capped(2)
    h.sources.nvd_items = [cve(1, 2025, "Old text."), cve(2, 2026)]
    assert h.cve.sync().ok
    h.clock_now = h.clock_now.replace(day=20)
    h.sources.nvd_items = [cve(1, 2025, "Corrected description of the flaw.")]
    assert h.cve.sync().ok
    assert h.db.nodes["CVE"]["CVE-2025-0001"]["description"] == "Corrected description of the flaw."


def test_copy_to_moves_the_newest_cves_with_embeddings_edges_and_checkpoints(capsys):
    from backend.manage import copy_to
    from backend.tests.fakes import InMemoryGraph

    h = capped(0)
    h.sources.nvd_items = [cve(i, 2020 + i % 5) for i in range(10)]
    assert h.cve.sync().ok
    target = InMemoryGraph()
    summary = copy_to(h.db, target, h.embedder.dimensions, max_cves=4)

    assert target.cve_count() == 4 and summary["copied"]["CVE"] >= 4
    newest = sorted(h.db.nodes["CVE"], key=lambda i: h.db.nodes["CVE"][i]["published"])[-4:]
    assert set(target.nodes["CVE"]) == set(newest)
    for label in ("CWE", "CAPEC", "ATTACK"):
        assert set(target.nodes[label]) == set(h.db.nodes[label])
    sample = next(iter(target.nodes["CVE"].values()))
    assert sample["embedding"] == h.db.nodes["CVE"][sample["id"]]["embedding"]   # not re-embedded
    assert target.edge_set(REL_CVE_CWE) == {e for e in h.db.edge_set(REL_CVE_CWE) if e[0] in target.nodes["CVE"]}
    for rel in ("CWE_CAPEC", "CAPEC_ATTACK"):
        assert target.edge_set(rel) == h.db.edge_set(rel)
    assert target.get_sync_state("nvd")["checkpoint"] == h.db.get_sync_state("nvd")["checkpoint"]


def test_max_cves_setting(monkeypatch):
    from backend.config import load_settings
    monkeypatch.setattr("backend.config.load_dotenv", lambda *a, **k: None)
    for name, value in (("NEO4J_URI", "bolt://x"), ("NEO4J_USERNAME", "u"), ("NEO4J_PASSWORD", "p"),
                        ("MAX_CVES", "120000")):
        monkeypatch.setenv(name, value)
    assert load_settings().max_cves == 120000
    monkeypatch.setenv("MAX_CVES", "")
    assert load_settings().max_cves == 0
