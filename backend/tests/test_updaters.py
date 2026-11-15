"""Updater tests: parsing, pagination, windows, idempotency, failure handling."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from backend.database import (
    REL_CAN_PRECEDE, REL_CAPEC_ATTACK, REL_CAPEC_CHILD, REL_CVE_CWE, REL_CWE_CAPEC, REL_CWE_CHILD,
    REL_SUBTECHNIQUE_OF,
)
from backend.tests.conftest import ATTACK_BUNDLE, CAPEC_XML, CWE_XML, Harness, nvd_item, zipped
from backend.updater.attack_updater import parse_attack_bundles
from backend.updater.capec_updater import parse_capec_catalog
from backend.updater.cve_updater import parse_cve, parse_iso, split_windows
from backend.updater.cwe_updater import parse_cwe_catalog
from backend.updater.data_processor import (
    DataValidationError, FetchError, http_get, normalize_attack_id, normalize_cwe_id, parse_xml,
)
import json


# --------------------------------------------------------------------------- #
# Parsing
# --------------------------------------------------------------------------- #
def test_cwe_xml_parsing_from_zip():
    rows, meta = parse_cwe_catalog(zipped(CWE_XML))
    by_id = {r["id"]: r for r in rows}
    assert meta["version"] == "9.9" and meta["weaknesses"] == 3
    assert "CWE-999" not in by_id                       # deprecated entries are skipped
    cwe89 = by_id["CWE-89"]
    assert cwe89["name"].startswith("Improper Neutralization of Special Elements used in an SQL")
    assert cwe89["category"] == "Base"
    assert cwe89["child_of_ids"] == ["CWE-943"]          # only ChildOf, not PeerOf
    assert cwe89["related_capec_ids"] == ["CAPEC-66", "CAPEC-7"]
    assert cwe89["alternate_terms"] == ["SQLi"]
    assert cwe89["mitigations"] == ["[Implementation] Use parameterized queries always ."]
    assert cwe89["member_of_categories"] == ["Data Neutralization Issues"]
    assert by_id["CWE-137"]["category"] == "Category"


def test_cwe_5x_groupings_schema_is_supported():
    xml = CWE_XML.replace("Categories>", "Groupings>").replace("Category", "Grouping")
    rows, _ = parse_cwe_catalog(xml.encode())
    assert {r["id"]: r for r in rows}["CWE-137"]["name"] == "Data Neutralization Issues"


def test_capec_xml_parsing():
    rows, meta = parse_capec_catalog(CAPEC_XML.encode())
    by_id = {r["id"]: r for r in rows}
    assert meta["attack_patterns"] == 4 and meta["deprecated_skipped"] == 1
    capec66 = by_id["CAPEC-66"]
    assert (capec66["name"], capec66["severity"], capec66["likelihood"]) == ("SQL Injection", "High", "High")
    assert capec66["childOf"] == ["CAPEC-248"] and capec66["can_precede_ids"] == ["CAPEC-7"]
    assert capec66["related_cwe_ids"] == ["CWE-89"]
    assert capec66["mitigations"] == ["Strong input validation of all user-controllable input."]
    assert by_id["CAPEC-98"]["attack_ids"] == ["T1566"]   # only the ATTACK taxonomy, not WASC
    assert by_id["CAPEC-98"]["can_follow_ids"] == ["CAPEC-248"]


def test_stix_parsing_filters_object_types():
    rows, meta = parse_attack_bundles([json.dumps(ATTACK_BUNDLE).encode()])
    by_id = {r["id"]: r for r in rows}
    assert set(by_id) == {"T1566", "T1566.001", "T1059"}  # no malware, tactic or revoked object
    assert meta["skipped"]["revoked_or_deprecated"] == 1
    assert by_id["T1566"]["tactics"] == ["initial-access"]
    assert by_id["T1566"]["type"] == "technique"
    assert by_id["T1566.001"]["type"] == "sub-technique"
    assert by_id["T1566.001"]["parent_ids"] == ["T1566"]  # from the relationship object
    assert by_id["T1566"]["mitigations"] == [
        "M1017 User Training: Train users to identify social engineering techniques."]
    assert "(Citation" not in by_id["T1059"]["description"]


def test_malformed_sources_are_rejected():
    with pytest.raises(DataValidationError):
        parse_xml(b"<Weakness_Catalog><broken></Weakness_Catalog>")
    with pytest.raises(DataValidationError):
        parse_xml(b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "b">]><x>&a;</x>')
    with pytest.raises(DataValidationError):
        parse_capec_catalog(CWE_XML.encode())             # wrong catalogue type
    with pytest.raises(DataValidationError):
        parse_attack_bundles([b'{"type": "report"}'])
    with pytest.raises(DataValidationError):
        parse_attack_bundles([b"not json"])


def test_identifier_normalisation():
    assert normalize_cwe_id("cwe 89") == "CWE-89" and normalize_cwe_id("NVD-CWE-noinfo") is None
    assert normalize_attack_id("1574.010") == "T1574.010" and normalize_attack_id("TA0002") is None


def test_cve_parsing_complete_record():
    row = parse_cve(nvd_item("CVE-2024-0001", "SQL injection.", cwes=["CWE-89", "NVD-CWE-Other"], score=9.8))
    assert row["base_score"] == 9.8 and row["severity"] == "CRITICAL" and row["cvss_version"] == "3.1"
    assert row["impact_score"] == 5.9 and row["exploitability_score"] == 3.9
    assert row["related_cwe_ids"] == ["CWE-89"]
    assert row["patch_urls"] == ["https://vendor.test/advisory/CVE-2024-0001"]


def test_cve_parsing_missing_cvss_and_cwe_stay_empty():
    row = parse_cve(nvd_item("CVE-2024-0002", "No metrics.", cwes=["NVD-CWE-noinfo"]))
    assert row["base_score"] is None and row["severity"] is None
    assert row["impact_score"] is None and row["exploitability_score"] is None
    assert row["related_cwe_ids"] == []
    assert parse_cve({"cve": {"id": "not-a-cve"}}) is None and parse_cve({}) is None


# --------------------------------------------------------------------------- #
# NVD pagination, windows, checkpoints
# --------------------------------------------------------------------------- #
def test_nvd_pagination_initial_sync(harness: Harness):
    result = harness.cve.sync()
    assert result.status == "success" and result.records == 3
    assert [r["startIndex"] for r in harness.sources.nvd_requests] == ["0", "2"]
    assert all(r["resultsPerPage"] == "2" for r in harness.sources.nvd_requests)
    assert set(harness.db.nodes["CVE"]) == {"CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003"}
    state = harness.db.get_sync_state("nvd")
    # checkpoint = sync start minus the overlap, and resume markers are cleared
    assert parse_iso(state["checkpoint"]) == harness.clock_now - timedelta(minutes=15)
    assert "full_sync_next_index" not in state and state["status"] == "success"


def test_nvd_incremental_update_window(harness: Harness):
    harness.cve.sync()
    harness.sources.nvd_requests.clear()
    first_checkpoint = parse_iso(harness.db.get_sync_state("nvd")["checkpoint"])
    harness.clock_now = harness.clock_now + timedelta(hours=2)
    harness.sources.nvd_items = [nvd_item("CVE-2024-0001", "SQL injection (updated text).",
                                          cwes=["CWE-89"], score=9.8)]
    result = harness.cve.sync()
    assert result.status == "success" and result.details["mode"] == "incremental"
    request = harness.sources.nvd_requests[0]
    # the window starts *before* the checkpoint (overlap) and ends at "now"
    assert parse_iso(request["lastModStartDate"]) == first_checkpoint - timedelta(minutes=15)
    assert parse_iso(request["lastModEndDate"]) == harness.clock_now
    assert harness.db.nodes["CVE"]["CVE-2024-0001"]["description"] == "SQL injection (updated text)."
    assert parse_iso(harness.db.get_sync_state("nvd")["checkpoint"]) == harness.clock_now
    assert len(harness.db.nodes["CVE"]) == 3            # nothing lost, nothing duplicated


def test_nvd_windows_never_exceed_120_days():
    start = datetime(2025, 1, 1, tzinfo=timezone.utc)
    windows = split_windows(start, start + timedelta(days=300), 120)
    assert len(windows) == 3 and windows[0][0] == start and windows[-1][1] == start + timedelta(days=300)
    assert all((b - a) <= timedelta(days=120) for a, b in windows)
    assert all(windows[i][1] == windows[i + 1][0] for i in range(2))


def test_nvd_long_gap_uses_several_windows(harness: Harness):
    harness.cve.sync()
    harness.sources.nvd_requests.clear()
    harness.clock_now = harness.clock_now + timedelta(days=200)
    assert harness.cve.sync().details["windows"] == 2
    starts = {r["lastModStartDate"] for r in harness.sources.nvd_requests}
    assert len(starts) == 2


def test_nvd_failed_sync_does_not_advance_checkpoint_and_recovers(harness: Harness):
    harness.cve.sync()
    checkpoint = harness.db.get_sync_state("nvd")["checkpoint"]
    harness.clock_now = harness.clock_now + timedelta(hours=3)
    harness.sources.fail_status["nvd.test"] = 503
    failed = harness.cve.sync()
    state = harness.db.get_sync_state("nvd")
    assert failed.status == "failed" and state["status"] == "failed" and state["last_error"]
    assert state["checkpoint"] == checkpoint            # unchanged
    assert len(harness.db.nodes["CVE"]) == 3            # existing records untouched
    # recovery: the next run repeats the same window from the old checkpoint
    del harness.sources.fail_status["nvd.test"]
    harness.sources.nvd_requests.clear()
    assert harness.cve.sync().status == "success"
    assert parse_iso(harness.sources.nvd_requests[0]["lastModStartDate"]) == \
        parse_iso(checkpoint) - timedelta(minutes=15)
    assert "last_error" not in harness.db.get_sync_state("nvd")


def test_nvd_initial_sync_resumes_after_interruption(harness: Harness):
    harness.sources.nvd_fail_at_start_index = 2          # second page fails
    assert harness.cve.sync().status == "failed"
    state = harness.db.get_sync_state("nvd")
    assert "checkpoint" not in state and state["full_sync_next_index"] == 2
    assert len(harness.db.nodes["CVE"]) == 2             # first page was persisted
    harness.sources.nvd_fail_at_start_index = None
    harness.sources.nvd_requests.clear()
    result = harness.cve.sync()
    assert result.status == "success" and "resumed" in result.details["mode"]
    assert harness.sources.nvd_requests[0]["startIndex"] == "2"
    assert len(harness.db.nodes["CVE"]) == 3 and "checkpoint" in harness.db.get_sync_state("nvd")


def test_checkpoint_not_advanced_when_database_write_fails(harness: Harness):
    harness.cve.sync()
    checkpoint = harness.db.get_sync_state("nvd")["checkpoint"]
    harness.clock_now = harness.clock_now + timedelta(hours=1)
    original = harness.db.upsert_cves
    harness.db.upsert_cves = lambda rows, batch_size=500: (_ for _ in ()).throw(RuntimeError("write failed"))
    harness.sources.nvd_items = [nvd_item("CVE-2024-0009", "New record.", score=5.0)]
    assert harness.cve.sync().status == "failed"
    assert harness.db.get_sync_state("nvd")["checkpoint"] == checkpoint
    harness.db.upsert_cves = original
    assert harness.cve.sync().status == "success" and "CVE-2024-0009" in harness.db.nodes["CVE"]


def test_http_retry_with_backoff_then_error():
    import httpx
    calls, delays = [], []

    def handler(request):
        calls.append(1)
        return httpx.Response(503 if len(calls) < 3 else 200, content=b"ok")

    client = httpx.Client(transport=httpx.MockTransport(handler))
    assert http_get(client, "https://x.test/a", max_retries=3, sleep=delays.append).content == b"ok"
    assert delays == [2.0, 4.0]                           # exponential backoff
    always_down = httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(500)))
    with pytest.raises(FetchError):
        http_get(always_down, "https://x.test/a", max_retries=2, sleep=lambda s: None)
    not_found = httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(404)))
    with pytest.raises(FetchError):
        http_get(not_found, "https://x.test/a", max_retries=5, sleep=delays.append)
    assert delays == [2.0, 4.0]                           # 404 is not retried


# --------------------------------------------------------------------------- #
# Graph construction, relationships, idempotency
# --------------------------------------------------------------------------- #
def test_relationship_extraction_builds_expected_edges(harness: Harness):
    harness.sync_all()
    db = harness.db
    assert db.edge_set(REL_CWE_CHILD) == {("CWE-89", "CWE-943")}
    assert db.edge_set(REL_CWE_CAPEC) == {("CWE-89", "CAPEC-66"), ("CWE-89", "CAPEC-7")}
    assert db.edge_set(REL_CAPEC_CHILD) == {("CAPEC-66", "CAPEC-248"), ("CAPEC-7", "CAPEC-66")}
    # CanPrecede as stated, and "98 CanFollow 248" stored as 248 CAN_PRECEDE 98
    assert db.edge_set(REL_CAN_PRECEDE) == {("CAPEC-66", "CAPEC-7"), ("CAPEC-248", "CAPEC-98")}
    assert db.edge_set(REL_CAPEC_ATTACK) == {("CAPEC-98", "T1566")}
    assert db.edge_set(REL_SUBTECHNIQUE_OF) == {("T1566.001", "T1566")}
    assert db.edge_set(REL_CVE_CWE) == {("CVE-2024-0001", "CWE-89"), ("CVE-2024-0003", "CWE-79")}


def test_edges_only_link_existing_nodes(harness: Harness):
    harness.capec.sync()                                  # CAPEC before CWE / ATT&CK exist
    assert harness.db.edge_set(REL_CWE_CAPEC) == set()
    assert harness.db.edge_set(REL_CAPEC_ATTACK) == set()
    harness.cwe.sync()
    harness.attack.sync()
    assert ("CWE-89", "CAPEC-66") in harness.db.edge_set(REL_CWE_CAPEC)
    assert harness.db.edge_set(REL_CAPEC_ATTACK) == {("CAPEC-98", "T1566")}


def test_cves_stored_before_cwes_are_linked_later(harness: Harness):
    harness.cve.sync()
    assert harness.db.edge_set(REL_CVE_CWE) == set()
    harness.cwe.sync()
    assert ("CVE-2024-0001", "CWE-89") in harness.db.edge_set(REL_CVE_CWE)


def test_repeated_synchronisation_creates_no_duplicates(harness: Harness):
    harness.sync_all()
    before = harness.db.counts()
    edges_before = {rel: harness.db.edge_set(rel) for rel in before["relationships"]}
    for updater in (harness.cwe, harness.capec, harness.attack):
        assert updater.sync(force=True).status == "success"
    assert harness.cve.sync(full=True).status == "success"
    assert harness.db.counts() == before
    assert {rel: harness.db.edge_set(rel) for rel in before["relationships"]} == edges_before


def test_unchanged_source_is_detected_by_hash(harness: Harness):
    assert harness.cwe.sync().status == "success"
    writes = harness.db.write_calls
    second = harness.cwe.sync()
    assert second.status == "unchanged"
    assert harness.db.get_sync_state("cwe")["status"] == "success"
    assert harness.db.write_calls <= writes + 2           # only status bookkeeping


def test_changed_record_and_removed_relationship_are_applied(harness: Harness):
    harness.sync_all()
    harness.sources.cwe_xml = CWE_XML.replace(
        '<Related_Weakness Nature="ChildOf" CWE_ID="943" View_ID="1000" Ordinal="Primary"/>', "") \
        .replace("externally-influenced input.", "externally-influenced input from an upstream component.")
    result = harness.cwe.sync()
    assert result.status == "success" and result.changed == 1
    assert "upstream component" in harness.db.nodes["CWE"]["CWE-89"]["description"]
    assert harness.db.edge_set(REL_CWE_CHILD) == set()     # edge the source withdrew is removed
    # CWE_CAPEC is still asserted by the CAPEC feed, so those edges must survive
    assert harness.db.edge_set(REL_CWE_CAPEC) == {("CWE-89", "CAPEC-66"), ("CWE-89", "CAPEC-7")}
    assert len(harness.db.nodes["CWE"]) == 4


def test_failed_mitre_download_keeps_existing_data(harness: Harness):
    harness.sync_all()
    before = harness.db.counts()
    good_hash = harness.db.get_sync_state("capec")["content_hash"]
    harness.sources.fail_status["capec.test"] = 500
    result = harness.capec.sync()
    state = harness.db.get_sync_state("capec")
    assert result.status == "failed" and state["status"] == "failed" and "500" in state["last_error"]
    assert state["content_hash"] == good_hash and harness.db.counts() == before


def test_malformed_or_shrunken_update_is_refused(harness: Harness):
    harness.sync_all()
    before = harness.db.counts()
    harness.sources.capec_xml = "<Attack_Pattern_Catalog><oops>"
    assert harness.capec.sync().status == "failed"
    one_pattern = CAPEC_XML.split('<Attack_Pattern ID="7"')[0] + "</Attack_Patterns></Attack_Pattern_Catalog>"
    harness.sources.capec_xml = one_pattern               # 1 of 4 records left: suspicious
    result = harness.capec.sync()
    assert result.status == "failed" and "suspicious" in result.error
    assert harness.db.counts() == before


def test_embeddings_are_only_recomputed_for_changed_text(harness: Harness):
    harness.cwe.sync()
    calls = []
    original = harness.embedder.embed
    harness.embedder.embed = lambda texts: calls.append(len(texts)) or original(texts)
    assert harness.cwe.sync(force=True).status == "success"
    assert calls == []                                    # nothing changed -> no embedding call
    assert len(harness.db.nodes["CWE"]["CWE-89"]["embedding"]) == 128
