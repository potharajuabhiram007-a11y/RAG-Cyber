"""Shared fixtures: mocked official-source payloads and an in-memory graph.

No test talks to NVD, MITRE or Neo4j.  External HTTP is replaced by
``httpx.MockTransport`` and the database by ``InMemoryGraph``.
"""
from __future__ import annotations

import io
import json
import zipfile
from datetime import datetime, timezone

import httpx
import pytest

from backend.config import DATA_DIR, Settings
from backend.rag.generator import Assistant, Generator
from backend.rag.retriever import Retriever
from backend.tests.fakes import InMemoryGraph
from backend.updater.attack_updater import AttackUpdater
from backend.updater.capec_updater import CAPECUpdater
from backend.updater.cve_updater import CVEUpdater
from backend.updater.cwe_updater import CWEUpdater
from backend.updater.data_processor import EmbeddingClient, FoundationIngestor

CWE_URL = "https://cwe.test/cwec_latest.xml.zip"
CAPEC_URL = "https://capec.test/capec_latest.xml"
ATTACK_URL = "https://attack.test/enterprise-attack.json"
NVD_URL = "https://nvd.test/rest/json/cves/2.0"

CWE_XML = """<?xml version="1.0" encoding="UTF-8"?>
<Weakness_Catalog xmlns="http://cwe.mitre.org/cwe-7" Name="CWE" Version="9.9" Date="2026-01-01">
  <Weaknesses>
    <Weakness ID="89" Name="Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')" Abstraction="Base" Structure="Simple" Status="Stable">
      <Description>The product constructs all or part of an SQL command using externally-influenced input.</Description>
      <Related_Weaknesses>
        <Related_Weakness Nature="ChildOf" CWE_ID="943" View_ID="1000" Ordinal="Primary"/>
        <Related_Weakness Nature="PeerOf" CWE_ID="79" View_ID="1000"/>
      </Related_Weaknesses>
      <Alternate_Terms><Alternate_Term><Term>SQLi</Term></Alternate_Term></Alternate_Terms>
      <Likelihood_Of_Exploit>High</Likelihood_Of_Exploit>
      <Potential_Mitigations>
        <Mitigation><Phase>Implementation</Phase><Description>Use parameterized queries <xhtml:b xmlns:xhtml="http://www.w3.org/1999/xhtml">always</xhtml:b>.</Description></Mitigation>
      </Potential_Mitigations>
      <Related_Attack_Patterns>
        <Related_Attack_Pattern CAPEC_ID="66"/>
        <Related_Attack_Pattern CAPEC_ID="7"/>
      </Related_Attack_Patterns>
    </Weakness>
    <Weakness ID="943" Name="Improper Neutralization of Special Elements in Data Query Logic" Abstraction="Class" Structure="Simple" Status="Incomplete">
      <Description>The product generates a query intended to access or manipulate data in a data store.</Description>
    </Weakness>
    <Weakness ID="79" Name="Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')" Abstraction="Base" Structure="Simple" Status="Stable">
      <Description>The product does not neutralize user-controllable input before it is placed in output used as a web page.</Description>
    </Weakness>
    <Weakness ID="999" Name="DEPRECATED: Old weakness" Abstraction="Base" Structure="Simple" Status="Deprecated">
      <Description>Deprecated.</Description>
    </Weakness>
  </Weaknesses>
  <Categories>
    <Category ID="137" Name="Data Neutralization Issues" Status="Draft">
      <Summary>Weaknesses in this category are related to neutralization.</Summary>
      <Relationships><Has_Member CWE_ID="89" View_ID="699"/></Relationships>
    </Category>
  </Categories>
</Weakness_Catalog>
"""

CAPEC_XML = """<?xml version="1.0" encoding="UTF-8"?>
<Attack_Pattern_Catalog xmlns="http://capec.mitre.org/capec-3" Name="CAPEC" Version="9.9" Date="2026-01-01">
  <Attack_Patterns>
    <Attack_Pattern ID="66" Name="SQL Injection" Abstraction="Standard" Status="Draft">
      <Description>This attack exploits target software that constructs SQL statements based on user input.</Description>
      <Likelihood_Of_Attack>High</Likelihood_Of_Attack>
      <Typical_Severity>High</Typical_Severity>
      <Related_Attack_Patterns>
        <Related_Attack_Pattern Nature="ChildOf" CAPEC_ID="248"/>
        <Related_Attack_Pattern Nature="CanPrecede" CAPEC_ID="7"/>
      </Related_Attack_Patterns>
      <Mitigations><Mitigation>Strong input validation of all user-controllable input.</Mitigation></Mitigations>
      <Related_Weaknesses><Related_Weakness CWE_ID="89"/></Related_Weaknesses>
    </Attack_Pattern>
    <Attack_Pattern ID="7" Name="Blind SQL Injection" Abstraction="Detailed" Status="Draft">
      <Description>Blind SQL Injection results from an insufficient mitigation for SQL Injection.</Description>
      <Related_Attack_Patterns><Related_Attack_Pattern Nature="ChildOf" CAPEC_ID="66"/></Related_Attack_Patterns>
      <Related_Weaknesses><Related_Weakness CWE_ID="89"/></Related_Weaknesses>
    </Attack_Pattern>
    <Attack_Pattern ID="248" Name="Command Injection" Abstraction="Meta" Status="Stable">
      <Description>An adversary looking to execute a command of their choosing injects new items into an existing command.</Description>
    </Attack_Pattern>
    <Attack_Pattern ID="98" Name="Phishing" Abstraction="Standard" Status="Draft">
      <Description>Phishing is a social engineering technique where an attacker masquerades as a legitimate entity.</Description>
      <Related_Attack_Patterns><Related_Attack_Pattern Nature="CanFollow" CAPEC_ID="248"/></Related_Attack_Patterns>
      <Mitigations><Mitigation>Do not follow any links you receive within your e-mails.</Mitigation></Mitigations>
      <Taxonomy_Mappings>
        <Taxonomy_Mapping Taxonomy_Name="ATTACK"><Entry_ID>1566</Entry_ID><Entry_Name>Phishing</Entry_Name></Taxonomy_Mapping>
        <Taxonomy_Mapping Taxonomy_Name="WASC"><Entry_ID>19</Entry_ID></Taxonomy_Mapping>
      </Taxonomy_Mappings>
    </Attack_Pattern>
    <Attack_Pattern ID="500" Name="DEPRECATED: gone" Abstraction="Standard" Status="Deprecated">
      <Description>Deprecated.</Description>
    </Attack_Pattern>
  </Attack_Patterns>
</Attack_Pattern_Catalog>
"""


def _technique(stix_id, attack_id, name, tactic, sub=False, **extra):
    return {"type": "attack-pattern", "id": stix_id, "name": name,
            "description": f"Adversaries may use {name}. (Citation: Example)",
            "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": tactic}],
            "x_mitre_is_subtechnique": sub, "x_mitre_platforms": ["Windows", "Linux"],
            "x_mitre_domains": ["enterprise-attack"],
            "external_references": [{"source_name": "mitre-attack", "external_id": attack_id,
                                     "url": f"https://attack.mitre.org/techniques/{attack_id}"}],
            **extra}


ATTACK_BUNDLE = {"type": "bundle", "id": "bundle--1", "objects": [
    _technique("attack-pattern--1566", "T1566", "Phishing", "initial-access"),
    _technique("attack-pattern--1566-001", "T1566.001", "Spearphishing Attachment", "initial-access", sub=True),
    _technique("attack-pattern--1059", "T1059", "Command and Scripting Interpreter", "execution"),
    _technique("attack-pattern--old", "T1000", "Revoked Technique", "execution", revoked=True),
    {"type": "malware", "id": "malware--1", "name": "NotATechnique",
     "external_references": [{"source_name": "mitre-attack", "external_id": "S0001"}]},
    {"type": "x-mitre-tactic", "id": "x-mitre-tactic--1", "name": "Execution",
     "external_references": [{"source_name": "mitre-attack", "external_id": "TA0002"}]},
    {"type": "course-of-action", "id": "course-of-action--1", "name": "User Training",
     "external_references": [{"source_name": "mitre-attack", "external_id": "M1017"}]},
    {"type": "relationship", "id": "relationship--1", "relationship_type": "subtechnique-of",
     "source_ref": "attack-pattern--1566-001", "target_ref": "attack-pattern--1566"},
    {"type": "relationship", "id": "relationship--2", "relationship_type": "mitigates",
     "source_ref": "course-of-action--1", "target_ref": "attack-pattern--1566",
     "description": "Train users to identify social engineering techniques."},
    {"type": "relationship", "id": "relationship--3", "relationship_type": "uses",
     "source_ref": "malware--1", "target_ref": "attack-pattern--1059"},
]}


def nvd_item(cve_id, description, cwes=(), score=None, modified="2026-01-02T00:00:00.000"):
    cve = {"id": cve_id, "published": "2024-01-01T00:00:00.000", "lastModified": modified,
           "vulnStatus": "Analyzed", "descriptions": [{"lang": "en", "value": description}],
           "metrics": {}, "weaknesses": [], "references": [
               {"url": f"https://vendor.test/advisory/{cve_id}", "tags": ["Vendor Advisory"]}]}
    if score is not None:
        cve["metrics"] = {"cvssMetricV31": [{"type": "Primary", "exploitabilityScore": 3.9,
                                             "impactScore": 5.9, "cvssData": {
                                                 "version": "3.1", "baseScore": score,
                                                 "baseSeverity": "CRITICAL",
                                                 "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}]}
    if cwes:
        cve["weaknesses"] = [{"source": "nvd@nist.gov", "type": "Primary",
                              "description": [{"lang": "en", "value": c} for c in cwes]}]
    return {"cve": cve}


NVD_ITEMS = [
    nvd_item("CVE-2024-0001", "SQL injection in the login form of ExampleApp allows remote attackers "
                              "to read the database.", cwes=["CWE-89"], score=9.8),
    nvd_item("CVE-2024-0002", "An issue in ExampleRouter firmware has unspecified impact.",
             cwes=["NVD-CWE-noinfo"]),
    nvd_item("CVE-2024-0003", "Cross-site scripting in ExampleCMS comment field.", cwes=["CWE-79"],
             score=6.1),
]


def zipped(xml: str) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("cwec_v9.9.xml", xml)
    return buffer.getvalue()


def make_settings(**overrides) -> Settings:
    values = dict(neo4j_uri="bolt://test", neo4j_username="neo4j", neo4j_password="test-only",
                  nvd_api_url=NVD_URL, cwe_xml_url=CWE_URL, capec_xml_url=CAPEC_URL,
                  attack_stix_urls=(ATTACK_URL,), nvd_results_per_page=2, http_max_retries=1,
                  scheduler_enabled=False, run_initial_sync=False, admin_api_key="test-admin-key",
                  embedding_dimensions=128, reference_docs_dir=str(DATA_DIR / "reference_docs"))
    values.update(overrides)
    return Settings(**values)


class MockSources:
    """Configurable mock of NVD and the MITRE download sites."""

    def __init__(self):
        self.cwe_xml, self.capec_xml = CWE_XML, CAPEC_XML
        self.attack_bundle = ATTACK_BUNDLE
        self.nvd_items = list(NVD_ITEMS)
        self.fail_status: dict[str, int] = {}       # host -> HTTP status to return
        self.nvd_requests: list[dict] = []
        self.nvd_fail_at_start_index: int | None = None

    def handler(self, request: httpx.Request) -> httpx.Response:
        host = request.url.host
        if host in self.fail_status:
            return httpx.Response(self.fail_status[host])
        if host == "cwe.test":
            return httpx.Response(200, content=zipped(self.cwe_xml))
        if host == "capec.test":
            return httpx.Response(200, content=self.capec_xml.encode())
        if host == "attack.test":
            return httpx.Response(200, content=json.dumps(self.attack_bundle).encode())
        if host == "nvd.test":
            params = dict(request.url.params)
            self.nvd_requests.append(params)
            start, size = int(params.get("startIndex", 0)), int(params.get("resultsPerPage", 2000))
            if self.nvd_fail_at_start_index is not None and start >= self.nvd_fail_at_start_index:
                return httpx.Response(503)
            page = self.nvd_items[start:start + size]
            return httpx.Response(200, json={"resultsPerPage": len(page), "startIndex": start,
                                             "totalResults": len(self.nvd_items),
                                             "format": "NVD_CVE", "version": "2.0",
                                             "vulnerabilities": page})
        return httpx.Response(404)

    def client(self) -> httpx.Client:
        return httpx.Client(transport=httpx.MockTransport(self.handler))


def no_sleep(_seconds: float) -> None:
    return None


class Harness:
    def __init__(self, settings: Settings | None = None):
        self.settings = settings or make_settings()
        self.db = InMemoryGraph()
        self.sources = MockSources()
        self.embedder = EmbeddingClient(self.settings)
        self.clock_now = datetime(2026, 1, 10, tzinfo=timezone.utc)
        client = self.sources.client()
        self.cwe = CWEUpdater(self.db, self.embedder, self.settings, http_client=client, sleep=no_sleep)
        self.capec = CAPECUpdater(self.db, self.embedder, self.settings, http_client=client, sleep=no_sleep)
        self.attack = AttackUpdater(self.db, self.embedder, self.settings, http_client=client, sleep=no_sleep)
        self.cve = CVEUpdater(self.db, self.embedder, self.settings, http_client=client,
                              sleep=no_sleep, clock=lambda: self.clock_now)

    def sync_all(self) -> None:
        for updater in (self.cwe, self.capec, self.attack):
            result = updater.sync()
            assert result.ok, result
        result = self.cve.sync()
        assert result.ok, result


@pytest.fixture
def harness() -> Harness:
    return Harness()


@pytest.fixture(scope="session")
def knowledge() -> Harness:
    """A fully synchronised graph including the real reference documents."""
    h = Harness()
    h.sync_all()
    summary = FoundationIngestor(h.db, h.embedder, h.settings).ingest_all()
    assert not summary["errors"], summary["errors"]
    return h


@pytest.fixture(scope="session")
def assistant(knowledge) -> Assistant:
    return Assistant(Retriever(knowledge.db, knowledge.embedder, knowledge.settings),
                     Generator(knowledge.settings))
