"""CVSS v3.1 calculator and the extra API router."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from backend.api_extra import cvss31_base_score, parse_vector, roundup
from backend.main import create_app


@pytest.mark.parametrize("vector, score, severity", [
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "CRITICAL"),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0, "CRITICAL"),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1, "MEDIUM"),
    ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8, "HIGH"),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0, "NONE"),
])
def test_cvss31_reference_scores(vector, score, severity):
    result = cvss31_base_score(parse_vector(vector))
    assert (result["score"], result["severity"]) == (score, severity)


def test_roundup_follows_the_specification():
    assert roundup(4.02) == 4.1 and roundup(4.0) == 4.0 and roundup(0.0) == 0.0


def test_invalid_vectors_are_rejected():
    with pytest.raises(ValueError):
        parse_vector("CVSS:3.0/AV:N")
    with pytest.raises(ValueError):
        cvss31_base_score({"AV": "N"})
    with pytest.raises(ValueError):
        cvss31_base_score({**parse_vector("CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")})


def test_calculate_endpoint(harness):
    from backend.main import AppState
    state = AppState(harness.settings, db=harness.db, embedder=harness.embedder,
                     sync_manager=object(), assistant=object())
    client = TestClient(create_app(state, start_background=False))
    ok = client.post("/api/severity/calculate",
                     json={"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"})
    assert ok.status_code == 200 and ok.json()["score"] == 9.8
    bad = client.post("/api/severity/calculate", json={"vector": "nonsense"})
    assert bad.status_code == 422
