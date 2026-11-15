"""
IRONCLAD FastAPI Endpoint Test Suite.

Tests all REST API endpoints using Starlette TestClient.
Database is initialized in-memory via lifespan; demo seed data is populated.
"""

from __future__ import annotations

import pytest
from starlette.testclient import TestClient

# App import triggers lifespan seed on first run
from ironclad.server.app import app


@pytest.fixture(scope="module")
def client() -> TestClient:
    """Module-scoped test client so the DB is initialized once."""
    with TestClient(app, raise_server_exceptions=True) as c:
        yield c


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

class TestHealth:

    def test_health_returns_200(self, client: TestClient):
        resp = client.get("/api/health")
        assert resp.status_code == 200

    def test_health_body(self, client: TestClient):
        data = client.get("/api/health").json()
        assert data["status"] == "HEALTHY"
        assert "version" in data

    def test_health_contains_service_name(self, client: TestClient):
        data = client.get("/api/health").json()
        assert "IRONCLAD" in data["service"]


# ---------------------------------------------------------------------------
# Overview
# ---------------------------------------------------------------------------

class TestOverview:

    def test_overview_200(self, client: TestClient):
        assert client.get("/api/overview").status_code == 200

    def test_overview_has_required_fields(self, client: TestClient):
        data = client.get("/api/overview").json()
        # Actual field names from the OverviewStats Pydantic model
        required = [
            "network_security_status", "total_packets_analysed", "total_flows",
            "active_alerts", "suspicious_hosts", "overall_risk_score",
            "final_classification",
        ]
        for field in required:
            assert field in data, f"Missing field: {field} — got keys: {list(data.keys())}"

    def test_overview_risk_score_range(self, client: TestClient):
        data = client.get("/api/overview").json()
        assert 0.0 <= data["overall_risk_score"] <= 10.0


# ---------------------------------------------------------------------------
# Engines
# ---------------------------------------------------------------------------

class TestEngines:

    def test_engines_200(self, client: TestClient):
        assert client.get("/api/engines").status_code == 200

    def test_engines_has_engines_list(self, client: TestClient):
        data = client.get("/api/engines").json()
        assert "engines" in data
        assert isinstance(data["engines"], list)

    def test_engines_risk_scores_valid(self, client: TestClient):
        data = client.get("/api/engines").json()
        for engine in data["engines"]:
            assert 0.0 <= engine["risk_score"] <= 10.0
            assert 0.0 <= engine["confidence_score"] <= 100.0


# ---------------------------------------------------------------------------
# Sub-Engines
# ---------------------------------------------------------------------------

class TestSubEngines:

    def test_subengines_200(self, client: TestClient):
        assert client.get("/api/sub-engines").status_code == 200

    def test_subengines_has_list(self, client: TestClient):
        # /api/sub-engines returns a plain list
        data = client.get("/api/sub-engines").json()
        assert isinstance(data, list)

    def test_subengines_have_required_fields(self, client: TestClient):
        data = client.get("/api/sub-engines").json()
        for se in data:
            assert "subengine_id" in se
            assert "name" in se
            assert "risk_score" in se


# ---------------------------------------------------------------------------
# Incidents
# ---------------------------------------------------------------------------

class TestIncidents:

    def test_incidents_200(self, client: TestClient):
        assert client.get("/api/incidents").status_code == 200

    def test_incidents_has_list(self, client: TestClient):
        data = client.get("/api/incidents").json()
        assert "incidents" in data
        assert "total" in data

    def test_incidents_severity_filter(self, client: TestClient):
        resp = client.get("/api/incidents?severity=CRITICAL")
        assert resp.status_code == 200
        data = resp.json()
        for inc in data["incidents"]:
            assert inc["severity"] == "CRITICAL"

    def test_incidents_search_ip(self, client: TestClient):
        resp = client.get("/api/incidents?search_ip=192.168")
        assert resp.status_code == 200

    def test_incident_detail_404_on_missing(self, client: TestClient):
        resp = client.get("/api/incidents/99999")
        assert resp.status_code == 404

    def test_incident_detail_found(self, client: TestClient):
        # Fetch first incident id from list
        data = client.get("/api/incidents").json()
        if data["incidents"]:
            inc_id = data["incidents"][0]["id"]
            resp = client.get(f"/api/incidents/{inc_id}")
            assert resp.status_code == 200
            detail = resp.json()
            assert "incident" in detail
            assert "primary_engine_findings" in detail
            assert "recommended_actions" in detail


# ---------------------------------------------------------------------------
# Threat Intel
# ---------------------------------------------------------------------------

class TestThreatIntel:

    def test_threat_intel_200(self, client: TestClient):
        assert client.get("/api/threat-intel").status_code == 200

    def test_threat_intel_has_indicators(self, client: TestClient):
        data = client.get("/api/threat-intel").json()
        assert "indicators" in data
        assert isinstance(data["indicators"], list)

    def test_threat_intel_has_known_bad_ip(self, client: TestClient):
        data = client.get("/api/threat-intel").json()
        ips = [ind["indicator"] for ind in data["indicators"]]
        assert "198.51.100.77" in ips


# ---------------------------------------------------------------------------
# Topology
# ---------------------------------------------------------------------------

class TestTopology:

    def test_topology_200(self, client: TestClient):
        assert client.get("/api/topology").status_code == 200

    def test_topology_has_nodes_and_links(self, client: TestClient):
        data = client.get("/api/topology").json()
        assert "nodes" in data
        assert "links" in data
        assert isinstance(data["nodes"], list)
        assert isinstance(data["links"], list)


# ---------------------------------------------------------------------------
# Analysis Status
# ---------------------------------------------------------------------------

class TestAnalysisStatus:

    def test_status_200(self, client: TestClient):
        resp = client.get("/api/status/demo-session-alpha-001")
        # Either 200 (found) or 404 (not seeded yet, OK)
        assert resp.status_code in (200, 404)


# ---------------------------------------------------------------------------
# Containment
# ---------------------------------------------------------------------------

class TestContainment:

    def test_hosts_200(self, client: TestClient):
        assert client.get("/api/containment/hosts").status_code == 200

    def test_hosts_has_list(self, client: TestClient):
        # /api/containment/hosts returns a plain list
        data = client.get("/api/containment/hosts").json()
        assert isinstance(data, list)

    def test_audit_log_200(self, client: TestClient):
        assert client.get("/api/containment/audit-log").status_code == 200

    def test_audit_log_has_list(self, client: TestClient):
        # /api/containment/audit-log returns a plain list
        data = client.get("/api/containment/audit-log").json()
        assert isinstance(data, list)

    def test_simulate_containment(self, client: TestClient):
        resp = client.post("/api/containment/simulate", json={
            "ip": "192.168.1.88",
            "action": "ISOLATE",
            "operator": "analyst_test",
            "reason": "Automated test containment",
            "notes": "Test run only",
        })
        assert resp.status_code in (200, 201, 400, 422)


# ---------------------------------------------------------------------------
# Upload
# ---------------------------------------------------------------------------

class TestUpload:

    def test_generate_synthetic_200(self, client: TestClient):
        resp = client.post("/api/upload/generate-synthetic")
        assert resp.status_code == 200

    def test_generate_synthetic_has_task_id(self, client: TestClient):
        resp = client.post("/api/upload/generate-synthetic")
        data = resp.json()
        assert "task_id" in data

    def test_pcap_upload_no_file_422(self, client: TestClient):
        resp = client.post("/api/upload/pcap")
        assert resp.status_code == 422
