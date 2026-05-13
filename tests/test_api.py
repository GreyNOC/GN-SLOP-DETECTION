from fastapi.testclient import TestClient

from app.main import app
from app.models.schemas import MAX_TEXT_LENGTH

client = TestClient(app)


def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_analyze_endpoint():
    response = client.post("/api/v1/analyze", json={"text": "This is revolutionary and guaranteed."})
    assert response.status_code == 200
    payload = response.json()
    assert "score" in payload
    assert "signals" in payload
    assert "dimensions" in payload
    assert "profile" in payload


def test_analyze_endpoint_rejects_oversized_text():
    response = client.post("/api/v1/analyze", json={"text": "x" * (MAX_TEXT_LENGTH + 1)})
    assert response.status_code == 422


def test_analyze_url_blocks_private_network_by_default():
    response = client.post("/api/v1/analyze-url", json={"url": "http://127.0.0.1/"})
    assert response.status_code == 400
    assert "Private" in response.json()["detail"]


def test_analyze_url_restricts_nonstandard_ports():
    response = client.post("/api/v1/analyze-url", json={"url": "https://example.com:4443/"})
    assert response.status_code == 400
    assert "ports 80 and 443" in response.json()["detail"]
