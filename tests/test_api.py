from fastapi.testclient import TestClient

from app.main import app

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
