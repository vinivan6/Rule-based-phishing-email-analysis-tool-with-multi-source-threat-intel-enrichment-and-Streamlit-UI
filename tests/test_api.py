from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_health_endpoint():
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_analyze_email_endpoint_returns_expected_structure():
    payload = {
        "sender": "hr@company.com",
        "display_name": "HR Team",
        "subject": "Team lunch next Friday",
        "body": "Please let me know your dietary restrictions for Friday lunch.",
        "headers": "From: hr@company.com\nReply-To: hr@company.com",
        "attachments": ["menu.pdf"]
    }

    response = client.post("/analyze-email", json=payload)

    assert response.status_code == 200

    data = response.json()

    assert "verdict" in data
    assert "confidence" in data
    assert "reasons" in data
    assert "indicators" in data
    assert "recommended_action" in data
    assert "llm_notes" in data
    assert "model_used" in data
    assert "artifacts" in data

    assert "urls" in data["artifacts"]
    assert "domains" in data["artifacts"]
    assert "ip_addresses" in data["artifacts"]
    assert "attachments" in data["artifacts"]
    assert "phone_numbers" in data["artifacts"]
    assert "amounts" in data["artifacts"]