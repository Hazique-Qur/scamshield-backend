from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from app.main import app
from app.database.connection import Base, get_db
from app.models import user, scan, indicator, evidence, conversation, message, user_settings

SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base.metadata.create_all(bind=engine)


def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db
client = TestClient(app)


def test_register_and_login():
    response = client.post("/api/v1/auth/register", json={"name": "Test", "email": "test@example.com", "password": "password123"})
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data

    response = client.post("/api/v1/auth/login", json={"email": "test@example.com", "password": "password123"})
    assert response.status_code == 200
    assert "access_token" in response.json()

    response = client.post("/api/v1/auth/login", json={"email": "test@example.com", "password": "wrong"})
    assert response.status_code == 401


def test_duplicate_email():
    client.post("/api/v1/auth/register", json={"name": "A", "email": "dup@example.com", "password": "password123"})
    response = client.post("/api/v1/auth/register", json={"name": "B", "email": "dup@example.com", "password": "password123"})
    assert response.status_code == 400


def test_text_scan_flow():
    register = client.post("/api/v1/auth/register", json={"name": "Scan", "email": "scan@example.com", "password": "password123"}).json()
    token = register["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    response = client.post("/api/v1/scans/text", json={"scan_type": "TEXT", "input_text": "urgent payment required"}, headers=headers)
    assert response.status_code == 200
    scan = response.json()
    scan_id = scan["id"]

    response = client.get(f"/api/v1/scans/{scan_id}", headers=headers)
    assert response.status_code == 200
    result = response.json()
    assert result["risk_score"] >= 0
    assert result["risk_level"] in {"SAFE", "SUSPICIOUS", "HIGH_RISK", "CRITICAL"}

    response = client.get("/api/v1/scans/999", headers=headers)
    assert response.status_code == 404


def test_dashboard():
    register = client.post("/api/v1/auth/register", json={"name": "Dash", "email": "dash@example.com", "password": "password123"}).json()
    token = register["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    response = client.get("/api/v1/dashboard/summary", headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert "total_scans" in data
    assert "average_risk" in data


def test_investigator():
    register = client.post("/api/v1/auth/register", json={"name": "Inv", "email": "inv@example.com", "password": "password123"}).json()
    token = register["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    scan = client.post("/api/v1/scans/text", json={"scan_type": "TEXT", "input_text": "urgent payment required"}, headers=headers).json()
    conv = client.post("/api/v1/investigator/conversations", json={"scan_id": scan["id"]}, headers=headers)
    assert conv.status_code == 200
    conversation_id = conv.json()["id"]

    response = client.post(
        f"/api/v1/investigator/conversations/{conversation_id}/messages",
        json={"message": "Why is this risky?"},
        headers=headers,
    )
    assert response.status_code == 200
    assert "message" in response.json()
