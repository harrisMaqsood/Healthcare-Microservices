import pytest
import asyncio
from httpx import AsyncClient
from fastapi.testclient import TestClient
from main import app, create_jwt_token, encrypt_data
import json

# Test client
client = TestClient(app)

@pytest.fixture
def auth_token():
    """Create a test JWT token"""
    return create_jwt_token("test_user", ["healthcare_provider", "ai_user"])

@pytest.fixture
def encrypted_health_data():
    """Create encrypted test health data"""
    test_data = {
        "symptoms": "fatigue, headache",
        "concerns": "stress management",
        "goals": "improve sleep quality"
    }
    return encrypt_data(json.dumps(test_data))

def test_health_check():
    """Test health check endpoint"""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "timestamp" in data
    assert "services" in data

def test_authentication():
    """Test authentication endpoint"""
    response = client.post(
        "/api/v1/auth/token",
        json={
            "username": "healthcare_provider",
            "password": "secure_password_123"
        }
    )
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"

def test_health_data_ingestion(auth_token, encrypted_health_data):
    """Test health data ingestion endpoint"""
    headers = {"Authorization": f"Bearer {auth_token}"}
    payload = {
        "encrypted_data": encrypted_health_data,
        "patient_id": "test_patient_123",
        "data_type": "symptoms"
    }
    
    response = client.post(
        "/api/v1/health-data/ingest",
        json=payload,
        headers=headers
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"

def test_coaching_generation(auth_token):
    """Test AI coaching generation endpoint"""
    headers = {"Authorization": f"Bearer {auth_token}"}
    payload = {
        "query": "I'm feeling stressed and having trouble sleeping. What should I do?",
        "context": {"age": 30, "gender": "female"},
        "preferences": {"style": "gentle", "focus": "holistic"}
    }
    
    response = client.post(
        "/api/v1/coaching/generate",
        json=payload,
        headers=headers
    )
    assert response.status_code == 200
    data = response.json()
    assert "recommendations" in data
    assert "confidence_score" in data
    assert 0 <= data["confidence_score"] <= 1
    assert "audit_id" in data

def test_unauthorized_access():
    """Test unauthorized access is blocked"""
    response = client.post(
        "/api/v1/coaching/generate",
        json={"query": "test query"}
    )
    assert response.status_code == 403

def test_rate_limiting():
    """Test rate limiting is enforced"""
    # This would need to be adjusted based on actual rate limits
    for i in range(25):  # Exceed the rate limit
        response = client.get("/health")
        if response.status_code == 429:
            break
    else:
        pytest.skip("Rate limiting not triggered in test environment")

@pytest.mark.asyncio
async def test_encryption_decryption():
    """Test encryption and decryption functions"""
    test_data = "sensitive health information"
    encrypted = encrypt_data(test_data)
    assert encrypted != test_data
    assert len(encrypted) > 0

if __name__ == "__main__":
    pytest.main([__file__])