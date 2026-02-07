"""
Tests for API key authentication on model-service endpoints.
"""

import os

from fastapi.testclient import TestClient

TEST_API_KEY = os.environ["MODEL_SERVICE_API_KEY"]


class TestAuthRejection:
    """Tests that protected endpoints reject requests without a valid API key."""

    def test_analyze_rejects_without_api_key(self, unauthenticated_client: TestClient) -> None:
        response = unauthenticated_client.post("/analyze", json={"text": "test"})
        assert response.status_code == 401
        assert "Invalid or missing API key" in response.json()["detail"]

    def test_analyze_output_rejects_without_api_key(self, unauthenticated_client: TestClient) -> None:
        response = unauthenticated_client.post("/analyze-output", json={"text": "test"})
        assert response.status_code == 401

    def test_analyze_batch_rejects_without_api_key(self, unauthenticated_client: TestClient) -> None:
        response = unauthenticated_client.post("/analyze/batch", json={"texts": ["test"]})
        assert response.status_code == 401

    def test_config_get_rejects_without_api_key(self, unauthenticated_client: TestClient) -> None:
        response = unauthenticated_client.get("/config")
        assert response.status_code == 401

    def test_config_post_rejects_without_api_key(self, unauthenticated_client: TestClient) -> None:
        response = unauthenticated_client.post("/config", json={"safeguard_model": "20b"})
        assert response.status_code == 401

    def test_cleanup_rejects_without_api_key(self, unauthenticated_client: TestClient) -> None:
        response = unauthenticated_client.post("/cleanup")
        assert response.status_code == 401

    def test_analyze_rejects_with_wrong_api_key(self, unauthenticated_client: TestClient) -> None:
        response = unauthenticated_client.post(
            "/analyze",
            json={"text": "test"},
            headers={"X-API-Key": "wrong-key"},
        )
        assert response.status_code == 401


class TestAuthAcceptance:
    """Tests that protected endpoints accept requests with a valid API key."""

    def test_analyze_accepts_x_api_key_header(self, unauthenticated_client: TestClient) -> None:
        response = unauthenticated_client.post(
            "/analyze",
            json={"text": "Hello, this is a normal message."},
            headers={"X-API-Key": TEST_API_KEY},
        )
        assert response.status_code == 200

    def test_analyze_accepts_bearer_token(self, unauthenticated_client: TestClient) -> None:
        response = unauthenticated_client.post(
            "/analyze",
            json={"text": "Hello, this is a normal message."},
            headers={"Authorization": f"Bearer {TEST_API_KEY}"},
        )
        assert response.status_code == 200

    def test_config_get_accepts_api_key(self, unauthenticated_client: TestClient) -> None:
        response = unauthenticated_client.get(
            "/config",
            headers={"X-API-Key": TEST_API_KEY},
        )
        assert response.status_code == 200


class TestUnauthenticatedEndpoints:
    """Tests that health/ready endpoints remain unauthenticated."""

    def test_health_accessible_without_api_key(self, unauthenticated_client: TestClient) -> None:
        response = unauthenticated_client.get("/health")
        assert response.status_code == 200

    def test_ready_accessible_without_api_key(self, unauthenticated_client: TestClient) -> None:
        response = unauthenticated_client.get("/ready")
        assert response.status_code == 200

    def test_metrics_requires_api_key(self, unauthenticated_client: TestClient) -> None:
        """Test that /metrics now requires API key authentication."""
        response = unauthenticated_client.get("/metrics")
        assert response.status_code == 401
