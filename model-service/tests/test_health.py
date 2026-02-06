"""
Tests for the /health and /config endpoints.
"""

from fastapi.testclient import TestClient

from main import SAFEGUARD_MODELS, model_service


class TestHealthEndpoint:
    """Tests for the health check endpoint."""

    def test_health_returns_200(self, client: TestClient) -> None:
        """Test that /health endpoint returns HTTP 200 status code."""
        response = client.get("/health")
        assert response.status_code == 200

    def test_health_response_structure(self, client: TestClient) -> None:
        """Test that /health endpoint returns the expected response structure."""
        response = client.get("/health")
        data = response.json()

        # Check all required fields are present
        assert "status" in data
        assert "model_loaded" in data
        assert "model_name" in data
        assert "device" in data
        assert "gpu_available" in data
        assert "gpu_memory" in data
        assert "requests_processed" in data
        assert "average_latency_ms" in data
        assert "uptime_seconds" in data

        # Check field types
        assert isinstance(data["status"], str)
        assert isinstance(data["model_loaded"], bool)
        assert isinstance(data["model_name"], str)
        assert isinstance(data["device"], str)
        assert isinstance(data["gpu_available"], bool)
        assert isinstance(data["requests_processed"], int)
        assert isinstance(data["average_latency_ms"], float)
        assert isinstance(data["uptime_seconds"], float)

    def test_health_status_healthy_when_model_loaded(self, client: TestClient) -> None:
        """Test that status is 'healthy' when model is loaded."""
        response = client.get("/health")
        data = response.json()

        assert data["status"] == "healthy"
        assert data["model_loaded"] is True

    def test_health_gpu_memory_info(self, client: TestClient) -> None:
        """Test that gpu_memory contains expected fields."""
        response = client.get("/health")
        data = response.json()

        assert "gpu_memory" in data
        gpu_mem = data["gpu_memory"]
        assert "allocated_mb" in gpu_mem
        assert "reserved_mb" in gpu_mem
        assert "total_mb" in gpu_mem

    def test_health_device_is_valid(self, client: TestClient) -> None:
        """Test that device is a valid value (cpu or cuda)."""
        response = client.get("/health")
        data = response.json()

        assert data["device"] in ["cpu", "cuda"]


class TestConfigEndpoint:
    """Tests for the /config GET and POST endpoints."""

    def test_get_config_returns_current_configuration(self, client: TestClient) -> None:
        """Test that GET /config returns the current model configuration."""
        response = client.get("/config")
        assert response.status_code == 200

        data = response.json()

        # Check all required fields are present
        assert "safeguard_model" in data
        assert "model_name" in data
        assert "device" in data

        # Check field types
        assert isinstance(data["safeguard_model"], str)
        assert isinstance(data["model_name"], str)
        assert isinstance(data["device"], str)

        # The model_name should correspond to the safeguard_model variant
        variant = data["safeguard_model"]
        assert variant in SAFEGUARD_MODELS
        assert data["model_name"] == SAFEGUARD_MODELS[variant]

    def test_post_config_changes_safeguard_model(self, client: TestClient) -> None:
        """Test that POST /config updates the safeguard model variant."""
        # Record original size so we can restore it after the test
        original_size = model_service.current_model_size

        try:
            # Switch to 20b variant
            response = client.post("/config", json={"safeguard_model": "20b"})
            assert response.status_code == 200

            data = response.json()
            assert data["safeguard_model"] == "20b"
            assert data["model_name"] == SAFEGUARD_MODELS["20b"]

            # Verify GET /config reflects the change
            get_response = client.get("/config")
            get_data = get_response.json()
            assert get_data["safeguard_model"] == "20b"
            assert get_data["model_name"] == SAFEGUARD_MODELS["20b"]
        finally:
            # Restore original model size to avoid affecting other tests
            model_service.current_model_size = original_size

    def test_post_config_with_invalid_model_variant_returns_400(self, client: TestClient) -> None:
        """Test that POST /config with an invalid model variant returns 400.

        Only '20b' and '120b' are valid safeguard model variants.
        Any other value should be rejected with a 422 Unprocessable Entity status.
        """
        response = client.post("/config", json={"safeguard_model": "999b"})
        assert response.status_code == 422

    def test_post_config_with_same_variant_is_idempotent(self, client: TestClient) -> None:
        """Test that setting the same variant again does not cause errors."""
        original_size = model_service.current_model_size

        response = client.post(
            "/config", json={"safeguard_model": original_size}
        )
        assert response.status_code == 200

        data = response.json()
        assert data["safeguard_model"] == original_size
