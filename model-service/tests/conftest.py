"""
Pytest configuration and fixtures for ClawGuard Model Service tests.

Uses unittest.mock to patch model loading and inference so tests run
without downloading the real safeguard model. The embedding model (small,
~90MB) still loads for semantic similarity tests.
"""

import os
import re
from typing import Generator
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

# Set the API key env var BEFORE importing main (which reads it at module load)
TEST_API_KEY = "test-model-service-api-key-for-tests"
os.environ["MODEL_SERVICE_API_KEY"] = TEST_API_KEY

# Patch ModelService methods BEFORE the app lifespan triggers model download.
import main


def _test_load_model(self) -> None:
    """Test replacement for load_model - loads embeddings only, skips safeguard model."""
    self.is_loaded = True
    self.model = MagicMock()
    self.tokenizer = MagicMock()
    self.load_embedding_model()


def _test_model_analyze(self, text: str) -> dict[str, float]:
    """Heuristic scoring used as a test double for _model_analyze.

    Replicates keyword/regex-based scoring so existing tests keep passing
    without requiring the real safeguard model on GPU.
    """
    text_lower = text.lower()

    # Prompt injection detection
    injection_keywords = [
        "ignore previous", "disregard", "forget your instructions",
        "new instructions", "override", "system prompt", "you are now",
        "act as", "pretend to be", "do not follow", "instead of",
        "reveal your", "show me your prompt", "what are your instructions",
        "repeat your rules",
    ]
    prompt_injection_score = 0.0
    for keyword in injection_keywords:
        if keyword in text_lower:
            prompt_injection_score = min(1.0, prompt_injection_score + 0.3)

    harmful_patterns = [
        r"empty\b.*\bwallet", r"drain\b.*\baccount", r"transfer\b.*\bfunds",
        r"\bsteal\b", r"send\b.*\b(?:money|funds|crypto|bitcoin|eth)\b",
        r"wire\s*transfer", r"delete\s+all\b", r"drop\s+table", r"\brm\s+-rf\b",
        r"execute\b.*\bcommand", r"run\b.*\bcommand", r"\bshutdown\b.*\bserver",
        r"format\b.*\bdisk", r"\bdestroy\b.*\b(?:data|file|system|server)",
        r"kill\b.*\bprocess", r"\bexfiltrate\b", r"\bransom\b",
    ]
    for pattern in harmful_patterns:
        if re.search(pattern, text_lower):
            prompt_injection_score = min(1.0, prompt_injection_score + 0.4)

    # Jailbreak detection
    jailbreak_keywords = [
        "dan mode", "jailbreak", "bypass", "unrestricted", "no limits",
        "evil mode", "developer mode", "without restrictions", "hypothetically",
        "roleplay as", "no restrictions", "unfiltered", "without safety",
        "disable filter", "remove restrictions",
    ]
    jailbreak_score = 0.0
    for keyword in jailbreak_keywords:
        if keyword in text_lower:
            jailbreak_score = min(1.0, jailbreak_score + 0.3)

    # PII detection
    pii_score = 0.0
    if re.search(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", text):
        pii_score += 0.3
    if re.search(r"\b\d{3}-\d{2}-\d{4}\b", text):
        pii_score += 0.4
    if re.search(r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b", text):
        pii_score += 0.2
    if re.search(r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b", text):
        pii_score += 0.4
    if re.search(r"\b[A-CEGHJ-PR-TW-Z]{2}\s?\d{2}\s?\d{2}\s?\d{2}\s?[A-D]\b", text, re.IGNORECASE):
        pii_score += 0.4
    if re.search(r"\b\d{3}\s?\d{3}\s?\d{4}\b", text):
        pii_score += 0.3
    if re.search(r"\b[A-Z]{2}\d{2}[A-Z0-9]{4,30}\b", text, re.IGNORECASE):
        pii_score += 0.35
    if re.search(r"\b\d{3}[-\s]?\d{3}[-\s]?\d{3}\b", text):
        pii_score += 0.4
    if re.search(r"\b\d{3}\s\d{3}\s\d{3}\b", text):
        pii_score += 0.4
    if re.search(r"\b[A-Z]{1,2}\d{6,8}\b", text, re.IGNORECASE):
        pii_score += 0.3
    if re.search(r"\b\d{9}\b", text):
        pii_score += 0.2
    pii_score = min(1.0, pii_score)

    return {
        "prompt_injection": prompt_injection_score,
        "jailbreak": jailbreak_score,
        "pii": pii_score,
    }


# Apply patches before any TestClient creates the app lifespan
main.ModelService.load_model = _test_load_model
main.ModelService._model_analyze = _test_model_analyze

from main import app, ModelService  # noqa: E402


@pytest.fixture(scope="function")
def client() -> Generator[TestClient, None, None]:
    """Create a TestClient for the FastAPI application with API key auth."""
    with TestClient(app) as test_client:
        test_client.headers["X-API-Key"] = TEST_API_KEY
        yield test_client


@pytest.fixture(scope="function")
def unauthenticated_client() -> Generator[TestClient, None, None]:
    """Create a TestClient WITHOUT API key auth (for auth rejection tests)."""
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture(scope="function")
def mock_model_service() -> Generator[MagicMock, None, None]:
    """Create a mock ModelService for testing."""
    mock_service = MagicMock(spec=ModelService)
    mock_service.is_loaded = True

    mock_response = MagicMock()
    mock_response.prompt_injection_score = 0.1
    mock_response.jailbreak_score = 0.1
    mock_response.pii_score = 0.1
    mock_response.blocked = False
    mock_response.detected_threats = []
    mock_response.processing_time_ms = 1.0
    mock_service.analyze.return_value = mock_response

    yield mock_service


@pytest.fixture(scope="function")
def mock_model_service_with_threats() -> Generator[MagicMock, None, None]:
    """Create a mock ModelService that detects threats."""
    mock_service = MagicMock(spec=ModelService)
    mock_service.is_loaded = True

    mock_response = MagicMock()
    mock_response.prompt_injection_score = 0.9
    mock_response.jailbreak_score = 0.8
    mock_response.pii_score = 0.6
    mock_response.blocked = True
    mock_response.detected_threats = ["prompt_injection", "jailbreak", "pii_exposure"]
    mock_response.processing_time_ms = 2.5
    mock_service.analyze.return_value = mock_response

    yield mock_service
