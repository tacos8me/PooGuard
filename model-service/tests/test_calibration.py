"""
Tests for the calibration module (calibration.py) and /calibration endpoints.
"""

import json
import math
import os
import tempfile

import pytest

from calibration import (
    CALIBRATION_CATEGORIES,
    CalibrationPipeline,
    IsotonicCalibrator,
    NoOpCalibrator,
    PlattCalibrator,
)


# ---------------------------------------------------------------------------
# NoOpCalibrator tests
# ---------------------------------------------------------------------------

class TestNoOpCalibrator:
    """Tests for the pass-through NoOp calibrator."""

    def test_calibrate_returns_same_score(self) -> None:
        cal = NoOpCalibrator()
        assert cal.calibrate(0.0) == 0.0
        assert cal.calibrate(0.5) == 0.5
        assert cal.calibrate(1.0) == 1.0
        assert cal.calibrate(0.123456) == 0.123456

    def test_to_dict(self) -> None:
        cal = NoOpCalibrator()
        assert cal.to_dict() == {"type": "noop"}

    def test_from_dict_roundtrip(self) -> None:
        cal = NoOpCalibrator()
        data = cal.to_dict()
        restored = NoOpCalibrator.from_dict(data)
        assert restored.calibrate(0.42) == 0.42


# ---------------------------------------------------------------------------
# PlattCalibrator tests
# ---------------------------------------------------------------------------

class TestPlattCalibrator:
    """Tests for Platt scaling (sigmoid) calibrator."""

    def test_default_params_identity_like(self) -> None:
        """Default A=1, B=0 gives sigma(s) = 1/(1+exp(-s)) which is near-identity."""
        cal = PlattCalibrator()
        # At s=0: sigma(0) = 0.5
        assert abs(cal.calibrate(0.0) - 0.5) < 0.01
        # Higher scores should give higher calibrated values
        assert cal.calibrate(0.9) > cal.calibrate(0.1)

    def test_calibrate_returns_valid_range(self) -> None:
        cal = PlattCalibrator(A=-3.0, B=1.0)
        for s in [0.0, 0.1, 0.25, 0.5, 0.75, 0.9, 1.0]:
            result = cal.calibrate(s)
            assert 0.0 <= result <= 1.0, f"Out of range for s={s}: {result}"

    def test_calibrate_monotonic(self) -> None:
        """With positive A, calibrate should be monotonically increasing."""
        cal = PlattCalibrator(A=5.0, B=-2.0)
        scores = [i / 10.0 for i in range(11)]
        calibrated = [cal.calibrate(s) for s in scores]
        for i in range(len(calibrated) - 1):
            assert calibrated[i] <= calibrated[i + 1] + 1e-9

    def test_fit_basic(self) -> None:
        """Fit on simple data: high raw scores should map higher than low raw scores."""
        cal = PlattCalibrator()
        # Positive samples have high raw scores, negatives have low
        raw_scores = [0.1, 0.2, 0.15, 0.8, 0.9, 0.85]
        true_labels = [0, 0, 0, 1, 1, 1]
        cal.fit(raw_scores, true_labels)

        # After fit, high raw score should calibrate higher than low raw score
        assert cal.calibrate(0.9) > cal.calibrate(0.1)

    def test_fit_calibrated_scores_in_range(self) -> None:
        """After fitting, all calibrated scores should be in [0, 1]."""
        cal = PlattCalibrator()
        raw_scores = [0.05, 0.1, 0.2, 0.3, 0.7, 0.8, 0.9, 0.95]
        true_labels = [0, 0, 0, 0, 1, 1, 1, 1]
        cal.fit(raw_scores, true_labels)

        for s in [0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0]:
            result = cal.calibrate(s)
            assert 0.0 <= result <= 1.0, f"Out of range: calibrate({s}) = {result}"

    def test_fit_requires_matching_lengths(self) -> None:
        cal = PlattCalibrator()
        with pytest.raises(ValueError, match="same length"):
            cal.fit([0.1, 0.2], [0, 0, 1])

    def test_fit_requires_minimum_samples(self) -> None:
        cal = PlattCalibrator()
        with pytest.raises(ValueError, match="at least 2"):
            cal.fit([0.5], [1])

    def test_fit_requires_both_classes(self) -> None:
        cal = PlattCalibrator()
        with pytest.raises(ValueError, match="at least one positive"):
            cal.fit([0.1, 0.2, 0.3], [0, 0, 0])
        with pytest.raises(ValueError, match="at least one positive"):
            cal.fit([0.1, 0.2, 0.3], [1, 1, 1])

    def test_to_dict_from_dict_roundtrip(self) -> None:
        cal = PlattCalibrator(A=2.5, B=-0.3)
        data = cal.to_dict()
        assert data["type"] == "platt"
        assert data["A"] == 2.5
        assert data["B"] == -0.3

        restored = PlattCalibrator.from_dict(data)
        assert restored.A == 2.5
        assert restored.B == -0.3
        assert abs(restored.calibrate(0.5) - cal.calibrate(0.5)) < 1e-12

    def test_fit_then_roundtrip(self) -> None:
        """Fit, serialize, deserialize, and verify calibration is preserved."""
        cal = PlattCalibrator()
        raw_scores = [0.1, 0.15, 0.2, 0.8, 0.85, 0.9]
        true_labels = [0, 0, 0, 1, 1, 1]
        cal.fit(raw_scores, true_labels)

        data = cal.to_dict()
        restored = PlattCalibrator.from_dict(data)

        for s in [0.0, 0.25, 0.5, 0.75, 1.0]:
            assert abs(cal.calibrate(s) - restored.calibrate(s)) < 1e-12

    def test_extreme_scores_no_overflow(self) -> None:
        """Verify no math overflow on extreme inputs."""
        cal = PlattCalibrator(A=100.0, B=-50.0)
        assert 0.0 <= cal.calibrate(0.0) <= 1.0
        assert 0.0 <= cal.calibrate(1.0) <= 1.0
        assert 0.0 <= cal.calibrate(-10.0) <= 1.0
        assert 0.0 <= cal.calibrate(10.0) <= 1.0


# ---------------------------------------------------------------------------
# IsotonicCalibrator tests
# ---------------------------------------------------------------------------

class TestIsotonicCalibrator:
    """Tests for isotonic (non-parametric) calibrator."""

    def test_calibrate_empty_passthrough(self) -> None:
        """Before fitting, calibrate should pass through unchanged."""
        cal = IsotonicCalibrator()
        assert cal.calibrate(0.5) == 0.5

    def test_fit_basic_monotonic(self) -> None:
        cal = IsotonicCalibrator()
        raw_scores = [0.1, 0.2, 0.3, 0.7, 0.8, 0.9]
        true_labels = [0, 0, 0, 1, 1, 1]
        cal.fit(raw_scores, true_labels)

        # Result should be monotonically non-decreasing
        prev = -1.0
        for s in [0.0, 0.1, 0.2, 0.3, 0.5, 0.7, 0.8, 0.9, 1.0]:
            result = cal.calibrate(s)
            assert result >= prev - 1e-9
            prev = result

    def test_fit_calibrated_scores_in_range(self) -> None:
        cal = IsotonicCalibrator()
        raw_scores = [0.05, 0.1, 0.3, 0.5, 0.7, 0.9, 0.95]
        true_labels = [0, 0, 0, 1, 1, 1, 1]
        cal.fit(raw_scores, true_labels)

        for s in [0.0, 0.1, 0.3, 0.5, 0.7, 0.9, 1.0]:
            result = cal.calibrate(s)
            assert 0.0 <= result <= 1.0

    def test_fit_requires_matching_lengths(self) -> None:
        cal = IsotonicCalibrator()
        with pytest.raises(ValueError, match="same length"):
            cal.fit([0.1], [0, 1])

    def test_fit_requires_minimum_samples(self) -> None:
        cal = IsotonicCalibrator()
        with pytest.raises(ValueError, match="at least 2"):
            cal.fit([0.5], [1])

    def test_to_dict_from_dict_roundtrip(self) -> None:
        cal = IsotonicCalibrator()
        raw_scores = [0.1, 0.3, 0.5, 0.7, 0.9]
        true_labels = [0, 0, 1, 1, 1]
        cal.fit(raw_scores, true_labels)

        data = cal.to_dict()
        assert data["type"] == "isotonic"
        assert len(data["x_points"]) > 0
        assert len(data["y_points"]) > 0

        restored = IsotonicCalibrator.from_dict(data)
        for s in [0.0, 0.25, 0.5, 0.75, 1.0]:
            assert abs(cal.calibrate(s) - restored.calibrate(s)) < 1e-9

    def test_boundary_values(self) -> None:
        """Values outside the fitted range should clamp to boundary values."""
        cal = IsotonicCalibrator()
        raw_scores = [0.2, 0.4, 0.6, 0.8]
        true_labels = [0, 0, 1, 1]
        cal.fit(raw_scores, true_labels)

        # Below min: should return the lowest fitted y
        low_result = cal.calibrate(0.0)
        # Above max: should return the highest fitted y
        high_result = cal.calibrate(1.0)
        assert 0.0 <= low_result <= 1.0
        assert 0.0 <= high_result <= 1.0
        assert high_result >= low_result


# ---------------------------------------------------------------------------
# CalibrationPipeline tests
# ---------------------------------------------------------------------------

class TestCalibrationPipeline:
    """Tests for the CalibrationPipeline orchestrator."""

    def test_default_is_noop(self) -> None:
        pipeline = CalibrationPipeline()
        assert pipeline.calibrated is False
        for cat in CALIBRATION_CATEGORIES:
            assert isinstance(pipeline.calibrators[cat], NoOpCalibrator)

    def test_noop_passthrough(self) -> None:
        """With NoOp calibrators, scores should pass through unchanged."""
        pipeline = CalibrationPipeline()
        raw = {"prompt_injection": 0.3, "jailbreak": 0.6, "pii": 0.1}
        result = pipeline.calibrate_scores(raw)
        assert result == raw

    def test_calibrate_scores_clamped(self) -> None:
        """Result values are always clamped to [0, 1]."""
        pipeline = CalibrationPipeline()
        raw = {"prompt_injection": -0.1, "jailbreak": 1.5, "pii": 0.5}
        result = pipeline.calibrate_scores(raw)
        for v in result.values():
            assert 0.0 <= v <= 1.0

    def test_missing_category_defaults_to_zero(self) -> None:
        pipeline = CalibrationPipeline()
        result = pipeline.calibrate_scores({"prompt_injection": 0.5})
        assert result["jailbreak"] == 0.0
        assert result["pii"] == 0.0

    def test_save_and_load(self) -> None:
        """Save calibration params to file and reload."""
        pipeline = CalibrationPipeline()
        # Fit some calibrators
        cal = PlattCalibrator()
        cal.fit(
            [0.1, 0.15, 0.2, 0.8, 0.85, 0.9],
            [0, 0, 0, 1, 1, 1],
        )
        pipeline.calibrators["prompt_injection"] = cal
        pipeline.calibrated = True

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            path = f.name

        try:
            pipeline.save_to_file(path)

            # Load into a new pipeline
            new_pipeline = CalibrationPipeline()
            loaded = new_pipeline.load_from_file(path)
            assert loaded is True
            assert new_pipeline.calibrated is True
            assert isinstance(new_pipeline.calibrators["prompt_injection"], PlattCalibrator)
            assert isinstance(new_pipeline.calibrators["jailbreak"], NoOpCalibrator)

            # Verify calibration is identical
            for s in [0.0, 0.25, 0.5, 0.75, 1.0]:
                orig = pipeline.calibrate_scores({"prompt_injection": s, "jailbreak": s, "pii": s})
                loaded_result = new_pipeline.calibrate_scores({"prompt_injection": s, "jailbreak": s, "pii": s})
                for cat in CALIBRATION_CATEGORIES:
                    assert abs(orig[cat] - loaded_result[cat]) < 1e-9
        finally:
            os.unlink(path)

    def test_load_nonexistent_file(self) -> None:
        pipeline = CalibrationPipeline()
        result = pipeline.load_from_file("/nonexistent/path/calibration.json")
        assert result is False
        assert pipeline.calibrated is False

    def test_load_invalid_json(self) -> None:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write("not valid json {{{")
            path = f.name

        try:
            pipeline = CalibrationPipeline()
            result = pipeline.load_from_file(path)
            assert result is False
            assert pipeline.calibrated is False
        finally:
            os.unlink(path)

    def test_get_state(self) -> None:
        pipeline = CalibrationPipeline()
        state = pipeline.get_state()
        assert state["calibrated"] is False
        assert "prompt_injection" in state["categories"]
        assert "jailbreak" in state["categories"]
        assert "pii" in state["categories"]

    def test_fit_from_benchmark_platt(self) -> None:
        pipeline = CalibrationPipeline()
        results = {
            "prompt_injection": {
                "raw_scores": [0.1, 0.15, 0.2, 0.8, 0.85, 0.9],
                "true_labels": [0, 0, 0, 1, 1, 1],
            },
            "jailbreak": {
                "raw_scores": [0.05, 0.1, 0.9, 0.95],
                "true_labels": [0, 0, 1, 1],
            },
            # pii omitted - should remain NoOp
        }
        pipeline.fit_from_benchmark(results, method="platt")

        assert pipeline.calibrated is True
        assert isinstance(pipeline.calibrators["prompt_injection"], PlattCalibrator)
        assert isinstance(pipeline.calibrators["jailbreak"], PlattCalibrator)
        assert isinstance(pipeline.calibrators["pii"], NoOpCalibrator)

    def test_fit_from_benchmark_isotonic(self) -> None:
        pipeline = CalibrationPipeline()
        results = {
            "prompt_injection": {
                "raw_scores": [0.1, 0.2, 0.8, 0.9],
                "true_labels": [0, 0, 1, 1],
            },
        }
        pipeline.fit_from_benchmark(results, method="isotonic")
        assert isinstance(pipeline.calibrators["prompt_injection"], IsotonicCalibrator)

    def test_fit_from_benchmark_insufficient_data(self) -> None:
        """Categories with insufficient data should keep NoOp."""
        pipeline = CalibrationPipeline()
        results = {
            "prompt_injection": {
                "raw_scores": [0.5],  # Only 1 sample
                "true_labels": [1],
            },
        }
        pipeline.fit_from_benchmark(results)
        assert isinstance(pipeline.calibrators["prompt_injection"], NoOpCalibrator)


# ---------------------------------------------------------------------------
# Endpoint tests (via TestClient from conftest)
# ---------------------------------------------------------------------------

class TestCalibrationEndpoints:
    """Tests for /calibration and /calibrate API endpoints.

    These tests reset the global calibration_pipeline before and after each test
    to avoid cross-test contamination from the POST /calibrate endpoint which
    writes calibration_params.json to disk.
    """

    @pytest.fixture(autouse=True)
    def _reset_calibration(self):
        """Reset calibration pipeline and clean up any persisted params file."""
        import main
        from calibration import CalibrationPipeline

        # Clean up file BEFORE test (in case previous run left it)
        params_path = main.CALIBRATION_PARAMS_PATH
        if os.path.exists(params_path):
            os.unlink(params_path)

        # Reset in-memory pipeline before test
        main.calibration_pipeline = CalibrationPipeline()
        yield
        # Reset after test and clean up file
        main.calibration_pipeline = CalibrationPipeline()
        if os.path.exists(params_path):
            os.unlink(params_path)

    def test_get_calibration_default_state(self, client) -> None:
        """GET /calibration returns uncalibrated state by default."""
        response = client.get("/calibration")
        assert response.status_code == 200
        data = response.json()
        assert data["calibrated"] is False
        assert "categories" in data

    def test_post_calibrate_platt(self, client) -> None:
        """POST /calibrate fits Platt calibrators and returns state."""
        response = client.post(
            "/calibrate",
            json={
                "results": {
                    "prompt_injection": {
                        "raw_scores": [0.1, 0.15, 0.2, 0.8, 0.85, 0.9],
                        "true_labels": [0, 0, 0, 1, 1, 1],
                    },
                    "jailbreak": {
                        "raw_scores": [0.05, 0.1, 0.85, 0.95],
                        "true_labels": [0, 0, 1, 1],
                    },
                },
                "method": "platt",
            },
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "calibrated"
        assert data["calibrated"] is True
        assert data["categories"]["prompt_injection"]["type"] == "platt"
        assert data["categories"]["jailbreak"]["type"] == "platt"
        assert data["categories"]["pii"]["type"] == "noop"

    def test_post_calibrate_isotonic(self, client) -> None:
        """POST /calibrate with isotonic method."""
        response = client.post(
            "/calibrate",
            json={
                "results": {
                    "prompt_injection": {
                        "raw_scores": [0.1, 0.2, 0.8, 0.9],
                        "true_labels": [0, 0, 1, 1],
                    },
                },
                "method": "isotonic",
            },
        )
        assert response.status_code == 200
        data = response.json()
        assert data["categories"]["prompt_injection"]["type"] == "isotonic"

    def test_calibration_state_after_calibrate(self, client) -> None:
        """GET /calibration reflects state after POST /calibrate."""
        # First, calibrate
        client.post(
            "/calibrate",
            json={
                "results": {
                    "prompt_injection": {
                        "raw_scores": [0.1, 0.2, 0.8, 0.9],
                        "true_labels": [0, 0, 1, 1],
                    },
                },
                "method": "platt",
            },
        )
        # Then check state
        response = client.get("/calibration")
        assert response.status_code == 200
        data = response.json()
        assert data["calibrated"] is True

    def test_calibration_requires_auth(self, unauthenticated_client) -> None:
        """Calibration endpoints require API key."""
        response = unauthenticated_client.get("/calibration")
        assert response.status_code == 401

        response = unauthenticated_client.post(
            "/calibrate",
            json={"results": {}, "method": "platt"},
        )
        assert response.status_code == 401


# ---------------------------------------------------------------------------
# Fallback parser score tests
# ---------------------------------------------------------------------------

class TestFallbackParserScores:
    """Tests for the updated keyword-based fallback parser scores."""

    def test_single_injection_keyword_score(self) -> None:
        """Single keyword match should produce 0.7."""
        from main import ModelService
        service = ModelService()
        # "unsafe" + one injection keyword ("injection")
        scores = service._parse_safeguard_response("This is unsafe, detected injection")
        assert scores["prompt_injection"] == 0.7

    def test_multiple_injection_keywords_score(self) -> None:
        """Multiple keyword matches should produce 0.9."""
        from main import ModelService
        service = ModelService()
        # "unsafe" + two injection keywords ("injection" + "override")
        scores = service._parse_safeguard_response(
            "This is unsafe, detected injection override attempt"
        )
        assert scores["prompt_injection"] == 0.9

    def test_unsafe_no_category_score(self) -> None:
        """'Unsafe' with no category match should produce 0.5."""
        from main import ModelService
        service = ModelService()
        scores = service._parse_safeguard_response("This input is unsafe and blocked")
        assert scores["prompt_injection"] == 0.5
        assert scores["jailbreak"] == 0.0
        assert scores["pii"] == 0.0

    def test_single_jailbreak_keyword_score(self) -> None:
        from main import ModelService
        service = ModelService()
        scores = service._parse_safeguard_response("Unsafe: jailbreak detected")
        assert scores["jailbreak"] == 0.7

    def test_multiple_jailbreak_keywords_score(self) -> None:
        from main import ModelService
        service = ModelService()
        scores = service._parse_safeguard_response(
            "Unsafe: jailbreak bypass attempt"
        )
        assert scores["jailbreak"] == 0.9

    def test_single_pii_keyword_score(self) -> None:
        from main import ModelService
        service = ModelService()
        scores = service._parse_safeguard_response("Unsafe: contains pii data")
        assert scores["pii"] == 0.7

    def test_multiple_pii_keywords_score(self) -> None:
        from main import ModelService
        service = ModelService()
        scores = service._parse_safeguard_response(
            "Unsafe: pii found, contains ssn and personal data"
        )
        assert scores["pii"] == 0.9
