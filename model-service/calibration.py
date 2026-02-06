"""
Score Calibration Pipeline for PooGuard Model Service.

Provides Platt scaling (logistic/sigmoid) calibration to map raw model scores
to well-calibrated probabilities. Applied AFTER raw model inference, BEFORE
threshold comparison.

Classes:
    NoOpCalibrator: Pass-through (no calibration file = no change)
    PlattCalibrator: Logistic regression calibration (sigmoid fit)
    IsotonicCalibrator: Non-parametric monotonic calibration
    CalibrationPipeline: Per-category calibration orchestrator
"""

import json
import logging
import math
from pathlib import Path
from typing import Optional

logger = logging.getLogger("pooguard-model-service")

# Categories that can be independently calibrated
CALIBRATION_CATEGORIES = ["prompt_injection", "jailbreak", "pii"]


class NoOpCalibrator:
    """Pass-through calibrator that returns scores unchanged.

    Used when no calibration data is available, ensuring backward
    compatibility with uncalibrated model output.
    """

    def calibrate(self, raw_score: float) -> float:
        return raw_score

    def to_dict(self) -> dict:
        return {"type": "noop"}

    @classmethod
    def from_dict(cls, data: dict) -> "NoOpCalibrator":
        return cls()


class PlattCalibrator:
    """Platt scaling calibrator using logistic (sigmoid) transformation.

    Maps raw score s to calibrated probability:
        P(y=1 | s) = 1 / (1 + exp(-(A*s + B)))

    Positive A means higher raw score -> higher calibrated probability.
    Parameters A and B are fit via gradient descent on cross-entropy loss
    (no scipy/sklearn dependency).
    """

    def __init__(self, A: float = 1.0, B: float = 0.0):
        self.A = A
        self.B = B

    def calibrate(self, raw_score: float) -> float:
        """Apply Platt scaling to a raw score. Returns value in [0, 1].

        Uses standard logistic convention: P = 1 / (1 + exp(-(A*s + B)))
        so that positive A means higher score -> higher calibrated probability.
        """
        exponent = self.A * raw_score + self.B
        # Clamp exponent to avoid overflow
        exponent = max(-500.0, min(500.0, exponent))
        calibrated = 1.0 / (1.0 + math.exp(-exponent))
        return max(0.0, min(1.0, calibrated))

    def fit(self, raw_scores: list[float], true_labels: list[int],
            max_iter: int = 500, tol: float = 1e-7) -> None:
        """Fit A, B parameters via gradient descent with adaptive step size.

        Uses the Platt (2000) formulation with target probabilities adjusted
        to avoid overfitting: t+ = (N+ + 1) / (N+ + 2), t- = 1 / (N- + 2).

        Args:
            raw_scores: List of raw model scores (0-1 range typically).
            true_labels: List of binary labels (1 = positive, 0 = negative).
            max_iter: Maximum optimization iterations.
            tol: Convergence tolerance on gradient norm.
        """
        if len(raw_scores) != len(true_labels):
            raise ValueError("raw_scores and true_labels must have same length")
        if len(raw_scores) < 2:
            raise ValueError("Need at least 2 samples to fit calibration")

        n = len(raw_scores)
        n_pos = sum(true_labels)
        n_neg = n - n_pos

        if n_pos == 0 or n_neg == 0:
            raise ValueError("Need at least one positive and one negative sample")

        # Platt's adjusted targets to avoid overfitting
        t_pos = (n_pos + 1.0) / (n_pos + 2.0)
        t_neg = 1.0 / (n_neg + 2.0)

        targets = [t_pos if label == 1 else t_neg for label in true_labels]

        # Initialize A, B
        A = 0.0
        B = 0.0

        # Adaptive learning rate (bold driver heuristic)
        lr = 1.0
        prev_nll = float("inf")

        for _iteration in range(max_iter):
            # Forward pass: compute predictions and loss
            # Convention: P = sigma(A*s + B) = 1 / (1 + exp(-(A*s + B)))
            nll = 0.0
            grad_A = 0.0
            grad_B = 0.0

            for i in range(n):
                s = raw_scores[i]
                t = targets[i]
                exponent = A * s + B
                exponent = max(-500.0, min(500.0, exponent))
                p = 1.0 / (1.0 + math.exp(-exponent))
                p_safe = max(1e-15, min(1.0 - 1e-15, p))
                nll += -(t * math.log(p_safe) + (1.0 - t) * math.log(1.0 - p_safe))

                # Gradient: d/dA NLL = sum (p_i - t_i) * s_i
                diff = p - t
                grad_A += diff * s
                grad_B += diff

            grad_A /= n
            grad_B /= n

            # Check convergence on gradient norm
            grad_norm = math.sqrt(grad_A * grad_A + grad_B * grad_B)
            if grad_norm < tol:
                break

            # Bold driver: increase lr if loss decreased, decrease if it increased
            if nll < prev_nll:
                lr *= 1.05
            else:
                lr *= 0.5

            prev_nll = nll

            # Gradient descent step
            A -= lr * grad_A
            B -= lr * grad_B

        self.A = A
        self.B = B

    def to_dict(self) -> dict:
        return {"type": "platt", "A": self.A, "B": self.B}

    @classmethod
    def from_dict(cls, data: dict) -> "PlattCalibrator":
        return cls(A=data["A"], B=data["B"])


class IsotonicCalibrator:
    """Non-parametric isotonic (monotonic) calibration.

    Uses the pool adjacent violators (PAV) algorithm to produce a
    monotonically non-decreasing mapping from raw scores to calibrated
    probabilities via piecewise-linear interpolation.
    """

    def __init__(self):
        self._x_points: list[float] = []
        self._y_points: list[float] = []

    def calibrate(self, raw_score: float) -> float:
        """Apply isotonic calibration via linear interpolation."""
        if not self._x_points:
            return raw_score

        # Clamp to range
        if raw_score <= self._x_points[0]:
            return self._y_points[0]
        if raw_score >= self._x_points[-1]:
            return self._y_points[-1]

        # Binary search for the interval
        lo, hi = 0, len(self._x_points) - 1
        while lo < hi - 1:
            mid = (lo + hi) // 2
            if self._x_points[mid] <= raw_score:
                lo = mid
            else:
                hi = mid

        # Linear interpolation
        x0, x1 = self._x_points[lo], self._x_points[hi]
        y0, y1 = self._y_points[lo], self._y_points[hi]
        if x1 == x0:
            return y0
        t = (raw_score - x0) / (x1 - x0)
        calibrated = y0 + t * (y1 - y0)
        return max(0.0, min(1.0, calibrated))

    def fit(self, raw_scores: list[float], true_labels: list[int]) -> None:
        """Fit isotonic regression using PAV algorithm.

        Args:
            raw_scores: List of raw model scores.
            true_labels: List of binary labels (1 = positive, 0 = negative).
        """
        if len(raw_scores) != len(true_labels):
            raise ValueError("raw_scores and true_labels must have same length")
        if len(raw_scores) < 2:
            raise ValueError("Need at least 2 samples to fit calibration")

        # Sort by raw_scores
        pairs = sorted(zip(raw_scores, true_labels), key=lambda p: p[0])

        # PAV algorithm
        # Each block is [sum_of_values, count, min_x, max_x]
        blocks: list[list] = []
        for x, y in pairs:
            blocks.append([float(y), 1, x, x])
            # Merge violating adjacent blocks
            while len(blocks) >= 2:
                last = blocks[-1]
                prev = blocks[-2]
                if prev[0] / prev[1] > last[0] / last[1]:
                    # Merge: pool adjacent violators
                    prev[0] += last[0]
                    prev[1] += last[1]
                    prev[3] = last[3]  # extend max_x
                    blocks.pop()
                else:
                    break

        # Build interpolation points from blocks
        self._x_points = []
        self._y_points = []
        for block_sum, block_count, min_x, max_x in blocks:
            avg_y = block_sum / block_count
            # Use midpoint of x-range as the representative x
            mid_x = (min_x + max_x) / 2.0
            self._x_points.append(mid_x)
            self._y_points.append(avg_y)

    def to_dict(self) -> dict:
        return {
            "type": "isotonic",
            "x_points": self._x_points,
            "y_points": self._y_points,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "IsotonicCalibrator":
        cal = cls()
        cal._x_points = data["x_points"]
        cal._y_points = data["y_points"]
        return cal


# Registry for deserializing calibrators from JSON
_CALIBRATOR_TYPES = {
    "noop": NoOpCalibrator,
    "platt": PlattCalibrator,
    "isotonic": IsotonicCalibrator,
}


def _calibrator_from_dict(data: dict):
    """Deserialize a calibrator from its dict representation."""
    cal_type = data.get("type", "noop")
    cls = _CALIBRATOR_TYPES.get(cal_type)
    if cls is None:
        logger.warning(f"Unknown calibrator type '{cal_type}', using NoOp")
        return NoOpCalibrator()
    return cls.from_dict(data)


class CalibrationPipeline:
    """Orchestrates per-category score calibration.

    Holds one calibrator per threat category (prompt_injection, jailbreak, pii).
    When no calibration file is present, all calibrators default to NoOp.
    """

    def __init__(self):
        self.calibrators: dict = {
            cat: NoOpCalibrator() for cat in CALIBRATION_CATEGORIES
        }
        self.calibrated: bool = False

    def calibrate_scores(self, raw_scores: dict[str, float]) -> dict[str, float]:
        """Calibrate all category scores.

        Args:
            raw_scores: Dict with keys from CALIBRATION_CATEGORIES and float values.

        Returns:
            Dict with same keys, calibrated float values clamped to [0, 1].
        """
        result = {}
        for cat in CALIBRATION_CATEGORIES:
            raw = raw_scores.get(cat, 0.0)
            calibrated = self.calibrators[cat].calibrate(raw)
            result[cat] = max(0.0, min(1.0, calibrated))
        return result

    def get_state(self) -> dict:
        """Return current calibration state for the /calibration endpoint."""
        return {
            "calibrated": self.calibrated,
            "categories": {
                cat: self.calibrators[cat].to_dict()
                for cat in CALIBRATION_CATEGORIES
            },
        }

    def save_to_file(self, path: str) -> None:
        """Save calibration parameters to a JSON file."""
        state = {
            cat: self.calibrators[cat].to_dict()
            for cat in CALIBRATION_CATEGORIES
        }
        Path(path).write_text(json.dumps(state, indent=2))
        logger.info(f"Calibration parameters saved to {path}")

    def load_from_file(self, path: str) -> bool:
        """Load calibration parameters from a JSON file.

        Returns True if loaded successfully, False if file not found or invalid.
        """
        p = Path(path)
        if not p.exists():
            logger.info(f"No calibration file at {path}, using NoOp calibrators")
            self.calibrated = False
            return False

        try:
            data = json.loads(p.read_text())
            for cat in CALIBRATION_CATEGORIES:
                if cat in data:
                    self.calibrators[cat] = _calibrator_from_dict(data[cat])
                else:
                    self.calibrators[cat] = NoOpCalibrator()

            # Mark as calibrated if any calibrator is not NoOp
            self.calibrated = any(
                not isinstance(self.calibrators[cat], NoOpCalibrator)
                for cat in CALIBRATION_CATEGORIES
            )
            logger.info(
                f"Calibration parameters loaded from {path} "
                f"(calibrated={self.calibrated})"
            )
            return True
        except (json.JSONDecodeError, KeyError, TypeError) as e:
            logger.warning(f"Failed to load calibration file {path}: {e}")
            self.calibrated = False
            return False

    def fit_from_benchmark(
        self,
        results: dict[str, dict],
        method: str = "platt",
    ) -> None:
        """Fit calibrators from benchmark results.

        Args:
            results: Dict with category keys, each containing:
                - raw_scores: list of raw model scores
                - true_labels: list of binary labels
            method: "platt" or "isotonic"
        """
        for cat in CALIBRATION_CATEGORIES:
            if cat not in results:
                logger.warning(f"No benchmark data for '{cat}', keeping NoOp")
                continue

            cat_data = results[cat]
            raw_scores = cat_data.get("raw_scores", [])
            true_labels = cat_data.get("true_labels", [])

            if len(raw_scores) < 2:
                logger.warning(f"Insufficient data for '{cat}' ({len(raw_scores)} samples), keeping NoOp")
                continue

            try:
                if method == "isotonic":
                    cal = IsotonicCalibrator()
                else:
                    cal = PlattCalibrator()
                cal.fit(raw_scores, true_labels)
                self.calibrators[cat] = cal
                logger.info(f"Fitted {method} calibrator for '{cat}' on {len(raw_scores)} samples")
            except ValueError as e:
                logger.warning(f"Failed to fit calibrator for '{cat}': {e}")

        self.calibrated = any(
            not isinstance(self.calibrators[cat], NoOpCalibrator)
            for cat in CALIBRATION_CATEGORIES
        )
