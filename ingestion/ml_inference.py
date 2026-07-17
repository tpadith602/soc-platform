"""
ML Inference Engine

Loads the Random Forest model trained by scripts/train_model.py and scores
feature vectors built by pipeline/flow_features.py. This is what was
missing before: the model was trained and saved to disk but nothing ever
loaded it back for live predictions. This module closes that gap.

Designed to fail soft: if no trained model exists yet (model/*.pkl missing),
`MLAnomalyDetector.available` is False and `predict()` always returns None,
so the rest of the pipeline (rule-based detection) keeps working unaffected.

FIX (vs. an earlier version of this module): the original design assumed a
separate label_encoder.pkl produced by LabelEncoder. That branch in
train_model.py never actually fired (a dtype-check bug meant string labels
were never encoded), and it turns out scikit-learn classifiers support
string class labels natively anyway -- model.classes_ already holds them
in the same order predict_proba returns. So this module no longer looks
for label_encoder.pkl at all; it reads the class list straight from
features.json (written by train_model.py) for a small startup-time check,
and falls back to the model's own .classes_ attribute as the source of
truth at prediction time.
"""

import json
import logging
from pathlib import Path
from typing import List, Optional, Tuple

log = logging.getLogger("soc.ml_inference")

try:
    import joblib
except ImportError:
    joblib = None


class MLAnomalyDetector:
    # FIX: confidence below this is too noisy to alert on
    MIN_CONFIDENCE = 0.60

    def __init__(self, model_dir: Path):
        self.model_dir = Path(model_dir)
        self.model = None
        self.scaler = None
        self.feature_names: List[str] = []
        self.classes: List[str] = []
        self.benign_index: Optional[int] = None
        self.available = False
        self._load()

    def _load(self) -> None:
        if joblib is None:
            log.warning("joblib not installed - ML inference disabled")
            return

        model_path = self.model_dir / 'random_forest_model.pkl'
        scaler_path = self.model_dir / 'scaler.pkl'
        features_path = self.model_dir / 'features.json'

        if not (model_path.exists() and scaler_path.exists() and features_path.exists()):
            log.warning(
                f"No trained model found in {self.model_dir} "
                "(run scripts/train_model.py first) - ML inference disabled, "
                "rule-based detection will still run."
            )
            return

        try:
            self.model = joblib.load(model_path)
            self.scaler = joblib.load(scaler_path)
            with open(features_path) as f:
                meta = json.load(f)
            self.feature_names = meta.get('features', [])

            # FIX: classes come from the model itself (authoritative,
            # correctly ordered for predict_proba), not a separate encoder.
            self.classes = [str(c) for c in getattr(self.model, 'classes_', meta.get('classes', []))]
            self.benign_index = self._find_benign_index(self.classes)

            self.available = True
            log.info(
                f"✅ ML model loaded: {len(self.feature_names)} features, "
                f"classes={self.classes}, benign_index={self.benign_index}"
            )
        except Exception as e:
            log.error(f"Failed to load ML model: {e}")
            self.available = False

    @staticmethod
    def _find_benign_index(classes) -> int:
        for i, c in enumerate(classes):
            if 'benign' in c.lower() or 'normal' in c.lower():
                return i
        return 0  # fall back to first class if nothing matches "benign"/"normal"

    def predict(self, feature_vector: List[float]) -> Optional[Tuple[bool, float, str]]:
        """Returns (is_anomaly, confidence, predicted_label) or None if the
        model isn't available or the vector is the wrong shape."""
        if not self.available:
            return None
        if len(feature_vector) != len(self.feature_names):
            log.warning(
                f"Feature vector length {len(feature_vector)} != expected "
                f"{len(self.feature_names)} - skipping ML scoring for this sample"
            )
            return None

        try:
            import pandas as pd
            row = pd.DataFrame([feature_vector], columns=self.feature_names)
            scaled = self.scaler.transform(row)
            proba = self.model.predict_proba(scaled)[0]
            pred_idx = int(proba.argmax())
            confidence = float(proba[pred_idx])

            is_anomaly = pred_idx != self.benign_index and confidence >= self.MIN_CONFIDENCE
            label = self.classes[pred_idx] if pred_idx < len(self.classes) else str(pred_idx)

            return is_anomaly, confidence, label
        except Exception as e:
            log.error(f"ML prediction failed: {e}")
            return None
