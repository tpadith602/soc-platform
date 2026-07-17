#!/usr/bin/env python3
"""
Random Forest Model Training
Target: 98.42% Accuracy (CICIDS2017 Dataset)

The model saved here (model/random_forest_model.pkl + scaler.pkl +
label_encoder.pkl + features.json) is loaded for live inference by
ingestion/ml_inference.py and used as the ML layer in nids_engine.py's
hybrid (rule-based + ML) DetectionEngine. See CHANGELOG.md for details
on how live traffic gets mapped onto this model's expected features.
"""

import pandas as pd
import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
from sklearn.preprocessing import StandardScaler
from pathlib import Path
import sys
import json
import warnings
warnings.filterwarnings('ignore')

sys.path.insert(0, str(Path(__file__).parent.parent))
from config.settings import MODEL_DIR, DATA_DIR

def train_model():
    print("=" * 60)
    print("🤖 Random Forest Model Training")
    print("=" * 60)

    # FIX: dataset_path now points at the curated traffic dataset the user
    # provided (data/processed_dataset.csv). It is NOT a raw CICIDS2017
    # export -- it's a 5-feature reduction (destination_port, duration,
    # packet_count, byte_count, connection_rate) covering BENIGN, PortScan,
    # FTP-Patator, and SSH-Patator. We still check the legacy filename too
    # in case a full CICIDS export is dropped in later.
    candidates = [
        DATA_DIR / 'processed_dataset.csv',
        DATA_DIR / 'cicids2017_processed.csv',
    ]
    dataset_path = next((p for p in candidates if p.exists()), None)
    if dataset_path is None:
        print(f"❌ No dataset found. Looked for: {[str(p) for p in candidates]}")
        return False

    df = pd.read_csv(dataset_path)
    print(f"📊 Loaded {len(df)} rows with {len(df.columns)} columns from {dataset_path.name}")

    # FIX: previously this auto-selected ALL numeric columns as features,
    # which silently included dead/constant columns (timestamp, protocol,
    # anomaly_score, threat_score, failed_logins were all constant zero in
    # the provided dataset) -- zero variance, zero signal, just noise.
    # If the curated 5-feature file is present we know its exact schema and
    # use it directly; otherwise fall back to the old auto-detect behavior
    # (with a zero-variance column drop) for other datasets.
    KNOWN_FEATURE_SET = ['destination_port', 'duration', 'packet_count', 'byte_count', 'connection_rate']
    target_cols = [col for col in df.columns if 'label' in col.lower() or 'class' in col.lower()]
    target_col = target_cols[0] if target_cols else df.columns[-1]

    if all(c in df.columns for c in KNOWN_FEATURE_SET):
        feature_cols = KNOWN_FEATURE_SET
        print(f"📊 Using known curated feature set: {feature_cols}")
    else:
        numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()
        feature_cols = [col for col in numeric_cols if col != target_col]
        # Drop zero-variance columns (constant across all rows = no signal)
        dropped = [c for c in feature_cols if df[c].nunique() <= 1]
        if dropped:
            print(f"⚠️ Dropping zero-variance columns: {dropped}")
            feature_cols = [c for c in feature_cols if c not in dropped]
        print(f"📊 Auto-detected features: {len(feature_cols)} columns")

    print(f"🎯 Target column: {target_col}")

    X = df[feature_cols].fillna(0)
    y = df[target_col]

    # FIX: previously checked `y.dtype == 'object'` to decide whether to
    # LabelEncode the target. Modern pandas (>=2.x with the string backend)
    # reports string columns as dtype 'str', not 'object', so that check
    # silently evaluated False and label_encoder.pkl was never written --
    # even though the labels were strings the whole time. RandomForestClassifier
    # natively supports string class labels (model.classes_ holds them), so
    # rather than patch the dtype check we just drop the encoder dependency
    # entirely and let sklearn carry the string labels through predict_proba.
    print(f"🏷️ Target classes: {sorted(y.unique())}")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    print(f"📊 Training: {len(X_train)} samples")
    print(f"📊 Test: {len(X_test)} samples")

    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    print("\n🤖 Training Random Forest...")
    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=15,
        random_state=42,
        n_jobs=-1,
        class_weight='balanced'
    )

    import time
    start = time.time()
    model.fit(X_train_scaled, y_train)
    elapsed = time.time() - start

    y_pred = model.predict(X_test_scaled)
    accuracy = accuracy_score(y_test, y_pred)

    print(f"\n📈 Accuracy: {accuracy*100:.2f}%")
    print(f"⏱️ Training time: {elapsed:.2f}s")
    print(f"\n📋 Classification Report:")
    print(classification_report(y_test, y_pred))

    MODEL_DIR.mkdir(parents=True, exist_ok=True)

    joblib.dump(model, MODEL_DIR / 'random_forest_model.pkl')
    joblib.dump(scaler, MODEL_DIR / 'scaler.pkl')
    # FIX: no separate label_encoder.pkl anymore -- model.classes_ already
    # holds the string class labels in predict_proba's column order, and
    # we persist that same list to features.json so ml_inference.py doesn't
    # need to re-load the model just to find the benign class index.
    classes = [str(c) for c in model.classes_]

    with open(MODEL_DIR / 'features.json', 'w') as f:
        json.dump({
            'features': feature_cols,
            'classes': classes,
            'accuracy': accuracy,
            'training_time': elapsed,
            'model_type': 'RandomForestClassifier'
        }, f, indent=2)

    print(f"\n✅ Model saved to: {MODEL_DIR}")
    print(f"   Classes: {classes}")
    return True

if __name__ == '__main__':
    train_model()
