# =========================================
# USB RISK PREDICTOR (PHASE 2.4 – HYBRID)
# REVISED FOR GUI + PACKAGE STRUCTURE
# =========================================

import os
import joblib
import pandas as pd

# ---- Core imports ----
from core.usb_scanner import scan_usb

# ---- Rule + Risk engines ----
from rules.rule_engine import apply_rules
from risk.hybrid_risk_engine import calculate_final_score
from risk.decision_engine import decide_action


RISK_MAP = {
    0: "LOW RISK 🙂",
    1: "MEDIUM RISK ⚠️",
    2: "HIGH RISK 😈"
}


def predict_usb_risk(drive_path: str):
    """
    GUI-safe USB risk prediction entry point.
    No input(), no print(), no exit().
    Returns a structured result dictionary.
    """

    # =====================
    # Resolve model path
    # =====================
    current_dir = os.path.dirname(os.path.abspath(__file__))
    root_dir = os.path.dirname(os.path.dirname(current_dir))
    model_path = os.path.join(root_dir, "models", "usb_risk_model.pkl")

    if not os.path.exists(model_path):
        raise FileNotFoundError("usb_risk_model.pkl not found")

    # =====================
    # Load ML model (LOCKED)
    # =====================
    model = joblib.load(model_path)
    feature_order = list(model.feature_names_in_)

    # =====================
    # Validate USB path
    # =====================
    if not os.path.exists(drive_path):
        raise FileNotFoundError("USB path does not exist")

    if not drive_path.endswith("\\"):
        raise ValueError("USB path must end with \\")

    # =====================
    # Scan USB
    # =====================
    scan_result = scan_usb(drive_path)

    if isinstance(scan_result, dict):
        features = scan_result
        scanned_files = []
    else:
        features, scanned_files = scan_result

    # =====================
    # ML Inference (Phase 2.3)
    # =====================
    row = {feature: features.get(feature, 0) for feature in feature_order}
    df = pd.DataFrame([row], columns=feature_order)

    prediction = model.predict(df)[0]
    probabilities = model.predict_proba(df)[0]

    ml_probs = {
        "LOW": round(probabilities[0] * 100, 2),
        "MEDIUM": round(probabilities[1] * 100, 2),
        "HIGH": round(probabilities[2] * 100, 2)
    }

    # =====================
    # Rule Engine (Phase 2.4)
    # =====================
    rule_score, rule_hits = apply_rules(drive_path, scanned_files)

    # =====================
    # Hybrid Risk Engine
    # =====================
    final_score = calculate_final_score(rule_score, ml_probs)
    decision, severity = decide_action(final_score)

    # =====================
    # Structured Output
    # =====================
    return {
        "usb_path": drive_path,
        "ml_prediction": RISK_MAP[prediction],
        "ml_probabilities": ml_probs,
        "rule_score": rule_score,
        "rule_hits": rule_hits,
        "final_score": final_score,
        "decision": decision,
        "severity": severity
    }


# =========================================
# END OF USB RISK PREDICTOR (PHASE 2.4)
# =========================================
