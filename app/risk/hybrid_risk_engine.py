# =========================================
# HYBRID RISK ENGINE – PHASE 2.4
# Rules dominate, ML assists
# =========================================

def calculate_ml_score(ml_probs: dict) -> float:
    """
    Calculate weighted ML risk score from class probabilities.
    ml_probs values are expected in percentage (0–100).
    """

    return (
        ml_probs.get("LOW", 0) * 0.2 +
        ml_probs.get("MEDIUM", 0) * 0.5 +
        ml_probs.get("HIGH", 0) * 1.0
    )


def calculate_final_score(rule_score: float, ml_probs: dict) -> float:
    """
    Final hybrid risk score.
    Rule engine dominates, ML assists.
    """

    ml_score = calculate_ml_score(ml_probs)

    final_score = (rule_score * 0.6) + (ml_score * 0.4)

    return round(final_score, 2)


# =========================================
# END OF HYBRID RISK ENGINE
# =========================================
