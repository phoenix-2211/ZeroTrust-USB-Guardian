# =========================
# Decision Engine – Phase 2.4.3
# =========================

def decide_action(final_score):
    if final_score < 30:
        return "ALLOW", "SAFE"

    elif 30 <= final_score < 50:
        return "WARN", "SOFT_WARN"

    elif 50 <= final_score < 70:
        return "WARN", "HARD_WARN"

    else:
        return "BLOCK", "CRITICAL"
# End of decision_engine.py