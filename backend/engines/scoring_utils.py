import numpy as np


def clamp(x):
    return max(0.0, min(1.0, x))


def get_risk_bin(score):
    if score >= 75:
        return "critical"
    elif score >= 60:
        return "high"
    elif score >= 40:
        return "medium"
    elif score >= 25:
        return "low"
    return "safe"


def percentile_bin(score, history):
    if len(history) < 30:
        return get_risk_bin(score)

    arr = np.array(history)
    p = np.sum(arr < score) / len(arr)

    if p >= 0.90:
        return "critical"
    elif p >= 0.75:
        return "high"
    elif p >= 0.40:
        return "medium"
    elif p >= 0.15:
        return "low"
    return "safe"