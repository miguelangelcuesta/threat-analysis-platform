from collections import defaultdict

IDENTITY = {"brand_impersonation", "phishing_keywords"}
BEHAVIOR = {
    "credentials",
    "threats",
    "urgency",
    "reward",
    "suspicious_link"
}
INFRA = {"very_new_domain", "recent_domain", "long_domain"}


def group_signals(signals: list[str]) -> dict:
    """
    Clasifica señales del engine en capas SOC.
    """

    grouped = {
        "identity": [],
        "behavior": [],
        "infra": [],
        "unknown": []
    }

    for s in signals:
        if s in IDENTITY:
            grouped["identity"].append(s)

        elif s in BEHAVIOR:
            grouped["behavior"].append(s)

        elif s in INFRA:
            grouped["infra"].append(s)

        else:
            grouped["unknown"].append(s)

    return grouped