MITRE_MAP = {
    "SOC-RULE-001": {
        "tactic": "Credential Access",
        "technique": "T1566 - Phishing",
    },
    "SOC-RULE-002": {
        "tactic": "Initial Access",
        "technique": "T1566.002 - Spearphishing Link",
    },
    "SOC-RULE-003": {
        "tactic": "Resource Development",
        "technique": "T1583 - Acquire Infrastructure",
    },
    "SOC-RULE-004": {
        "tactic": "Persistence",
        "technique": "T1078 - Valid Accounts (attempted)"
    }
}


def evaluate_rules(identity_hits, behavior_hits, infra_hits, signals):

    rules = []

    # RULE 1 - Phishing Credential Correlation
    if identity_hits >= 1 and "credentials" in signals:
        rules.append({
            "rule_id": "SOC-RULE-001",
            "name": "Credential Phishing Attempt",
            "severity": "high",
            "logic": "identity + credentials signal"
        })

    # RULE 2 - Urgency Manipulation Pattern
    if "urgency" in signals and "credentials" in signals:
        rules.append({
            "rule_id": "SOC-RULE-002",
            "name": "Urgency-based Social Engineering",
            "severity": "medium",
            "logic": "urgency + credential pressure"
        })

    # RULE 3 - Brand Impersonation Attack
    if "brand_impersonation" in signals:
        rules.append({
            "rule_id": "SOC-RULE-003",
            "name": "Brand Impersonation Detected",
            "severity": "high",
            "logic": "fake brand domain detected"
        })

    # RULE 4 - Malicious Infrastructure Pattern
    if infra_hits >= 1:
        rules.append({
            "rule_id": "SOC-RULE-004",
            "name": "Suspicious Infrastructure",
            "severity": "low",
            "logic": "new or suspicious domain"
        })

    return rules

