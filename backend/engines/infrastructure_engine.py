from datetime import datetime, date

from backend.engines.url_utils import domain_resolves


TRUSTED_DOMAINS = {
    "msn.com",
    "google.com",
    "microsoft.com",
    "amazon.com",
    "apple.com",
    "paypal.com",
    "mundodeportivo.com"
}


def domain_risk(domain):
    score = 0
    signals = []

    if not domain:
        return 0, ["empty_domain"]

    if domain in TRUSTED_DOMAINS:
        signals.append("trusted_domain")
    else:
        signals.append("unknown_domain")
        score += 8

    if not domain_resolves(domain):
        signals.append("domain_unresolvable")
        signals.append("domain_non_existent")
        score += 35

    brands = ["paypal", "google", "amazon", "apple", "microsoft"]

    if any(b in domain for b in brands):
        if domain not in TRUSTED_DOMAINS:
            score += 40
            signals.append("brand_impersonation")

    if any(k in domain for k in ["login", "secure", "verify", "account"]):
        score += 15
        signals.append("phishing_keywords")

    if len(domain) > 30:
        score += 10
        signals.append("long_domain")

    return score, signals


def whois_risk(domain):
    score = 0
    signals = []

    try:
        import whois
        w = whois.whois(domain)
        creation = w.creation_date

        if not creation:
            return 10, ["no_whois_data"]

        if isinstance(creation, list):
            creation = creation[0]

        if isinstance(creation, date):
            creation = datetime.combine(creation, datetime.min.time())

        age_days = (datetime.now() - creation).days

        if age_days < 30:
            score += 25
            signals.append("very_new_domain")

        elif age_days < 180:
            score += 10
            signals.append("recent_domain")

        else:
            signals.append("established_domain")

    except Exception:
        return 10, ["whois_lookup_failed"]

    return score, signals


def confidence_score(semantic_hits, url_signals, whois_signals, rules_triggered):
    score = 1.0
    signals = []

    if len(semantic_hits) == 0:
        score -= 0.25
        signals.append("no_semantic_evidence")

    if len(url_signals) == 0:
        score -= 0.15
        signals.append("no_url_evidence")

    if len(whois_signals) == 0:
        score -= 0.10
        signals.append("no_whois_evidence")

    if len(rules_triggered) == 0:
        score -= 0.15
        signals.append("no_rule_evidence")

    if len(semantic_hits) > 0 and len(url_signals) == 0:
        score -= 0.10
        signals.append("signal_mismatch")

    score = max(0.0, min(1.0, score))

    return score, signals


def trust_score(domain):
    signals = []

    if not domain:
        return 0.5, ["no_domain"]

    if domain in TRUSTED_DOMAINS:
        return 1.0, ["trusted_domain"]

    score = 0.5

    if domain.endswith((".com", ".es", ".org", ".net")):
        score += 0.2
        signals.append("standard_tld")

    if domain.count(".") > 2:
        score -= 0.2
        signals.append("many_subdomains")

    if any(k in domain for k in ["login", "secure", "verify", "account"]):
        score -= 0.3
        signals.append("suspicious_keywords")

    score = max(0.0, min(1.0, score))

    return score, signals