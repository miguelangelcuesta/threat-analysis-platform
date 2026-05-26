import re
from datetime import datetime, date
from urllib.parse import urlparse

from sentence_transformers import SentenceTransformer, util
from backend.soc.soc_rules import evaluate_rules


# =========================
# CONFIG
# =========================

_model = None
INTENT_EMB = None

SIM_THRESHOLD = 0.22

MAX_URL_SCORE = 100
MAX_ML_SCORE = 120


# =========================
# MODEL
# =========================

def get_model():
    global _model
    if _model is None:
        _model = SentenceTransformer("all-MiniLM-L6-v2")
    return _model


# =========================
# INTENTS
# =========================

INTENTS = {
    "impersonation": "paypal microsoft google amazon apple bank security account verification",
    "credentials": "password login credentials verify account card code",
    "threats": "suspended blocked terminated urgent security alert",
    "urgency": "immediately urgent now action required",
    "reward": "gift prize reward lottery bonus",
    "suspicious_link": "click link login verify secure access",
    "benign_security": "security awareness documentation best practices training"
}

WEIGHTS = {
    "impersonation": 30,
    "credentials": 35,
    "threats": 25,
    "urgency": 15,
    "reward": 10,
    "suspicious_link": 25,
    "benign_security": -25
}

SIGNAL_MAP = {
    "impersonation": "brand_impersonation",
    "credentials": "credentials",
    "threats": "threats",
    "urgency": "urgency",
    "reward": "reward",
    "suspicious_link": "suspicious_link",
    "benign_security": "benign_security"
}


identity_signals = {"brand_impersonation"}
behavior_signals = {
    "credentials",
    "threats",
    "urgency",
    "reward",
    "suspicious_link"
}

infra_signals = {
    "very_new_domain",
    "recent_domain",
    "long_domain"
}


# =========================
# HELPERS
# =========================

def extract_urls(text):
    return re.findall(r'(https?://[^\s]+)', text or "")


def extract_domain(url):
    try:
        return urlparse(url).netloc.replace("www.", "").lower()
    except:
        return ""


def clamp(x):
    return max(0.0, min(1.0, x))


# =========================
# RISK LEVEL
# =========================

def get_risk_bin(score):
    if score >= 80:
        return "critical"
    elif score >= 60:
        return "high"
    elif score >= 35:
        return "medium"
    elif score >= 15:
        return "low"
    return "safe"


# =========================
# DOMAIN ANALYSIS
# =========================

def domain_risk(domain):
    score = 0
    signals = []

    if not domain:
        return 0, []

    legit = [
        "paypal.com",
        "google.com",
        "amazon.com",
        "amazon.es",
        "apple.com",
        "microsoft.com"
    ]

    if any(b in domain for b in ["paypal", "google", "amazon", "apple", "microsoft"]):
        if not any(domain.endswith(d) for d in legit):
            score += 40
            signals.append("brand_impersonation")

    if any(k in domain for k in ["login", "secure", "verify", "account"]):
        score += 15
        signals.append("phishing_keywords")

    if len(domain) > 30:
        score += 10
        signals.append("long_domain")

    return score, signals


# =========================
# WHOIS
# =========================

def whois_risk(domain):
    score = 0
    signals = []

    try:
        import whois
        w = whois.whois(domain)
        creation = w.creation_date

        if isinstance(creation, list):
            creation = creation[0]

        if creation:
            if isinstance(creation, date):
                creation = datetime.combine(creation, datetime.min.time())

            age_days = (datetime.now() - creation).days

            if age_days < 30:
                score += 30
                signals.append("very_new_domain")
            elif age_days < 180:
                score += 10
                signals.append("recent_domain")

    except:
        pass

    return score, signals


# =========================
# EMBEDDINGS
# =========================

def get_embeddings(model):
    global INTENT_EMB

    if INTENT_EMB is None:
        INTENT_EMB = {
            k: model.encode(v, convert_to_tensor=True)
            for k, v in INTENTS.items()
        }

    return INTENT_EMB


# =========================
# HUMAN LAYER
# =========================

def build_text_analysis(signals):
    techniques = []

    if "urgency" in signals:
        techniques.append("Uso de urgencia para manipular al usuario")

    if "threats" in signals:
        techniques.append("Mensajes de presión o bloqueo")

    if "credentials" in signals:
        techniques.append("Intento de robo de credenciales")

    if "reward" in signals:
        techniques.append("Promesas de recompensa o premio")

    intention = (
        "Manipulación psicológica"
        if techniques
        else "Sin intención sospechosa clara"
    )

    return intention, techniques


def build_url_analysis(domain, signals):
    if not domain:
        return "-", "No se detectó URL"

    if "brand_impersonation" in signals:
        return domain, "Posible suplantación de marca"

    if "phishing_keywords" in signals:
        return domain, "Uso de patrones típicos de phishing"

    if "very_new_domain" in signals:
        return domain, "Dominio recién registrado"

    return domain, "Sin anomalías técnicas relevantes"


def build_attack_chain(signals):
    chain = []

    if "brand_impersonation" in signals:
        chain.append("Suplantación de identidad")

    if "urgency" in signals:
        chain.append("Presión psicológica")

    if "credentials" in signals:
        chain.append("Intento de robo de credenciales")

    if "suspicious_link" in signals:
        chain.append("Enlace fraudulento")

    return chain


def build_evidence(signals):
    evidence = []

    if "brand_impersonation" in signals:
        evidence.append("Suplantación de marca detectada")

    if "credentials" in signals:
        evidence.append("Posible robo de credenciales")

    if "urgency" in signals:
        evidence.append("Uso de urgencia para manipulación")

    if "suspicious_link" in signals:
        evidence.append("Enlace sospechoso detectado")

    if "very_new_domain" in signals:
        evidence.append("Dominio recién creado")

    return evidence


def build_summary(score):
    if score >= 80:
        return "Intento de phishing crítico con alta probabilidad de robo de credenciales."
    elif score >= 60:
        return "Se detecta un patrón de fraude altamente sospechoso."
    elif score >= 35:
        return "Se detectan indicios de actividad sospechosa moderada."
    elif score >= 15:
        return "Existen algunas señales leves de riesgo."
    return "No se detectan indicadores relevantes de amenaza."


# =========================
# MAIN ENGINE
# =========================

def analyze_text(text: str):

    model = get_model()
    text = text or ""

    embedding = model.encode(text, convert_to_tensor=True)

    semantic_hits = []
    url_signals = []
    whois_signals = []

    # URL
    urls = extract_urls(text)

    url_score = 0
    main_domain = "-"

    for url in urls:
        domain = extract_domain(url)
        main_domain = domain

        d_score, d_sig = domain_risk(domain)
        w_score, w_sig = whois_risk(domain)

        url_score += d_score + w_score
        url_signals.extend(d_sig)
        whois_signals.extend(w_sig)

    url_norm = clamp(url_score / MAX_URL_SCORE)

    # ML
    emb = get_embeddings(model)

    ml_score = 0
    benign_score = 0

    for intent, proto in emb.items():
        sim = util.cos_sim(embedding, proto).item()

        if sim > SIM_THRESHOLD:
            semantic_hits.append(SIGNAL_MAP[intent])

            if intent == "benign_security":
                benign_score += abs(WEIGHTS[intent]) * sim
            else:
                ml_score += WEIGHTS[intent] * sim

    ml_norm = clamp((ml_score - benign_score) / MAX_ML_SCORE)

    # SIGNALS
    all_signals = set(semantic_hits + url_signals + whois_signals)

    identity_hits = len(all_signals & identity_signals)
    behavior_hits = len(all_signals & behavior_signals)
    infra_hits = len(all_signals & infra_signals)

    rules_triggered = evaluate_rules(
        identity_hits,
        behavior_hits,
        infra_hits,
        all_signals
    )

    rule_score = clamp(len(rules_triggered) * 0.15)

    attack_chain_score = 0.15 if (
        identity_hits >= 1 and behavior_hits >= 2
    ) else 0

    phishing_confidence = 0
    if "brand_impersonation" in all_signals:
        phishing_confidence += 0.15
    if "credentials" in all_signals:
        phishing_confidence += 0.20
    if "suspicious_link" in all_signals:
        phishing_confidence += 0.15
    if "very_new_domain" in all_signals:
        phishing_confidence += 0.15

    phishing_confidence = clamp(phishing_confidence)

    # FINAL RISK
    risk = (
        ml_norm * 0.35 +
        url_norm * 0.30 +
        rule_score * 0.15 +
        attack_chain_score * 0.20 +
        phishing_confidence
    )

    risk = clamp(risk)
    score = int(risk * 100)
    level = get_risk_bin(score)

    intention, techniques = build_text_analysis(all_signals)
    domain, url_problem = build_url_analysis(main_domain, all_signals)

    return {
        "verdict": {
            "level": level,
            "score": score,
            "action": (
                "Bloquear inmediatamente" if level == "critical"
                else "Revisión urgente" if level == "high"
                else "Monitorizar" if level == "medium"
                else "Sin acción necesaria"
            )
        },

        "executive_summary": build_summary(score),

        "analysis": {
            "text": {
                "intention": intention,
                "tecnicas": techniques
            },
            "url": {
                "dominio": domain,
                "problema": url_problem
            }
        },

        "cadena_ataque": build_attack_chain(all_signals),
        "evidencias": build_evidence(all_signals),
        "signals": list(all_signals)
    }