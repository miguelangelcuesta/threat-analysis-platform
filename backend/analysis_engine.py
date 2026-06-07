import re
import math
import numpy as np
from collections import deque
from datetime import datetime, date
from urllib.parse import urlparse

from sentence_transformers import SentenceTransformer, util
from backend.soc.soc_rules import evaluate_rules


# =========================
# CONFIG
# =========================

_model = None
INTENT_EMB = None

SIM_THRESHOLD = 0.18

MAX_URL_SCORE = 100
MAX_ML_SCORE = 120

# 📊 historial para calibración
RISK_HISTORY = deque(maxlen=500)


# =========================
# MODEL
# =========================

def get_model():
    global _model
    if _model is None:
        _model = SentenceTransformer("sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2")
    return _model


# =========================
# INTENTS
# =========================


INTENTS = {

    "impersonation": """
paypal microsoft google amazon apple banco soporte seguridad cuenta verificación
equipo de seguridad verificación de identidad alerta de seguridad acceso seguro
""",

    "credentials": """
contraseña iniciar sesión credenciales acceso usuario autenticación pin código
introduce tu contraseña verifica tu cuenta banco login acceso seguro
""",

    "threats": """
cuenta suspendida bloqueada desactivada restringida acceso denegado
alerta de seguridad advertencia final eliminación permanente cuenta comprometida
""",

    "urgency": """
urgente inmediatamente ahora acción requerida tiempo limitado última advertencia
actúa ya responde hoy en minutos respuesta inmediata
""",

    "reward": """
premio regalo recompensa lotería bono dinero gratis cashback ganaste
has ganado reclama tu premio oferta exclusiva
""",

    "suspicious_link": """
haz clic en el enlace inicia sesión verifica acceso seguro portal
actualiza tu cuenta confirma identidad página de inicio sesión enlace seguro
""",

    "benign_security": """
formación en seguridad buenas prácticas documentación interna políticas de empresa
concienciación seguridad procedimientos corporativos ciberseguridad educación
"""
}


WEIGHTS = {
    "impersonation": 25,
    "credentials": 30,
    "threats": 25,
    "urgency": 20,
    "reward": 15,
    "suspicious_link": 25,
    "benign_security": -30
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
# UI MAP (SINGLE SOURCE OF TRUTH)
# =========================

UI_MAP = {
    "safe": {
        "color": "#22c55e",
        "bg": "#071a12",
        "label": "SEGURO"
    },
    "low": {
        "color": "#38bdf8",
        "bg": "#0a1f2a",
        "label": "BAJO RIESGO"
    },
    "medium": {
        "color": "#facc15",
        "bg": "#2a240a",
        "label": "RIESGO MEDIO"
    },
    "high": {
        "color": "#fb923c",
        "bg": "#2a1408",
        "label": "RIESGO ALTO"
    },
    "critical": {
        "color": "#ef4444",
        "bg": "#2a0707",
        "label": "CRÍTICO"
    }
}


# =========================
# RISK LEVEL (CALIBRADO)
# =========================

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

    intention = "Manipulación psicológica" if techniques else "Sin intención sospechosa clara"

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
    if score >= 85:
        return "Intento de phishing crítico con alta probabilidad de robo de credenciales."
    elif score >= 65:
        return "Se detecta un patrón de fraude altamente sospechoso."
    elif score >= 40:
        return "Se detectan indicios de actividad sospechosa moderada."
    elif score >= 20:
        return "Existen algunas señales leves de riesgo."
    return "No se detectan indicadores relevantes de amenaza"


# =========================
# NORMALIZACIÓN ESTABLE
# =========================

# NOTE: funciones eliminadas porque no se usan en el motor actual:
# - percentile_score
# - calibrate


def percentile_bin(score, history):

    if len(history) < 30:
        if score >= 75:
            return "critical"
        elif score >= 60:
            return "high"
        elif score >= 40:
            return "medium"
        elif score >= 25:
            return "low"
        return "safe"

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

    # =========================
    # URL ANALYSIS
    # =========================

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

    url_norm = clamp(url_score / MAX_URL_SCORE) if urls else 0.0


    # =========================
    # ML SCORE
    # =========================

    emb = get_embeddings(model)

    ml_score = 0
    benign_score = 0

    for intent, proto in emb.items():
        sim = util.cos_sim(embedding, proto).item()
        sim = max(0, sim)

        if sim > SIM_THRESHOLD:
            semantic_hits.append(SIGNAL_MAP[intent])

        if intent == "benign_security":
            benign_score += abs(WEIGHTS[intent]) * sim
        else:
            ml_score += WEIGHTS[intent] * sim

    ml_norm = ml_score / MAX_ML_SCORE
    ml_norm = ml_norm - (benign_score / MAX_ML_SCORE)
    ml_norm = clamp(ml_norm)


    # =========================
    # SIGNALS
    # =========================

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

    rule_score = clamp(len(rules_triggered) / 5)


    # =========================
    # ATTACK PATTERN SCORE (SIN OVERBOOST)
    # =========================

    attack_chain_score = 0.10 if (identity_hits >= 1 and behavior_hits >= 2) else 0.0

    phishing_confidence = 0.0

    if "brand_impersonation" in all_signals:
        phishing_confidence += 0.15
    if "credentials" in all_signals:
        phishing_confidence += 0.20
    if "suspicious_link" in all_signals:
        phishing_confidence += 0.10
    if "very_new_domain" in all_signals:
        phishing_confidence += 0.10

    phishing_confidence = clamp(phishing_confidence / 0.55)


    # =========================
    # CRITICAL PATTERN (NO OVERRIDE)
    # =========================

    critical_pattern = 0.0

    if "credentials" in all_signals:
        critical_pattern += 0.20
    if "urgency" in all_signals:
        critical_pattern += 0.20
    if "brand_impersonation" in all_signals:
        critical_pattern += 0.20

    critical_pattern = clamp(critical_pattern)


    # =========================
    # FINAL SCORE (CALIBRADO REAL)
    # =========================

    raw_risk = (
        ml_norm * 0.30 +
        url_norm * 0.20 +
        rule_score * 0.15 +
        attack_chain_score * 0.10 +
        phishing_confidence * 0.15 +
        critical_pattern * 0.10
    )

    raw_risk = min(1.0, raw_risk * 1.15)

    score = int(clamp(raw_risk) ** 0.7 * 100)


    # =========================
    # BINNING ESTABLE
    # =========================

    RISK_HISTORY.append(score)

    level = percentile_bin(score, RISK_HISTORY)
    ui = UI_MAP[level]


    # =========================
    # OUTPUT
    # =========================

    intention, techniques = build_text_analysis(all_signals)
    domain, url_problem = build_url_analysis(main_domain, all_signals)

    return {
        "verdict": {
            "score": score,
            "level": level,
            "ui": ui,
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

        "reasoning": {
            "summary": build_summary(score),
            "key_factors": list(all_signals)[:10],
            "why_this_score": [
                f"ML: {ml_norm:.2f}",
                f"URL: {url_norm:.2f}",
                f"Rules: {len(rules_triggered)}",
                f"Attack: {attack_chain_score:.2f}",
                f"Phishing: {phishing_confidence:.2f}",
                f"Critical pattern: {critical_pattern:.2f}"
            ]
        },

        "cadena_ataque": build_attack_chain(all_signals),
        "evidencias": build_evidence(all_signals),
        "signals": list(all_signals)
    }

