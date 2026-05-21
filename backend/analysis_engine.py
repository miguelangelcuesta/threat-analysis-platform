import re
from datetime import datetime, date

from urllib.parse import urlparse
from sentence_transformers import SentenceTransformer, util

# =========================
# CONFIG
# =========================

SIMILARITY_THRESHOLD = 0.55
_model = None
_model_lock = None


def get_model():
    """Carga perezosa del modelo y lo reutiliza en producción.

    Nota: en producción el modelo debe cargarse una sola vez.
    """
    global _model
    if _model is None:
        _model = SentenceTransformer("all-MiniLM-L6-v2")
    return _model


# =========================
# INTENTS (SEÑALES SEMÁNTICAS)
# =========================

INTENTS = {
    "impersonation": "paypal bank login verify account support",
    "credentials": "password login credit card verification code",
    "threats": "account blocked urgent legal action immediate",
    "urgency": "immediately urgent now last warning",
    "reward": "you won prize lottery gift free",
    "suspicious_link": "click link verify secure login access"
}

WEIGHTS = {
    "impersonation": 30,
    "credentials": 35,
    "threats": 25,
    "urgency": 15,
    "reward": 10,
    "suspicious_link": 25
}


# =========================
# MARCAS (CONTROLADO Y ESCALABLE)
# =========================

KNOWN_BRANDS = {
    "paypal": ["paypal.com"],
    "google": ["google.com"],
    "amazon": ["amazon.com", "amazon.es"],
    "apple": ["apple.com"],
    "microsoft": ["microsoft.com"],
    "bank": []  # genérico, se evalúa distinto
}


def is_brand_impersonation(domain):
    for brand, legit_domains in KNOWN_BRANDS.items():
        if brand in domain:
            if legit_domains:
                if not any(domain.endswith(d) for d in legit_domains):
                    return True
            else:
                # caso "bank" → solo si parece falso
                if not domain.endswith(".com") and not domain.endswith(".es"):
                    return True
    return False


# =========================
# URL HELPERS
# =========================

def extract_urls(text):
    return re.findall(r'(https?://[^\s]+)', text or "")

def extract_domain(url):
    try:
        return urlparse(url).netloc.replace("www.", "").lower()
    except:
        return ""


# =========================
# DOMAIN RISK (MEJORADO)
# =========================

def is_legit_domain(domain):
    for legit_domains in KNOWN_BRANDS.values():
        for legit in legit_domains:
            if domain.endswith(legit):
                return True
    return False


def domain_risk(domain):
    score = 0
    signals = []

    if not domain:
        return 0, []

    # ✔ suplantación real
    if is_brand_impersonation(domain):
        score += 45
        signals.append("brand_impersonation")

    # ✔ keywords sospechosas SOLO si no es dominio legítimo
    suspicious_words = ["login", "secure", "verify", "account"]

    if any(word in domain for word in suspicious_words):
        if not is_legit_domain(domain):
            score += 25
            signals.append("phishing_keywords")

    # ✔ dominios raros
    if len(domain) > 30:
        score += 10
        signals.append("long_domain")

    return score, signals



# =========================
# WHOIS (CORREGIDO)
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
            # Normaliza creation_date si viene como date en lugar de datetime
            if isinstance(creation, date) and not isinstance(creation, datetime):
                creation = datetime.combine(creation, datetime.min.time())

            age_days = (datetime.now() - creation).days

            if age_days < 30:
                score += 30
                signals.append("very_new_domain")
            elif age_days < 180:
                score += 10
                signals.append("recent_domain")


    except:
        # ✔ NO penalizar fallo técnico
        pass

    return score, signals


# =========================
# NORMALIZACIÓN
# =========================

def clamp(n, min_v=0, max_v=100):
    return max(min_v, min(n, max_v))


# =========================
# SUMMARY
# =========================

def build_summary(score, risk_level):
    if risk_level == "danger":
        return {
            "verdict": "Alto riesgo de fraude detectado",
            "reason": "El contenido muestra patrones claros de phishing o suplantación"
        }

    if risk_level == "suspicious":
        return {
            "verdict": "Actividad sospechosa detectada",
            "reason": "Existen señales que requieren precaución antes de interactuar"
        }

    return {
        "verdict": "Sin riesgo relevante",
        "reason": "No se detectan patrones maliciosos significativos"
    }


# =========================
# ENGINE PRINCIPAL
# =========================

def analyze_text(text: str):

    model = get_model()
    text = text or ""

    embedding = model.encode(text, convert_to_tensor=True)

    semantic_score = 0
    url_score = 0

    semantic_hits = []
    url_signals = []
    whois_signals = []

    urls = extract_urls(text)

    # ================= URL ANALYSIS =================
    for url in urls:
        domain = extract_domain(url)

        d_score, d_sig = domain_risk(domain)
        w_score, w_sig = whois_risk(domain)

        url_score += d_score + w_score
        url_signals.extend(d_sig)
        whois_signals.extend(w_sig)

    url_score = clamp(url_score, 0, 70)

    # ================= SEMANTIC =================
    for intent, proto in INTENTS.items():
        proto_emb = model.encode(proto, convert_to_tensor=True)
        sim = util.cos_sim(embedding, proto_emb).item()

        if sim > SIMILARITY_THRESHOLD:
            semantic_hits.append(intent)
            semantic_score += WEIGHTS[intent]

    semantic_score = clamp(semantic_score, 0, 70)


    # ================= 🧠 SCORING V2 (IMPORTANTE) =================

    semantic_norm = semantic_score / 70
    url_norm = url_score / 70
    domain_norm = len(whois_signals) / 3

    risk_vector = {
        "semantic": semantic_norm,
        "url": url_norm,
        "domain": domain_norm
    }

    WEIGHT_MODEL = {
        "semantic": 0.45,
        "url": 0.35,
        "domain": 0.20
    }

    score = (
        risk_vector["semantic"] * WEIGHT_MODEL["semantic"] +
        risk_vector["url"] * WEIGHT_MODEL["url"] +
        risk_vector["domain"] * WEIGHT_MODEL["domain"]
    )

    score = int(clamp(score * 100, 0, 100))

    # ================= RISK LEVEL =================
    if score >= 75:
        risk_level = "danger"
    elif score >= 40:
        risk_level = "suspicious"
    else:
        risk_level = "safe"

    # ================= SIGNALS HUMANOS =================
    signals_map = {
        "impersonation": "Suplantación de identidad",
        "credentials": "Posible robo de credenciales",
        "threats": "Uso de presión o amenazas",
        "urgency": "Mensaje urgente o manipulativo",
        "reward": "Posible engaño por recompensa falsa",
        "suspicious_link": "Enlaces sospechosos",
        "brand_impersonation": "Suplantación de marca",
        "phishing_keywords": "Palabras típicas de phishing",
        "very_new_domain": "Dominio recién creado",
        "recent_domain": "Dominio reciente",
        "long_domain": "Dominio inusualmente largo"
    }

    signals_raw = list(set(semantic_hits + url_signals + whois_signals))
    signals = [signals_map.get(s, s) for s in signals_raw]

    # ================= ACTION =================
    action = (
        "Bloquear inmediatamente" if risk_level == "danger"
        else "Revisar antes de interactuar" if risk_level == "suspicious"
        else "Sin acción necesaria"
    )

    return {
        "risk_level": risk_level,
        "risk_score": score,
        "summary": build_summary(score, risk_level),
        "signals": signals,
        "breakdown": {
            "message_score": semantic_score,
            "url_score": url_score,
            "whois_score": len(whois_signals)
        },
        "action": action
    }