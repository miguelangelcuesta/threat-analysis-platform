from collections import deque

from sentence_transformers import SentenceTransformer, util

from backend.soc.soc_rules import evaluate_rules
from backend.reasoning_engine import build_reasoning
from backend.context_builder import build_context
from backend.llm_engine import generate_reasoning

from backend.engines.url_utils import extract_urls, extract_domain, domain_resolves
from backend.engines.scoring_utils import clamp, percentile_bin
from backend.engines.explainability_engine import (
    build_text_analysis,
    build_url_analysis,
    build_attack_chain,
    build_evidence,
    build_summary
)
from backend.engines.infrastructure_engine import (
    domain_risk,
    whois_risk,
    trust_score,
    confidence_score
)

# =========================
# CONFIG
# =========================

_model = None
INTENT_EMB = None

SIM_THRESHOLD = 0.30

MAX_URL_SCORE = 100
MAX_ML_SCORE = 120

#  historial para calibración
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

verifique su cuenta
confirme su cuenta
actualice sus datos
actualice la información
validar identidad
confirmar identidad
confirmar acceso
datos de acceso
credenciales de acceso
""",

    "threats": """
cuenta suspendida bloqueada desactivada restringida acceso denegado
alerta de seguridad advertencia final eliminación permanente cuenta comprometida
""",
    "urgency": """
urgente inmediatamente ahora acción requerida tiempo limitado última advertencia
actúa ya responde hoy en minutos respuesta inmediata

verifique inmediatamente
verifica ahora
actúe inmediatamente
acción urgente requerida
requiere atención inmediata
debe actuar ahora
evite la suspensión
último aviso
última oportunidad
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
# UI MAP (SINGLE SOURCE OF TRUTH)
# =========================

UI_MAP = {
    "safe": {
        "color": "#22c55e",
        "bg": "#071a12",
        "label": "SIN INDICADORES RELEVANTES"
    },
    "low": {
        "color": "#38bdf8",
        "bg": "#0a1f2a",
        "label": "RIESGO BAJO"
    },
    "medium": {
        "color": "#facc15",
        "bg": "#2a240a",
        "label": "PRECAUCION"
    },
    "high": {
        "color": "#fb923c",
        "bg": "#2a1408",
        "label": "RIESGO ALTO"
    },
    "critical": {
        "color": "#ef4444",
        "bg": "#2a0707",
        "label": "RIESGO CRÍTICO"
    }
}


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
        trust, trust_sig = trust_score(domain)
        url_signals.extend(trust_sig)

        url_score += d_score + w_score
        url_signals.extend(d_sig)
        whois_signals.extend(w_sig)

    url_norm = clamp(url_score / MAX_URL_SCORE) if urls else 0.0
    
    # =========================
    # DNS FINAL CHECK (UN SOLO PUNTO DE VERDAD)
    # =========================

    dns_fail = False
    dns_signal = []

    for url in urls:
        domain = extract_domain(url)

        if domain and not domain_resolves(domain):
            dns_fail = True
            dns_signal.append("domain_non_existent")

    if dns_fail:
        url_norm = min(1.0, url_norm + 0.5)
        url_signals.append("domain_unresolvable")

    # =========================
    # ML SCORE
    # =========================

    emb = get_embeddings(model)

    ml_score = 0
    benign_score = 0

    for intent, proto in emb.items():
        sim = util.cos_sim(embedding, proto).item()
        sim = max(0, sim)
        
        print(intent, round(sim, 3))

        thresholds = {
            "impersonation": 0.40,
            "credentials": 0.30,
            "threats": 0.35,
            "urgency": 0.45,
            "reward": 0.50,
            "suspicious_link": 0.30,
            "benign_security": 0.45
        }

        if sim > thresholds[intent]:
            semantic_hits.append(SIGNAL_MAP[intent])
            
        # HARD RULES (SOC OVERRIDE)
    text_lower = text.lower()

    if intent == "urgency":
        if any(x in text_lower for x in [
            "verifique inmediatamente",
            "acción inmediata",
            "último aviso",
            "actúe ahora",
            "urgente"
        ]):
            semantic_hits.append("urgency")

    if intent == "credentials":
        if any(x in text_lower for x in [
            "verifique su cuenta",
            "confirmar identidad",
            "introduzca su contraseña",
            "paypal",
            "login"
        ]):
            semantic_hits.append("credentials")

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

    all_signals = set(
    semantic_hits +
    url_signals +
    whois_signals
)
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

    conf_score, conf_signals = confidence_score(
    semantic_hits,
    url_signals,
    whois_signals,
    rules_triggered
)
    # =========================
# ATTACK PATTERN SCORE
# =========================

    attack_chain_score = 0.10 if (identity_hits >= 1 and behavior_hits >= 2) else 0.0

    # =========================
    # CRITICAL LAYER (UNIFICADO)
    # =========================

    critical_layer = 0.0

    if "brand_impersonation" in all_signals:
        critical_layer += 0.25

    if "credentials" in all_signals:
        critical_layer += 0.25

    if "urgency" in all_signals:
        critical_layer += 0.15

    if "phishing_keywords" in all_signals:
        critical_layer += 0.10

    if "very_new_domain" in all_signals:
        critical_layer += 0.10

    critical_layer = clamp(critical_layer)

    # =========================
    # FINAL SCORE (CALIBRADO REAL)
    # =========================

    raw_risk = (
    url_norm * 0.30 +
    rule_score * 0.20 +
    critical_layer * 0.35 +
    ml_norm * 0.15
)
    # =========================
# SOC CRITICAL OVERRIDE LAYER
# =========================

    if "brand_impersonation" in all_signals:
        raw_risk += 0.10

    if "credentials" in all_signals:
        raw_risk += 0.15

    if "suspicious_link" in all_signals:
        raw_risk += 0.10

    if "threats" in all_signals:
        raw_risk += 0.10

    # CAP FINAL
    raw_risk = min(1.0, raw_risk)

# OVERRIDE SOC REAL
    if dns_fail:
        raw_risk = max(raw_risk, 0.65)

    # =========================
    # FIX INCERTIDUMBRE
    # =========================

    confidence_adjust = 0.0

    if urls:
        confidence_adjust += 0.05

    if len(semantic_hits) == 0:
        confidence_adjust += 0.05

    if len(whois_signals) == 0:
        confidence_adjust += 0.05

    raw_risk = clamp(raw_risk + confidence_adjust)

    # =========================
    # SCORE FINAL
    # =========================

    score = int(raw_risk * 100)
    score = max(0, min(score, 100))

    # =========================
    # BINNING ESTABLE
    # =========================

    RISK_HISTORY.append(score)

    level = percentile_bin(score, RISK_HISTORY)
    ui = UI_MAP[level]
    
    # =========================
    # NORMALIZACIÓN PARA LLM
    # =========================

    level_map = {
        "green": "safe",
        "blue": "low",
        "yellow": "medium",
        "orange": "high",
        "red": "critical"
    }

    level = level_map.get(level, level)

    # =========================
    # CONFIDENCE (UNA SOLA VEZ)
    # =========================

    confidence, confidence_signals = confidence_score(
        semantic_hits,
        url_signals,
        whois_signals,
        rules_triggered
    )

    # =========================
    # CONTEXT (LLM)
    # =========================

    context = build_context(
        text=text,
        score=score,
        level=level,
        domain=main_domain,
        signals=all_signals,
        ml_score=ml_norm,
        url_score=url_norm,
        rules=len(rules_triggered)
    )
    
    llm_context = {
    "risk": {
        "level": level,
        "score": score
    },
    "signals": list(all_signals),
    "engine": {
        "ml_score": ml_norm,
        "url_score": url_norm,
        "rules": len(rules_triggered)
    }
}
    llm_reasoning = generate_reasoning(llm_context)

    # =========================
    # OUTPUT ANALYSIS BLOCKS
    # =========================

    intention, analysis = build_text_analysis(all_signals)

    domain, url_problem = build_url_analysis(main_domain, url_signals)

    attack_chain = build_attack_chain(list(all_signals))
    evidence = build_evidence(list(all_signals))

    # =========================
    # REASONING (LLM)
    # =========================

    reasoning = build_reasoning(
        score=score,
        level=level,
        signals=all_signals,
        analysis=context,
    )

    reasoning["why_this_score"] = llm_reasoning["why_this_score"]

    print("SIGNALS:", all_signals)
    print("SCORE:", score)
    
    # =========================
    # RETURN FINAL RESPONSE
    # =========================

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

        "executive_summary": llm_reasoning["executive_summary"],

        "analysis": {
            "text": {
                "intention": intention,
                "analysis": analysis
            },
            "url": {
                "dominio": domain,
                "problema": url_problem
            }
        },

        "reasoning": {
            "summary": build_summary(score),
            "why_this_score": reasoning["why_this_score"]
        },

        "cadena_ataque": attack_chain,
        "evidencias": evidence,
        "signals": list(all_signals)
    }