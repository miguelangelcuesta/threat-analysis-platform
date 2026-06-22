import os 
from collections import deque

from sentence_transformers import SentenceTransformer

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
from backend.engines.semantic_engine import (
    identity_signals,
    behavior_signals,
    infra_signals,
    get_embeddings,
    analyze_semantics
)

# =========================
# CONFIG
# =========================

_model = None
INTENT_EMB = None


MAX_URL_SCORE = 100
MAX_ML_SCORE = 120
USE_ML = os.getenv("USE_ML", "true").lower() == "true"

#  historial para calibración
RISK_HISTORY = deque(maxlen=500)

# =========================
# MODEL
# =========================

def get_model():
    global _model

    if not USE_ML:
        return None

    if _model is None:
        _model = SentenceTransformer("sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2")

    return _model


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
# MAIN ENGINE
# =========================

def analyze_text(text: str):
    
    global INTENT_EMB
    
    model = get_model()
    text = text or ""

    embedding = None

    if USE_ML and model is not None:
        embedding = model.encode(text, convert_to_tensor=True)
        
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
    
    for url in urls:
        domain = extract_domain(url)

        if domain and not domain_resolves(domain):
            dns_fail = True
            

    if dns_fail:
        url_norm = min(1.0, url_norm + 0.5)
        url_signals.append("domain_unresolvable")

    # =========================
    # ML SCORE
    # =========================

    if USE_ML and model is not None and embedding is not None:
        emb = get_embeddings(model, INTENT_EMB)

        semantic_hits, ml_score, benign_score, similarity_debug = analyze_semantics(
            text=text,
            embedding=embedding,
            embeddings=emb
        )

        INTENT_EMB = emb

        ml_norm = ml_score / MAX_ML_SCORE
        ml_norm = ml_norm - (benign_score / MAX_ML_SCORE)
        ml_norm = clamp(ml_norm)

    else:
        semantic_hits = []
        ml_score = 0
        benign_score = 0
        similarity_debug = {}
        ml_norm = 0.0

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