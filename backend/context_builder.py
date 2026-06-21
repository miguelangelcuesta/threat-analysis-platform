"""
Context Builder

Convierte el resultado técnico del análisis en un
contexto estructurado que pueda consumir un LLM.

No genera texto para el usuario.
No calcula riesgo.
Únicamente organiza información.
"""


def build_context(
    text,
    score,
    level,
    domain,
    signals,
    ml_score,
    url_score,
    rules
):

    return {

        "input": {
            "text": text,
            "domain": domain
        },

        "risk": {
            "score": score,
            "level": level
        },

        "engine": {
            "ml_score": round(ml_score, 2),
            "url_score": round(url_score, 2),
            "rules_triggered": rules
        },

        "signals": sorted(list(signals))

    }