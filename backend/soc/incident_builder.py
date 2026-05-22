from datetime import datetime
import uuid


def build_incident(
    text: str,
    risk_bin: str,
    risk_score: int,
    signals: list,
    soc: dict,
    mitre: dict
):
    """
    Convierte el output del analysis_engine en un incidente estructurado SOC-like
    """

    severity_map = {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "low": "low",
        "safe": "info"
    }

    incident = {
        "id": str(uuid.uuid4()),
        "timestamp": datetime.utcnow().isoformat() + "Z",

        "classification": {
            "type": "phishing_analysis",
            "severity": severity_map.get(risk_bin, "info")
        },

        "risk": {
            "score": risk_score,
            "level": risk_bin
        },

        "evidence": {
            "raw_text": text,
            "signals": signals,
            "soc": soc
        },

        "mitre": {
            "tactics": mitre.get("tactics", []),
            "techniques": mitre.get("techniques", [])
        },

        "narrative": generate_narrative(risk_bin, soc, mitre)
    }

    return incident


def generate_narrative(risk_bin, soc, mitre):
    """
    Explicación humana tipo SOC analyst
    """

    if risk_bin == "critical":
        return "Alta probabilidad de phishing con múltiples señales correladas y posible cadena de ataque activa."

    if risk_bin == "high":
        return "Actividad sospechosa con patrones de ingeniería social y señales relevantes de ataque."

    if risk_bin == "medium":
        return "Se detectan indicios parciales de comportamiento sospechoso."

    if risk_bin == "low":
        return "Señales débiles sin suficiente correlación para confirmar amenaza."

    return "Sin evidencia significativa de actividad maliciosa."