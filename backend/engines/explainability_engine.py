import random


def build_text_analysis(signals):

    introductions = [
        "Durante el análisis del contenido,",
        "Tras evaluar el texto analizado,",
        "El motor de análisis ha identificado que",
        "La evaluación del mensaje indica que",
        "Del análisis realizado se desprende que"
    ]

    social_signals = {
        "brand_impersonation",
        "credentials",
        "urgency",
        "threats",
        "reward",
        "suspicious_link"
    }

    detected = [s for s in signals if s in social_signals]

    if len(detected) >= 4:
        return (
            "Posible ingeniería social",
            f"{random.choice(introductions)} se detecta una combinación significativa de indicadores compatibles con phishing y manipulación del usuario. Este patrón suele aparecer en campañas activas de fraude digital."
        )

    if len(detected) >= 2:
        return (
            "Posible ingeniería social",
            f"{random.choice(introductions)} se han identificado varios indicadores asociados a técnicas de ingeniería social, aunque no son suficientes por sí solos para confirmar un ataque."
        )

    if len(detected) == 1:
        return (
            "Bajo nivel de riesgo",
            f"{random.choice(introductions)} se ha detectado un indicador compatible con técnicas de ingeniería social, aunque de forma aislada no resulta concluyente."
        )

    return (
        "Sin indicadores relevantes",
        f"{random.choice(introductions)} no se observan patrones claros de ingeniería social o phishing en el contenido analizado."
    )


def build_url_analysis(domain, url_signals):

    if not domain or domain == "-":
        return (
            "-",
            "No se ha detectado ninguna URL en el contenido analizado."
        )

    if "domain_unresolvable" in url_signals:
        return (
            domain,
            "El dominio no resuelve en DNS, lo que indica que no existe o no está activo públicamente. Este patrón es frecuente en dominios utilizados en campañas de phishing o infraestructuras desechables."
        )

    if "brand_impersonation" in url_signals:
        return (
            domain,
            "Se detectan indicios de posible suplantación de identidad mediante el uso de marcas reconocidas o patrones similares a dominios legítimos."
        )

    medium = {"recent_domain", "long_domain", "phishing_keywords"}

    if any(s in url_signals for s in medium):
        return (
            domain,
            "El dominio presenta características estructurales o temporales que requieren verificación adicional antes de considerarlo confiable."
        )

    return (
        domain,
        "El dominio responde correctamente y no se observan anomalías técnicas relevantes en el análisis básico. Esto no implica legitimidad, solo ausencia de señales de riesgo."
    )


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
    if "domain_unresolvable" in signals:
        evidence.append("Dominio no resoluble en DNS")

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