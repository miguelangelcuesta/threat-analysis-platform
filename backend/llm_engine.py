"""
LLM Engine

Actualmente utiliza un generador interno de explicaciones.

En futuras versiones podrá conectarse a:
- OpenAI
- - Ollama
- Llama
- Mistral

sin modificar el resto del proyecto.
"""

import random


INTRO = {

    "safe":
        "Tras evaluar el contenido y las evidencias disponibles, el motor no identifica indicios relevantes de actividad maliciosa.",

    "low":
        "El análisis detecta algunos elementos que merecen atención, aunque por sí solos no permiten considerar el contenido como claramente fraudulento.",

    "medium":
        "El contenido presenta varios indicadores compatibles con técnicas utilizadas en campañas de ingeniería social.",

    "high":
        "La combinación de evidencias observadas resulta consistente con patrones habituales de fraude digital y phishing.",

    "critical":
        "Las evidencias identificadas muestran una elevada compatibilidad con campañas maliciosas orientadas a engañar al usuario."
}


CONCLUSION = {

    "safe":
        "No se han identificado evidencias suficientes para considerar el contenido como una amenaza relevante. Aunque siempre es recomendable mantener una actitud prudente, el análisis no detecta indicadores significativos de fraude.",

    "low":
        "Se han identificado algunos indicadores compatibles con técnicas de ingeniería social. La evidencia disponible es limitada, por lo que el riesgo se considera bajo, aunque conviene actuar con precaución.",

    "medium":
        "El contenido presenta varias características asociadas a campañas de fraude. Aunque el análisis no permite confirmar una amenaza elevada, existen suficientes indicios para recomendar una verificación antes de continuar.",

    "high":
        "La combinación de señales detectadas incrementa de forma significativa la probabilidad de que el contenido forme parte de una campaña de ingeniería social o phishing. Se recomienda no interactuar hasta verificar su legitimidad.",

    "critical":
        "El análisis identifica una combinación de indicadores altamente compatible con intentos de phishing o robo de credenciales. La evidencia disponible aconseja tratar el contenido como potencialmente malicioso y evitar cualquier interacción."
}


def generate_reasoning(context):

    level = context["risk"]["level"]
    signals = context.get("signals", [])
    engine = context.get("engine", {})

    intro = INTRO[level]
    
    if "domain_unresolvable" in signals:

        intro = (
        "El análisis ha detectado anomalías relevantes en la infraestructura asociada al enlace analizado."
    )

        conclusion = (
        "El dominio no responde correctamente en DNS o no existe públicamente. "
        "Este comportamiento incrementa significativamente el riesgo y aconseja "
        "evitar cualquier interacción hasta verificar su legitimidad."
    )

    else:
        conclusion = CONCLUSION[level]

    variation = random.randint(0, 2)

    details = [
        "El análisis se basa en la correlación de señales detectadas en el contenido.",
        "El sistema evalúa patrones combinados de comportamiento y estructura.",
        "La clasificación se genera a partir de múltiples indicadores agregados."
    ]

    if len(signals) == 0:

        detail = "El contenido analizado no presenta elementos especialmente relevantes desde el punto de vista del motor de detección."

    elif len(signals) == 1:

        detail = "Se ha identificado un único indicador de riesgo. De forma aislada no resulta concluyente, aunque se ha tenido en cuenta para la evaluación."

    elif len(signals) <= 3:

        detail = details[variation % len(details)] + " El número de señales es bajo."

    else:

        detail = details[variation % len(details)] + " Alta densidad de señales correlacionadas."


    why = []

    # =========================
    # BASE REASONING
    # =========================

    if len(signals) == 0:

        why.append(
            "El motor no ha identificado evidencias suficientes para incrementar el nivel de riesgo."
        )

    else:

        why.append(
            "La puntuación se basa en la combinación y correlación de los indicadores detectados durante el análisis."
        )

        if len(signals) <= 2:

            why.append(
                "El número de evidencias es reducido, por lo que su impacto sobre la puntuación final es limitado."
            )

        elif len(signals) <= 4:

            why.append(
                "La presencia de varios indicadores compatibles con ingeniería social incrementa el nivel de riesgo estimado."
            )

        else:

            why.append(
                "La acumulación de múltiples evidencias coherentes entre sí aumenta significativamente el riesgo calculado."
            )

        if level in ["high", "critical"]:

            why.append(
                "La correlación entre las señales detectadas es consistente con patrones habituales de campañas de phishing."
            )

    # =========================
    # SIGNAL-SPECIFIC EXPLANATIONS
    # =========================

    if "brand_impersonation" in signals:
        why.append("Se detectan patrones compatibles con suplantación de identidad.")

    if "credentials" in signals:
        why.append("El contenido solicita información sensible o credenciales.")

    if "urgency" in signals:
        why.append("Se utilizan mecanismos de presión temporal para acelerar la decisión del usuario.")

    if "threats" in signals:
        why.append("Existen elementos intimidatorios destinados a forzar interacción.")

    if "reward" in signals:
        why.append("Se utilizan incentivos como mecanismo de persuasión.")

    if "suspicious_link" in signals:
        why.append("Se observa un enlace que requiere verificación adicional.")

    if "very_new_domain" in signals:
        why.append("Dominio de creación reciente detectado.")

    if len(why) == 0:
        why.append("No se identifican evidencias técnicas suficientes para considerar el contenido como amenaza.")

    summary = intro + " " + conclusion

    return {
        "executive_summary": summary,
        "text": summary,
        "why_this_score": why
    }