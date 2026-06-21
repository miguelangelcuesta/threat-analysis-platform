
"""
Reasoning Engine

Genera una explicación estructurada del análisis.
No calcula el riesgo, únicamente lo interpreta.

En futuras versiones este módulo será enriquecido
por un LLM local.
"""


# ============================================
# HUMAN READABLE SIGNALS
# ============================================

SIGNAL_INFO = {

    "brand_impersonation": {
        "title": "Suplantación de identidad",
        "description": "Se intenta aparentar una entidad legítima para generar confianza."
    },

    "credentials": {
        "title": "Solicitud de credenciales",
        "description": "El contenido intenta obtener información sensible del usuario."
    },

    "urgency": {
        "title": "Presión temporal",
        "description": "Se utiliza urgencia para reducir el tiempo de reflexión."
    },

    "threats": {
        "title": "Mensajes intimidatorios",
        "description": "Se emplean amenazas o consecuencias negativas para presionar."
    },

    "reward": {
        "title": "Promesa de recompensa",
        "description": "Se utilizan incentivos para aumentar la probabilidad de interacción."
    },

    "suspicious_link": {
        "title": "Enlace sospechoso",
        "description": "Se detecta un enlace compatible con patrones habituales de phishing."
    },

    "very_new_domain": {
        "title": "Dominio reciente",
        "description": "El dominio presenta una antigüedad reducida, aumentando la incertidumbre."
    },

    "recent_domain": {
        "title": "Dominio de creación reciente",
        "description": "La infraestructura es relativamente nueva respecto a dominios consolidados."
    },

    "long_domain": {
        "title": "Dominio inusualmente largo",
        "description": "La longitud del dominio coincide con patrones utilizados para confundir al usuario."
    }

}

# ============================================
# BUILD CONTEXT
# ============================================

def build_context(signals):

    context = []

    for signal in signals:

        info = SIGNAL_INFO.get(signal)

        if info:

            context.append({
                "signal": signal,
                "title": info["title"],
                "description": info["description"]
            })


    return context

def build_reasoning_context(
    score,
    level,
    action,
    signals
):

    context = build_context(signals)

    return {

        "score": score,

        "level": level,

        "action": action,

        "signals": list(signals),

        "context": context,

        "executive_summary":
            executive_summary(score, context),

        "attack_story":
            attack_story(signals),

        "dominant_factors":
            dominant_factors(signals)

    }


# ============================================
# EXECUTIVE SUMMARY
# ============================================

def executive_summary(score, context):

    if not context:
        return (
            "No se han identificado indicadores relevantes "
            "compatibles con campañas habituales de phishing "
            "o ingeniería social."
        )

    factors = [c["title"].lower() for c in context]

    if len(factors) == 1:
        intro = f"Se detecta {factors[0]}."
    elif len(factors) == 2:
        intro = f"Se detectan {factors[0]} y {factors[1]}."
    else:
        intro = (
            "Se detecta una combinación de "
            + ", ".join(factors[:-1])
            + f" y {factors[-1]}."
        )

    if score >= 80:
        conclusion = (
            "La combinación de estas señales es altamente "
            "compatible con campañas modernas de phishing y "
            "justifica una respuesta inmediata."
        )

    elif score >= 60:
        conclusion = (
            "Las evidencias observadas incrementan de forma "
            "significativa la probabilidad de fraude y "
            "requieren una revisión prioritaria."
        )

    elif score >= 40:
        conclusion = (
            "Se observan indicadores compatibles con técnicas "
            "de ingeniería social, aunque la evidencia no es "
            "concluyente."
        )

    else:
        conclusion = (
            "Las señales detectadas son limitadas y deben "
            "interpretarse junto con otras evidencias."
        )

    return intro + " " + conclusion



# ============================================
# ATTACK STORY
# ============================================

def attack_story(signals):

    story = []

    # Fase 1
    if "brand_impersonation" in signals:
        story.append(
            "El ataque comienza intentando generar confianza mediante una identidad aparentemente legítima."
        )

    # Fase 2
    if "urgency" in signals:
        story.append(
            "Posteriormente se introduce presión temporal para reducir la capacidad de análisis de la víctima."
        )

    if "threats" in signals:
        story.append(
            "El mensaje incorpora consecuencias negativas con el objetivo de aumentar la sensación de riesgo."
        )

    # Fase 3
    if "reward" in signals:
        story.append(
            "También se utilizan incentivos o recompensas como mecanismo para incrementar la interacción."
        )

    # Fase 4
    if "credentials" in signals:
        story.append(
            "El objetivo aparente es obtener información sensible o credenciales del usuario."
        )

    # Fase 5
    if "suspicious_link" in signals:
        story.append(
            "La acción propuesta dirige al usuario hacia un enlace cuya legitimidad requiere verificación."
        )

    # Infraestructura
    if "very_new_domain" in signals:
        story.append(
            "Además, la infraestructura utilizada presenta características compatibles con dominios de creación reciente."
        )

    if "recent_domain" in signals:
        story.append(
            "La antigüedad limitada del dominio incrementa la incertidumbre sobre su legitimidad."
        )

    if "long_domain" in signals:
        story.append(
            "La estructura del dominio muestra patrones utilizados frecuentemente para generar confusión visual."
        )

    if not story:
        story.append(
            "No se ha podido reconstruir una cadena de ataque consistente a partir de las señales disponibles."
        )

    return " ".join(story)




# ============================================
# DOMINANT FACTORS
# ============================================

def dominant_factors(signals):

    factors = []

    mapping = {
        "brand_impersonation":
            "Se detectan indicios de posible suplantación de identidad.",

        "credentials":
            "Existen elementos orientados a obtener credenciales o información sensible.",

        "urgency":
            "Se emplean mecanismos de presión temporal para acelerar la decisión del usuario.",

        "threats":
            "El mensaje incorpora consecuencias negativas para aumentar la probabilidad de interacción.",

        "reward":
            "Se utilizan incentivos o recompensas como elemento de persuasión.",

        "suspicious_link":
            "El contenido invita a acceder a un enlace que requiere validación adicional.",

        "very_new_domain":
            "El dominio presenta una antigüedad muy reducida, aumentando el nivel de incertidumbre.",

        "recent_domain":
            "La infraestructura utilizada es relativamente reciente.",

        "long_domain":
            "La estructura del dominio resulta inusualmente larga o compleja."
    }

    for signal in signals:
        if signal in mapping:
            factors.append(mapping[signal])

    if not factors:
        factors.append(
            "No se identifican factores de riesgo relevantes en el análisis realizado."
        )

    return factors


# ============================================
# CONFIDENCE
# ============================================

def confidence(score, signals):

    n = len(signals)

    if score >= 80:

        return {
            "level": "Alta",
            "reason":
                "La evaluación se apoya en múltiples indicadores consistentes compatibles con campañas habituales de phishing."
        }

    if score >= 60:

        return {
            "level": "Media-Alta",
            "reason":
                "Existen varias evidencias independientes que incrementan significativamente la confianza del análisis."
        }

    if score >= 40:

        return {
            "level": "Media",
            "reason":
                "Se observan indicadores relevantes, aunque algunos requieren contexto adicional para una conclusión firme."
        }

    if n >= 2:

        return {
            "level": "Limitada",
            "reason":
                "El análisis identifica algunas señales, pero la evidencia disponible es reducida."
        }

    return {
        "level": "Baja",
        "reason":
            "No existen suficientes indicadores para emitir una conclusión con alta confianza."
    }

# ============================================
# RECOMMENDATION
# ============================================

def recommendation(score):

    if score >= 80:

        return [

            "Bloquear inmediatamente la interacción.",

            "No introducir credenciales ni información personal.",

            "Verificar la identidad del remitente mediante un canal alternativo.",

            "Escalar el incidente al equipo de seguridad."

        ]

    elif score >= 60:

        return [

            "No interactuar con el contenido hasta completar la revisión.",

            "Verificar el dominio y el remitente.",

            "Analizar el enlace en un entorno controlado."

        ]

    elif score >= 40:

        return [

            "Revisar cuidadosamente el contexto antes de actuar.",

            "Confirmar la legitimidad mediante fuentes oficiales."

        ]

    elif score >= 20:

        return [

            "Mantener precaución y verificar la información disponible."

        ]

    return [

        "No se requieren acciones adicionales con la información analizada."

    ]


# ============================================
# MAIN
# ============================================

def build_reasoning(
    score,
    level,
    signals,
    analysis=None
):
    context = build_context(signals)

    return {

        "executive_summary":
            executive_summary(score, context),

        "attack_story":
            attack_story(signals),

        "dominant_factors":
            dominant_factors(signals),

        "confidence":
            confidence(score, signals),

        "recommendation":
            recommendation(score),
            

        "context":
            context,   

        "reasoning_version":
            "1.0",
            

        "raw_signals":
            list(signals)

        

    }

