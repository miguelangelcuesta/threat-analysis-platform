

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
    "urgency": 35,
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


THRESHOLDS = {
    "impersonation": 0.40,
    "credentials": 0.30,
    "threats": 0.35,
    "urgency": 0.45,
    "reward": 0.50,
    "suspicious_link": 0.30,
    "benign_security": 0.45
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


def get_embeddings(model, intent_cache):
    if intent_cache is None:
        intent_cache = {
            k: model.encode(v, convert_to_tensor=True)
            for k, v in INTENTS.items()
        }

    return intent_cache


def analyze_semantics(text, embedding, embeddings):
    from sentence_transformers import util
    
    semantic_hits = []
    ml_score = 0
    benign_score = 0
    similarity_debug = {}

    text_lower = text.lower()

    for intent, proto in embeddings.items():
        sim = util.cos_sim(embedding, proto).item()
        sim = max(0, sim)

        similarity_debug[intent] = round(sim, 3)

        if sim > THRESHOLDS[intent]:
            semantic_hits.append(SIGNAL_MAP[intent])

        # HARD RULES (SOC OVERRIDE)
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

    return semantic_hits, ml_score, benign_score, similarity_debug