# Anti-Scam Detector

## Security Intelligence Platform for Phishing Detection

Motor de análisis híbrido desarrollado para detectar campañas de phishing mediante la correlación de señales semánticas, infraestructura de dominio y reglas de comportamiento.

El sistema combina:

* NLP basado en Sentence Transformers.
* Análisis DNS y WHOIS.
* Detección de suplantación de identidad.
* Correlación de señales mediante reglas SOC.
* Motor explicable de toma de decisiones.
* API REST desarrollada con FastAPI.
* Interfaz web desarrollada con React.

El objetivo no es únicamente clasificar amenazas, sino proporcionar evidencia y razonamiento que permitan justificar cada decisión de seguridad.


**Producto de decisión para combatir phishing y estafas**: convierte señales de un mensaje y/o enlace en una **acción recomendada** (bloquear, revisar o monitorizar) con **explicación y evidencia**.

Diseñado para equipos que no pueden permitirse “mirar y pensar”: necesitan **responder rápido** y justificar por qué.

---

## El problema (en lenguaje de negocio)
Los intentos de phishing no se notan a simple vista: combinan redacción convincente, urgencia emocional y enlaces que aparentan legitimidad. Cuanto más tarde el triage, mayor es el impacto (fraude, credenciales comprometidas, interrupción operativa).

---

## La solución

### Arquitectura de análisis

## Tecnologías utilizadas

### Backend

* Python 3.11
* FastAPI
* Sentence Transformers
* NumPy
* Python-WHOIS

### Machine Learning / NLP

* paraphrase-multilingual-MiniLM-L12-v2
* Semantic Similarity
* Embedding-based Classification

### Security Analysis

* DNS Resolution
* WHOIS Analysis
* Domain Reputation Signals
* SOC Correlation Rules

### Frontend

* React
* JavaScript
* CSS

### Deployment

* Render
* GitHub


El motor procesa cada entrada mediante varias capas independientes:

1. **Semantic Detection Layer**

   * Sentence Transformers (paraphrase-multilingual-MiniLM-L12-v2)
   * Detección de patrones compatibles con phishing, ingeniería social y robo de credenciales.

2. **Infrastructure Analysis Layer**

   * Resolución DNS.
   * Análisis WHOIS.
   * Evaluación de antigüedad y características del dominio.

3. **SOC Correlation Layer**

   * Correlación entre señales de identidad, comportamiento e infraestructura.
   * Aplicación de reglas de detección inspiradas en procesos SOC.

4. **Risk Scoring Engine**

   * Normalización de señales.
   * Agregación de evidencias.
   * Clasificación en cinco niveles de riesgo.

5. **Explainability Layer**

   * Generación de evidencias.
   * Construcción de razonamientos explicables.
   * Recomendación de acción para el usuario o analista.

Anti-Scam Detector evalúa un input y devuelve un paquete listo para UI/operación:

- **`verdict.score` (0..100)**: nivel de riesgo cuantificado.
- **`verdict.level`**: `safe | low | medium | high | critical`.
- **`verdict.action`**: recomendación accionable.
- **Explicación**: factores dominantes + evidencia.
- **`cadena_ataque`**: resumen de los pasos típicos del intento.

---

## ¿Para quién es?
- **SOC / Ciberseguridad**: triage más rápido, priorización de alertas y explicación para auditoría.
- **Operaciones y Soporte**: detección temprana para reducir caídas antes de que ocurran.
- **Equipos de Riesgo / Compliance**: justificación reproducible de la decisión.

---

## Diferenciadores
- **Decisión con evidencia**, no solo “score”.
- **Explicable y consistente**: misma lógica para texto y enlaces.
- **Enfoque híbrido**: señales de lenguaje + señales del dominio/enlace + reglas de correlación.
- **Estabilización del binning** mediante historial para evitar saltos erráticos.

---

## Experiencia de uso (workflow)
1. El usuario/analista pega un mensaje o captura un enlace.
2. La UI muestra un **traffic light** y una **acción sugerida**.
3. El equipo ejecuta el paso recomendado.
4. El resultado incluye “**por qué**” y “**qué señales**” para mejorar el proceso y el aprendizaje.

---

## Cómo integrarlo (API)
### `POST /api/analyze`
**Body (JSON)** (campos opcionales):
- `text`: texto a evaluar
- `url`: enlace a evaluar
- `input_type`: `text` o `url` (por defecto `text`)

**Ejemplo**:
```json
{
  "text": "Verifica tu cuenta inmediatamente y accede ahora.",
  "url": null,
  "input_type": "text"
}
```

**Salida**: JSON con `verdict`, `executive_summary`, `analysis` y evidencias.

---

## Roadmap (lo que haríamos para convertirlo en versión “enterprise-ready”)
- Persistencia real de historial y calibración por dispositivo/usuario.
- Métricas de desempeño por categoría (precisión, recall, FPR) y tuning continuo.
- Ampliar cobertura de señales del dominio (patrones adicionales, infraestructura, ASN/TLD, etc.).
- Panel de analista: trending, justificación, y exportación para auditoría.

---

## Requisitos y ejecución rápida
### Backend
```bash
pip install -r requirements.txt
.venv\\Scripts\\uvicorn backend.server:app --reload --port 8000
```

### Frontend
```bash
cd frontend
npm install
npm start
```

---

## Nota de confianza
El motor es **orientativo**: no sustituye controles de seguridad ni verificación externa. Está optimizado para ayudar a equipos a tomar decisiones consistentes y rápidas.

---

## Contacto
Miguel Ángel Cuesta

