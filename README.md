# 🛡️ Anti-Scam Detector

Sistema de **detección de estafas / phishing** para analizar **texto** y **URLs** con una aproximación híbrida:
- **NLP semántico** (SentenceTransformer) para reconocer intenciones tipo phishing/urgencia/robo de credenciales.
- **Heurísticas de dominio** (suplantación por marcas conocidas, longitudes, keywords típicas).
- **Señales opcionales de reputación** mediante **WHOIS** (si está disponible en el entorno).

> ⚠️ Importante: esta herramienta ofrece una **evaluación orientativa** basada en patrones. No garantiza la legitimidad del mensaje o dominio.

---

## ✨ Funcionalidades

- Entrada por **tipo de contenido**:
  - Mensajes (texto)
  - Enlaces (URL)
- Clasificación en 3/4 niveles:
  - **safe** (bajo riesgo)
  - **suspicious** (riesgo moderado)
  - **danger** (alto riesgo)
- Salida **explicativa**:
  - `risk_score`
  - `summary` (veredicto + razonamiento)
  - `signals` (señales detectadas)
  - `breakdown` (contribuciones por motor semántico / URL / dominio)
  - `action` (recomendación de alto nivel)

---

## 🧩 Arquitectura

```
anti-scam-detector/
├─ backend/
│  ├─ server.py               # API FastAPI
│  └─ analysis_engine.py     # Motor de análisis (NLP + heurísticas)
└─ frontend/
   ├─ src/
   │  ├─ pages/DashboardPage.js   # UI principal (entrada + reporte)
   │  ├─ api/client.js            # cliente axios + header X-Device-ID
   │  └─ utils/device.js         # persistencia de device_id en localStorage
```

### Backend (FastAPI)
- Endpoint principal: `POST /api/analyze`
- Endpoints auxiliares (mock para UI):
  - `GET /api/history`
  - `GET /api/stats`

### Frontend (React)
- Interfaz para pegar un texto o una URL.
- Visualización del nivel de riesgo mediante un indicador (“traffic light”).

---

## 🔁 Contrato de API

### `POST /api/analyze`

**Request** (JSON):

- La API espera un diccionario con `text` y/o `url`.
- El frontend manda ambos campos según el modo:

```json
{
  "text": "..." ,
  "url": null,
  "input_type": "text"
}
```

o

```json
{
  "text": null,
  "url": "https://ejemplo.com",
  "input_type": "url"
}
```

**Nota**: en `backend/server.py`, el backend usa:
- `content = data.get("text") or data.get("url") or ""`

**Headers opcionales**:
- `X-Device-ID`: si no se envía, se usa `anonymous`.

**Response** (JSON):

```json
{
  "id": "YYYYMMDDHHMMSS",
  "risk_level": "safe|suspicious|danger",
  "risk_score": 0,
  "summary": {
    "verdict": "...",
    "reason": "..."
  },
  "signals": ["..."],
  "breakdown": {
    "message_score": 0,
    "url_score": 0,
    "whois_score": 0
  },
  "action": "..."
}
```

**Errores**:
- `400` con `detail: "Empty input"` si el contenido final resulta vacío.

---

## 🧠 Cómo funciona el motor (high-level)

### 1) Detección semántica (NLP)
- Se crea un embedding del texto de entrada.
- Se compara contra “prototipos” de intenciones (`INTENTS`) usando similitud coseno.
- Si la similitud supera `SIMILARITY_THRESHOLD`, se suma el peso asociado.

**Componentes** (ejemplos de intenciones):
- `credentials`
- `impersonation`
- `threats`
- `urgency`
- `reward`
- `suspicious_link`

### 2) Análisis de URLs / dominio
Para cada URL detectada en el texto:
- Se extrae el dominio (con `urlparse`).
- Se calcula `domain_risk(domain)` con:
  - suplantación por marcas conocidas (`brand_impersonation`)
  - keywords típicas de phishing dentro del dominio
  - dominios anormalmente largos
- Se calcula `whois_risk(domain)`:
  - edad del dominio (muy nuevo → más riesgo)
  - si WHOIS falla: **no penaliza** (se captura excepción y se continúa)

El resultado se “clampa” a un rango razonable para evitar que una sola URL domine.

### 3) Fusión y scoring final
El score final es una combinación ponderada del vector de riesgo:
- `semantic`: 45%
- `url`: 35%
- `domain`: 20% (derivado de señales WHOIS)

Luego se transforma a:
- `risk_score` entero entre `0..100`

### 4) Niveles de riesgo
- `danger` si `score >= 75`
- `suspicious` si `score >= 40`
- `safe` si `score < 40`

---

## 🧾 Señales (signals) y explicación

El motor devuelve señales “human-friendly” mediante un mapeo interno (`signals_map`).
Ejemplos:
- `brand_impersonation` → “Suplantación de marca”
- `credentials` → “Posible robo de credenciales”
- `very_new_domain` → “Dominio recién creado”

Además, el frontend incluye una capa adicional de traducción para algunas señales.

---

## ⚙️ Requisitos del sistema

### Backend
- Python 3.10+ recomendado
- Dependencias en `backend/requirements.txt`

### Frontend
- Node.js 16+ recomendado
- React (CRA) usando `react-scripts`

---

## 🚀 Setup y ejecución

### 1) Backend (FastAPI)

```bash
cd backend
python -m venv .venv
. .venv\Scripts\activate
pip install -r requirements.txt

uvicorn server:app --reload --port 8000
```

> En Windows, la activación es con `. .venv\Scripts\activate`.

API esperada:
- `http://localhost:8000/api/health`
- `http://localhost:8000/api/analyze`

### 2) Frontend (React)

```bash
cd frontend
npm install
npm start
```

El frontend requiere conocer la URL del backend si usas configuración por entorno.

---

## 🔌 Variables de entorno

### Backend
- `backend/server.py` carga `.env` desde `backend/`:
  - `load_dotenv(ROOT_DIR / ".env")`

> En el código actual, no se observa un uso directo de variables específicas, pero el archivo `.env` puede usarse para despliegues o ampliaciones.

### Frontend
- `frontend/src/api/client.js` usa `process.env.REACT_APP_BACKEND_URL`.
- Si no está definida, el frontend en varios puntos usa `http://localhost:8000` directamente (hay duplicidad en llamadas en distintos módulos).

---

## 🧪 Ejemplo rápido (curl)

```bash
curl -X POST http://localhost:8000/api/analyze \
  -H "Content-Type: application/json" \
  -d '{"text":"Recuerda verificar tu cuenta inmediatamente. Accede aquí: http://example.com/login"}'
```

---

## 📌 Limitaciones actuales

- **WHOIS** puede fallar según red/limitaciones del entorno (por eso no penaliza si ocurre una excepción).
- El análisis semántico depende de:
  - similitud con prototipos (`INTENTS`)
  - umbral (`SIMILARITY_THRESHOLD`)
- El sistema no reemplaza:
  - controles de seguridad del cliente
  - validación adicional (p.ej. reputación de dominio vía servicios externos)

---

## 🗺️ Roadmap (sugerido)

- Persistir `history` y `stats` (ahora están mock).
- Añadir almacenamiento por `X-Device-ID` y/o por usuario (con consentimiento).
- Cache del modelo `SentenceTransformer` (ya existe lazy init en `analysis_engine.py`) y optimización adicional de embeddings.
- Mejoras de extracción de URL y normalización (redirecciones, dominios punycode, etc.).
- Unificar llamadas de frontend para que todas usen el `client.js` (consistencia de baseURL y headers).

---

## 👤 Autor

Miguel Ángel Cuesta  
Cybersecurity & GRC Analyst

