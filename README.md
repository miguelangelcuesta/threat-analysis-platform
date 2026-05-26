# 🛡️ Anti-Scam Detector

Sistema de **detección de phishing/estafas** para analizar **texto** y **URLs** con una aproximación híbrida:

- **NLP semántico** (SentenceTransformer) para reconocer intenciones (p. ej. credenciales, suplantación, urgencia).
- **Heurísticas de dominio** (keywords típicas, longitud y señales de “suplantación”).
- **Señales de reputación (WHOIS)** opcionales (si están disponibles en el entorno).

> ⚠️ Importante: la herramienta ofrece una **evaluación orientativa** basada en patrones. No garantiza la legitimidad del mensaje o dominio.

---

## ✨ Funcionalidades

- Entrada por **tipo de contenido**:
  - Mensajes (texto)
  - Enlaces (URL) (vía campo `url` o URL embebida dentro del texto)
- Resultado orientado a UI:
  - `verdict.level` (bin semántico para el “traffic light”)
  - `verdict.score` (0..100)
  - `executive_summary` (resumen)
  - `analysis.text` (intención y técnicas)
  - `analysis.url` (dominio y problema)
  - `cadena_ataque` (pasos de posible ataque)
  - `evidencias` (evidencias detectadas)

---

## 🧩 Arquitectura

```
anti-scam-detector/
├─ backend/
│  ├─ server.py                 # API FastAPI
│  └─ analysis_engine.py       # Motor de análisis (NLP + heurísticas)
│  └─ soc/                     # reglas / correlación / persistencia
└─ frontend/
   ├─ src/
   │  ├─ pages/DashboardPage.js # UI principal (entrada + reporte)
   │  └─ api/client.js          # cliente axios
   │  └─ utils/device.js       # persistencia de device_id en localStorage
```

---

## 🔁 API (Backend)

### Endpoints

- `GET /api/health`
- `GET /api/analyze` ❌ (no existe)
- `POST /api/analyze`
- `GET /api/history` (mock)
- `GET /api/stats` (mock)

### `POST /api/analyze`

**Request (JSON):**

- El backend acepta `text` y/o `url`.
- Se procesa el campo:
  - `content = data.text or data.url or ""`

Ejemplo (texto):

```json
{
  "text": "...",
  "url": null,
  "input_type": "text"
}
```

Ejemplo (URL):

```json
{
  "text": null,
  "url": "https://ejemplo.com",
  "input_type": "url"
}
```

**Headers opcionales:**
- `X-Device-ID` (si no se envía, se usa `anonymous`)

**Response (JSON):**

```json
{
  "id": "YYYYMMDDHHMMSS",
  "device": "anonymous",
  "verdict": {
    "level": "safe|medium|high|critical",
    "score": 0,
    "action": "..."
  },
  "executive_summary": "...",
  "analysis": {
    "text": {
      "intention": "...",
      "tecnicas": ["..."]
    },
    "url": {
      "dominio": "...",
      "problema": "..."
    }
  },
  "cadena_ataque": ["..."],
  "evidencias": ["..."],
  "signals": ["..."]
}
```

**Errores:**
- `400` con `detail: "Empty input"` si `text`/`url` resultan vacíos.

---

## 🧠 Motor de análisis (high-level)

1. **Extracción de URLs** desde el texto (si aplica) y obtención del dominio.
2. **Riesgo de dominio** con heurísticas:
   - señales de posible **suplantación** por keywords de marcas
   - keywords típicas de phishing (login/secure/verify/account)
   - longitudes anómalas
3. **WHOIS (opcional)**:
   - si está disponible, estima riesgo por antigüedad
   - si falla, **no penaliza** (se captura la excepción)
4. **Análisis semántico (NLP)**:
   - embedding del texto
   - similitud con prototipos de intenciones (`INTENTS`)
   - scoring ponderado y transformación a 0..100
5. **Reglas** (`soc_rules`) y construcción de salida humana:
   - intención + técnicas
   - problema del dominio
   - cadena de ataque
   - evidencias

---

## 🚦 Niveles de riesgo (según UI)

El frontend interpreta `verdict.level` como:

- `safe`
- `medium` (riesgo medio)
- `high` (riesgo alto)
- `critical` (riesgo crítico)

---

## ⚙️ Requisitos del sistema

### Backend
- Python 3.10+
- Dependencias en `backend/requirements.txt`

### Frontend
- Node.js 16+
- React (CRA)

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

API esperada:
- `http://localhost:8000/api/health`
- `http://localhost:8000/api/analyze`

### 2) Frontend (React)

```bash
cd frontend
npm install
npm start
```

---

## 🧪 Ejemplo rápido (curl)

```bash
curl -X POST http://localhost:8000/api/analyze \
  -H "Content-Type: application/json" \
  -d '{"text":"Recuerda verificar tu cuenta inmediatamente. Accede aquí: http://example.com/login","url":null,"input_type":"text"}'
```

---

## 📌 Notas / Limitaciones

- WHOIS puede fallar según la red o restricciones del entorno.
- El scoring depende del ajuste de:
  - prototipos semánticos (`INTENTS`)
  - umbral de similitud
  - heurísticas de dominio
- No reemplaza controles de seguridad del cliente ni validaciones externas.

---

## 👤 Autor

Miguel Ángel Cuesta  
Cybersecurity & GRC Analyst

