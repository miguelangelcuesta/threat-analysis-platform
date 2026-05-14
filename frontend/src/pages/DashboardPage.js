import { useState } from "react";
import axios from "axios";
import TrafficLight from "../components/TrafficLight";

const API = "http://localhost:8000/api";

export default function DashboardPage() {

  const [inputType, setInputType] = useState("text");
  const [textInput, setTextInput] = useState("");
  const [urlInput, setUrlInput] = useState("");

  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");

  const analyze = async () => {

    const content = inputType === "text"
      ? textInput
      : urlInput;

    if (!content.trim()) {
      setError("Introduce contenido para analizar");
      return;
    }

    setError("");
    setLoading(true);
    setResult(null);

    try {

      const res = await axios.post(`${API}/analyze`, {
        text: inputType === "text" ? textInput : null,
        url: inputType === "url" ? urlInput : null,
        input_type: inputType,
      });

      setResult(res.data);

    } catch (e) {

      setError(
        e.response?.data?.detail ||
        "Error durante el análisis"
      );

    }

    setLoading(false);
  };

  const clear = () => {
    setTextInput("");
    setUrlInput("");
    setResult(null);
    setError("");
  };

  const risk = result?.risk_level;

  const ui = {
    safe: {
      color: "#22c55e",
      bg: "#052e16",
      title: "Análisis seguro",
      subtitle: "No se han detectado indicios relevantes de fraude"
    },

    suspicious: {
      color: "#facc15",
      bg: "#3b2f0b",
      title: "Actividad sospechosa detectada",
      subtitle: "Clasificación de riesgo basada en señales detectadas"
    },

    danger: {
      color: "#ef4444",
      bg: "#3f0a0a",
      title: "Amenaza detectada",
      subtitle: "Se han identificado patrones de fraude o suplantación"
    }
  };

  const theme = ui[risk] || ui.safe;

  const spinnerKeyframes = `
    @keyframes spin {
      0% { transform: rotate(0deg); }
      100% { transform: rotate(360deg); }
    }
  `;

  return (

    <div style={styles.page}>

      {/* LEFT PANEL */}
      <div style={styles.left}>

        <h2>🛡️ Plataforma de Análisis de Amenazas</h2>

<p style={styles.sideText}>
 Detección inteligente de amenazas,
  fraude digital y análisis de reputación.
</p>

        <div style={styles.toggle}>

          <button
            style={styles.toggleButton}
            onClick={() => setInputType("text")}
          >
            Texto
          </button>

          <button
            style={styles.toggleButton}
            onClick={() => setInputType("url")}
          >
            URL
          </button>

        </div>

        {inputType === "text" ? (

          <textarea
            style={styles.input}
            value={textInput}
            onChange={(e) => setTextInput(e.target.value)}
            placeholder="Introduce el mensaje sospechoso..."
          />

        ) : (

          <input
            style={styles.input}
            value={urlInput}
            onChange={(e) => setUrlInput(e.target.value)}
            placeholder="https://ejemplo.com"
          />

        )}

        <div style={styles.actions}>

          <button
            style={styles.primaryButton}
            onClick={analyze}
            disabled={loading}
          >
            {loading ? "Analizando..." : "Analizar"}
          </button>

          <button
            style={styles.secondaryButton}
            onClick={clear}
          >
            Limpiar
          </button>

        </div>

        {error && (
          <p style={styles.error}>
            {error}
          </p>
        )}

      </div>

      {/* CENTER PANEL */}
      <div style={styles.center}>

        <h2 style={{ marginBottom: 20 }}>
          🧠 Informe de seguridad
        </h2>

        {/* LOADING */}
        {loading && (

          <div style={styles.loadingBox}>

            <div style={styles.spinner}></div>

            <div>

              <h3 style={{ margin: 0 }}>
                Analizando amenaza...
              </h3>

              <p style={{ opacity: 0.7 }}>
                Procesando señales semánticas y reputación del dominio
              </p>

            </div>

          </div>
        )}

        {/* EMPTY */}
        {!result && !loading && (

          <div style={styles.emptyState}>

            <h3>
              Sistema preparado para análisis
            </h3>

            <p style={{ opacity: 0.7 }}>
              Introduce un mensaje o URL para iniciar
              la evaluación de riesgo.
            </p>

          </div>

        )}

        {/* RESULT */}
        {result && (

          <div
            style={{
              ...styles.card,
              background: theme.bg
            }}
          >

            {/* MAIN STATUS */}
            <div style={{ marginBottom: 22 }}>

              <div style={styles.stateRow}>

                <TrafficLight riskLevel={risk} />

                <h2
                  style={{
                    color: theme.color,
                    margin: 0
                  }}
                >
                  {theme.title}
                </h2>

              </div>

              <p
                style={{
                  opacity: 0.85,
                  marginTop: 8
                }}
              >
                {theme.subtitle}
              </p>

            </div>

            {/* ACTION */}
            <div
              style={{
                background: theme.color,
                color: "#000",
                padding: 14,
                borderRadius: 10,
                fontWeight: "bold",
                marginBottom: 22
              }}
            >
              🎯 {result.action}
            </div>

            {/* SIGNALS */}
            <h3>🧠 Señales detectadas</h3>

            {result.signals?.length ? (

              <ul style={styles.signalList}>

                {result.signals.map((s, i) => (
                  <li key={i}>
                    {translateSignal(s)}
                  </li>
                ))}

              </ul>

            ) : (

              <p>
                Sin señales relevantes detectadas
              </p>

            )}

            {/* ANALYSIS */}
            <h3>📊 Análisis</h3>

            <p style={{ lineHeight: 1.7 }}>

              Evaluación basada en comportamiento
              del contenido, estructura de enlaces
              y reputación del dominio para detectar
              posibles patrones de fraude.

            </p>

            {/* TECHNICAL */}
            <details
              style={{
                marginTop: 18,
                opacity: 0.85
              }}
            >

              <summary style={{ cursor: "pointer" }}>
                Detalles técnicos
              </summary>

              <p style={{ marginTop: 10 }}>

                Motor de scoring híbrido basado
                en NLP, heurísticas de dominio
                y clasificación de riesgo.

              </p>

            </details>

          </div>
        )}

      </div>

      <style>{spinnerKeyframes}</style>

    </div>
  );
}

/* ================= HELPERS ================= */

function translateSignal(signal) {

  const map = {
    "brand_impersonation": "Intento de suplantación de marca",
    "phishing_keywords": "Uso de lenguaje típico de phishing",
    "very_new_domain": "Dominio recién creado",
    "recent_domain": "Dominio reciente",
    "long_domain": "Dominio inusualmente largo",
    "credentials": "Posible intento de robo de credenciales",
    "urgency": "Uso de lenguaje manipulativo o urgente"
  };

  return map[signal] || signal;
}

/* ================= STYLES ================= */

const styles = {

  page: {
    display: "flex",
    minHeight: "100vh",
    background: "#0a0f1c",
    color: "white",
    fontFamily: "Arial"
  },

  left: {
    width: "30%",
    minWidth: 320,
    padding: 24,
    borderRight: "1px solid #1f2937",
    background: "#0b1220"
  },

  center: {
    flex: 1,
    padding: 30,
    overflowY: "auto"
  },

  sideText: {
    opacity: 0.7,
    lineHeight: 1.6,
    marginBottom: 20
  },

  toggle: {
    display: "flex",
    gap: 10,
    marginBottom: 15
  },

  toggleButton: {
    flex: 1,
    padding: 10,
    borderRadius: 8,
    border: "none",
    cursor: "pointer"
  },

  input: {
    width: "100%",
    minHeight: 130,
    padding: 14,
    borderRadius: 10,
    border: "1px solid #1f2937",
    background: "#111827",
    color: "white",
    resize: "none",
    outline: "none",
    marginBottom: 15
  },

  actions: {
    display: "flex",
    gap: 10
  },

  primaryButton: {
    flex: 1,
    padding: 12,
    borderRadius: 8,
    border: "none",
    background: "#2563eb",
    color: "white",
    cursor: "pointer",
    fontWeight: "bold"
  },

  secondaryButton: {
    flex: 1,
    padding: 12,
    borderRadius: 8,
    border: "1px solid #374151",
    background: "transparent",
    color: "white",
    cursor: "pointer"
  },

  card: {
    padding: 24,
    borderRadius: 16,
    border: "1px solid rgba(255,255,255,0.06)"
  },

  stateRow: {
    display: "flex",
    alignItems: "center",
    gap: 14
  },

  loadingBox: {
    display: "flex",
    alignItems: "center",
    gap: 20,
    background: "#111827",
    padding: 24,
    borderRadius: 14
  },

  spinner: {
    width: 45,
    height: 45,
    border: "4px solid #1f2937",
    borderTop: "4px solid #3b82f6",
    borderRadius: "50%",
    animation: "spin 1s linear infinite"
  },

  emptyState: {
    opacity: 0.75,
    marginTop: 40
  },

  signalList: {
    lineHeight: 2
  },

  error: {
    color: "#ff6b6b",
    marginTop: 15
  }

};