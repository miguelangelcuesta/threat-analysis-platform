import { useState } from "react";
import TrafficLight from "../components/TrafficLight";
import client from "../api/client";

export default function DashboardPage() {

  const [textInput, setTextInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");

  const analyze = async () => {

    if (!textInput.trim()) {
      setError("Introduce contenido para analizar");
      return;
    }

    setError("");
    setLoading(true);
    setResult(null);

    try {
      const res = await client.post("/analyze", {
        text: textInput,
        input_type: "text"
      });

      setResult(res.data);

    } catch (e) {
      setError(e.response?.data?.detail || "Error en el análisis");
    }

    setLoading(false);
  };

  const clear = () => {
    setTextInput("");
    setResult(null);
    setError("");
  };

  const risk = result?.verdict?.level || "safe";
  const score = result?.verdict?.score || 0;

  const UI = {
    safe: { color: "#22c55e", bg: "#071a12", label: "SEGURO" },
    low: { color: "#38bdf8", bg: "#0a1f2a", label: "BAJO RIESGO" },
    medium: { color: "#facc15", bg: "#2a240a", label: "RIESGO MEDIO" },
    high: { color: "#fb923c", bg: "#2a1408", label: "RIESGO ALTO" },
    critical: { color: "#ef4444", bg: "#2a0707", label: "CRÍTICO" }
  };

  const theme = UI[risk] || UI.safe;

  return (
    <div style={styles.page}>

      {/* LEFT PANEL */}
      <div style={styles.left}>

        <h2 style={styles.title}>SOC Threat Analyzer</h2>

        <p style={styles.subtitle}>
          Sistema de análisis de amenazas y phishing en tiempo real
        </p>

        <textarea
          style={styles.input}
          value={textInput}
          onChange={(e) => setTextInput(e.target.value)}
          placeholder="Introduce el mensaje o email sospechoso..."
        />

        <div style={styles.actions}>
          <button style={styles.primaryButton} onClick={analyze}>
            Analizar
          </button>

          <button style={styles.secondaryButton} onClick={clear}>
            Limpiar
          </button>
        </div>

        {error && <p style={styles.error}>{error}</p>}
      </div>

      {/* MAIN PANEL */}
      <div style={styles.center}>

        {!result && !loading && (
          <div style={styles.empty}>
            Sistema listo para análisis
          </div>
        )}

        {loading && (
          <div style={styles.loadingBox}>
            <div style={styles.spinner}></div>
            <div>
              Analizando amenaza en tiempo real...
            </div>
          </div>
        )}

        {/* RESULT */}
        {result && (
          <div style={{ ...styles.card, background: theme.bg }}>

            {/* HEADER DECISION */}
            <div style={styles.header}>
              <TrafficLight riskBin={risk} />

              <div>
                <div style={{ color: theme.color, fontSize: 22 }}>
                  {theme.label}
                </div>

                <div style={styles.score}>
                  Puntuación: {score}/100
                </div>
              </div>
            </div>

            {/* SUMMARY */}
            <div style={styles.section}>
              <h3>Resumen ejecutivo</h3>
              <p>{result.executive_summary}</p>
            </div>

            {/* TEXT ANALYSIS */}
            <div style={styles.grid}>

              <div style={styles.panel}>
                <h4>ANÁLISIS DEL TEXTO</h4>
                <p><b>Intención:</b> {result.analysis?.text?.intention || "-"}</p>
                <p><b>Técnicas:</b></p>
                <ul>
                  {(result.analysis?.text?.tecnicas || []).map((t, i) => (
                    <li key={i}>{t}</li>
                  ))}
                </ul>
              </div>

              {/* URL ANALYSIS */}
              <div style={styles.panel}>
                <h4>ANÁLISIS DE URL</h4>
                <p><b>Dominio:</b> {result.analysis?.url?.dominio || "-"}</p>
                <p>{result.analysis?.url?.problema}</p>
              </div>
            </div>

            {/* ATTACK CHAIN */}
            <div style={styles.section}>
              <h3>Cadena de ataque</h3>

              <ul>
                {(result.cadena_ataque || []).map((step, i) => (
                  <li key={i}>{step}</li>
                ))}
              </ul>
            </div>

            {/* EVIDENCE */}
            <div style={styles.section}>
              <h3>Evidencias</h3>

              <ul>
                {(result.evidencias || []).map((e, i) => (
                  <li key={i}>{e}</li>
                ))}
              </ul>
            </div>

            {/* ACTION */}
            <div style={styles.actionBox}>
              Acción recomendada: {result.verdict?.action}
            </div>

          </div>
        )}

      </div>
    </div>
  );
}

/* ================= STYLES ================= */

const styles = {

  page: {
    display: "flex",
    height: "100vh",
    background: "#0a0f1c",
    color: "#ffffff",
    fontFamily: "Arial"
  },

  left: {
    width: 340,
    padding: 20,
    borderRight: "1px solid #1f2937",
    background: "#0b1220"
  },

  center: {
    flex: 1,
    padding: 24,
    overflowY: "auto"
  },

  title: {
    fontSize: 18,
    marginBottom: 10
  },

  subtitle: {
    fontSize: 13,
    opacity: 0.7,
    marginBottom: 20
  },

  input: {
    width: "100%",
    height: 180,
    background: "#111827",
    color: "white",
    border: "1px solid #374151",
    borderRadius: 8,
    padding: 10
  },

  actions: {
    display: "flex",
    gap: 10,
    marginTop: 10
  },

  primaryButton: {
    flex: 1,
    padding: 10,
    background: "#2563eb",
    border: "none",
    color: "white",
    cursor: "pointer"
  },

  secondaryButton: {
    flex: 1,
    padding: 10,
    background: "transparent",
    border: "1px solid #374151",
    color: "white",
    cursor: "pointer"
  },

  error: {
    marginTop: 10,
    color: "#ef4444"
  },

  center: {
    flex: 1
  },

  empty: {
    opacity: 0.6,
    marginTop: 40
  },

  loadingBox: {
    padding: 20,
    display: "flex",
    gap: 15,
    alignItems: "center"
  },

  spinner: {
    width: 35,
    height: 35,
    border: "3px solid #1f2937",
    borderTop: "3px solid #3b82f6",
    borderRadius: "50%",
    animation: "spin 1s linear infinite"
  },

  card: {
    padding: 20,
    borderRadius: 12
  },

  header: {
    display: "flex",
    gap: 15,
    alignItems: "center",
    marginBottom: 20
  },

  score: {
    fontSize: 13,
    opacity: 0.8
  },

  section: {
    marginTop: 20
  },

  grid: {
    display: "grid",
    gridTemplateColumns: "1fr 1fr",
    gap: 10,
    marginTop: 20
  },

  panel: {
    background: "#0f172a",
    padding: 12,
    borderRadius: 8,
    border: "1px solid #1f2937"
  },

  actionBox: {
    marginTop: 20,
    padding: 12,
    background: "#111827",
    borderRadius: 8,
    border: "1px solid #374151",
    fontWeight: "bold"
  }
};