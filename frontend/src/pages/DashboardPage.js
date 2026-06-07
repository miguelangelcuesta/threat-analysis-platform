import { useState } from "react";
import TrafficLight from "../components/TrafficLight";
import client from "../api/client";
import RiskBar from "../components/RiskBar";

export default function DashboardPage() {

  const [textInput, setTextInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");

  const analyze = async () => {
  console.log("CLICK ANALYZE FUNCIONA");

    if (!textInput.trim()) {
      setError("Introduce contenido para analizar");
      return;
    }

    setError("");
    setLoading(true);
    setResult(null);

    setTimeout(async () => {
      try {
        const res = await client.post("/analyze", {
          text: textInput,
          input_type: "text"
        });
        console.log("VERDICT COMPLETO:", result?.verdict);
console.log("LEVEL:", result?.verdict?.level);
console.log("UI:", result?.verdict?.ui);
console.log("SCORE:", result?.verdict?.score);

        setResult(res.data);
      } catch (e) {
        console.log("ERROR BACKEND:", e);
        setError(e.response?.data?.detail || "Error en el análisis");
      }

      setLoading(false);
    }, 2000);
  };

  const clear = () => {
    setTextInput("");
    setResult(null);
    setError("");
  };

  const verdict = result?.verdict;
  const score = verdict?.score || 0;
  const ui = verdict?.ui;


  return (
  <div style={styles.layout}>

    {/* SIDEBAR */}
    <div style={styles.sidebar}>
      <h2 style={styles.logo}>SOC Threat Analyzer</h2>

      <p style={styles.subtitle}>
        Motor de Inteligencia de Amenazas y Phishing
      </p>

      <textarea
        style={styles.input}
        value={textInput}
        onChange={(e) => setTextInput(e.target.value)}
        placeholder="Introduce una URL, email o contenido sospechoso..."
      />

      <button style={styles.primaryButton} onClick={analyze}>
        Analizar
      </button>

      <button style={styles.secondaryButton} onClick={clear}>
        Limpiar
      </button>

      {error && <p style={styles.error}>{error}</p>}
    </div>

    {/* MAIN */}
    <div style={styles.main}>

      {!result && !loading && (
        <div style={styles.empty}>
          Sistema listo. Introduce un objetivo para analizar.
        </div>
      )}

      {loading && (
        <div style={styles.loadingBox}>
          <div style={styles.spinner}></div>
          Analizando amenaza...
        </div>
      )}

      {result && (
        <div style={{
          ...styles.card,
          background: ui.bg,
          border: `1px solid ${ui.color}33`
        }}>


          {/* HEADER */}
          <div style={styles.header}>

              <div style={styles.riskIcon}>
              	<TrafficLight ui={ui} />
              </div>


            <div style={styles.headerInfo}>

              <div style={{ ...styles.riskLabel, color: ui.color }}>
                {ui.label}
              </div>


              <div style={styles.scoreLine}>
                <span style={{ ...styles.scoreNumber, color: ui.color }}>
  {score}
</span>
                <span style={styles.scoreMax}>/100</span>
              </div>


              <RiskBar score={score} ui={ui} />


            </div>

          </div>

          {/* SUMMARY */}
          <div style={styles.panel}>
              <h3 style={{ ...styles.panelTitle, color: ui.color }}>
              	RESUMEN EJECUTIVO
              </h3>

            <p>{result.executive_summary}</p>
          </div>

          {/* GRID */}
          <div style={styles.grid}>

            <div style={styles.panel}>
              <h4 style={{ ...styles.panelTitle, color: ui.color }}>
                ANÁLISIS DEL TEXTO
              </h4>


              <p><b>Intención:</b> {result.analysis?.text?.intention}</p>

              <p><b>Técnicas:</b></p>
              <ul>
                {(result.analysis?.text?.tecnicas || []).map((t, i) => (
                  <li key={i}>{t}</li>
                ))}
              </ul>
            </div>

            <div style={styles.panel}>
              <h4 style={{ ...styles.panelTitle, color: ui.color }}>
                ANÁLISIS DE URL
              </h4>


              <p><b>Dominio:</b> {result.analysis?.url?.dominio}</p>
              <p>{result.analysis?.url?.problema}</p>
            </div>

            <div style={styles.panel}>
              <h4 style={{ ...styles.panelTitle, color: ui.color }}>
                POR QUÉ ESTE SCORE
              </h4>


              <p style={{ opacity: 0.8 }}>
                {result.reasoning?.summary}
              </p>

              <ul>
                {(result.reasoning?.why_this_score || []).map((item, i) => (
                  <li key={i}>
                    {item
                      .replace("ML contribution", "Coincidencia con patrones de phishing")
                      .replace("URL risk", "Riesgo del enlace")
                      .replace("Rule triggers", "Reglas de seguridad activadas")
                      .replace("Attack chain detected", "Patrón de ataque detectado")
                      .replace("Phishing signals", "Señales de phishing")}
                  </li>
                ))}
              </ul>
            </div>

          </div>

          {/* ACTION */}
          <div style={{
            ...styles.action,
            borderLeft: `4px solid ${ui.color}`
          }}>

            ACCIÓN RECOMENDADA: {result.verdict?.action}
          </div>

        </div>
      )}

    </div>
  </div>
);
}

/* ================= STYLES ================= */

const styles = {

  layout: {
    display: "flex",
    height: "100vh",
    background: "#0a0f1c",
    color: "white",
    fontFamily: "Arial"
  },

  sidebar: {
    width: 320,
    padding: 20,
    background: "#0b1220",
    borderRight: "1px solid #1f2937",
    display: "flex",
    flexDirection: "column",
    gap: 10
  },

  logo: {
    fontSize: 18,
    fontWeight: "bold",
    color: "#60a5fa"
  },

  main: {
    flex: 1,
    padding: 24,
    overflowY: "auto"
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

  primaryButton: {
    padding: 10,
    background: "#2563eb",
    border: "none",
    color: "white",
    cursor: "pointer"
  },

  secondaryButton: {
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
    animationName: "spin",
    animationDuration: "1s",
    animationIterationCount: "infinite",
    animationTimingFunction: "linear"
  },

  card: {
    padding: 24,
    borderRadius: 16,
    border: "1px solid #1f2937",
    boxShadow: "0 0 25px rgba(0,0,0,0.35)"
  },

  header: {
    display: "flex",
    gap: 15,
    alignItems: "center",
    marginBottom: 20,
    paddingBottom: 12,
    borderBottom: "1px solid #1f2937"
  },

  grid: {
    display: "grid",
    gridTemplateColumns: "1fr 1fr",
    gap: 10,
    marginTop: 20
  },

  panel: {
    background: "#0f172a",
    padding: 14,
    borderRadius: 12,
    border: "1px solid #1f2937",
    boxShadow: "0 0 0 1px rgba(255,255,255,0.03)"
  },

  panelTitle: {
    fontSize: 12,
    fontWeight: "700",
    letterSpacing: 1.2,
    textTransform: "uppercase",
    marginBottom: 10,
    color: "#38bdf8",
    opacity: 0.95
  },

  action: {
    marginTop: 20,
    padding: 12,
    background: "#0b1220",
    border: "1px solid #1f2937",
    fontWeight: "bold"
  },

  riskIcon: {
    width: 42,
    display: "flex",
    alignItems: "center",
    justifyContent: "center"
  },

  headerInfo: {
    display: "flex",
    flexDirection: "column",
    gap: 6
  },

  riskLabel: {
    fontSize: 18,
    fontWeight: "bold",
    letterSpacing: 1
  },

  scoreLine: {
    display: "flex",
    alignItems: "baseline",
    gap: 4
  },

  scoreNumber: {
    fontSize: 34,
    fontWeight: "800",
    
  },

  scoreMax: {
    fontSize: 14,
    opacity: 0.6
  
  }
};