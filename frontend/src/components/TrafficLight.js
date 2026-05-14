export default function TrafficLight({ riskLevel }) {
  const config = {
    safe: { color: "#38a169" },
    suspicious: { color: "#facc15" },
    danger: { color: "#e53e3e" }
  };

  const current = config[riskLevel] || config.safe;

  return (
    <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
      <div
        style={{
          width: 14,
          height: 14,
          borderRadius: "50%",
          background: current.color,
          animation: "pulse 1.2s infinite"
        }}
      />

      <style>{`
        @keyframes pulse {
          0% { transform: scale(1); opacity: 1; }
          50% { transform: scale(1.3); opacity: 0.6; }
          100% { transform: scale(1); opacity: 1; }
        }
      `}</style>
    </div>
  );
}