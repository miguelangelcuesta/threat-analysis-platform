export default function TrafficLight({ ui }) {
  const color = ui?.color || "#999";

  return (
    <div style={{ display: "flex", alignItems: "center" }}>
      <div
        style={{
          width: 12,
          height: 12,
          borderRadius: "50%",
          background: color,
          boxShadow: `0 0 10px ${color}`,
          animation: "pulse 1.2s infinite"
        }}
      />

      <style>{`
        @keyframes pulse {
          0% { transform: scale(1); opacity: 1; }
          50% { transform: scale(1.4); opacity: 0.6; }
          100% { transform: scale(1); opacity: 1; }
        }
      `}</style>
    </div>
  );
}
