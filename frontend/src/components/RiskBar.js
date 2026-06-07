export default function RiskBar({ score = 0, ui }) {
  const color = ui?.color || "#999";

  return (
    <div style={styles.container}>
      <div style={styles.bar}>
        <div
          style={{
            ...styles.fill,
            width: `${score}%`,
            backgroundColor: color
          }}
        />
      </div>
    </div>
  );
}

const styles = {
  container: {
    marginTop: 10
  },
  bar: {
    width: "100%",
    height: 10,
    backgroundColor: "#1f2937",
    borderRadius: 20,
    overflow: "hidden"
  },
  fill: {
    height: "100%",
    transition: "width 0.4s ease"
  },
  label: {
    fontSize: 12,
    opacity: 0.7,
    marginTop: 6
  }
};
