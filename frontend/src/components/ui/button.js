export function Button({ children, onClick, className = "" }) {
  return (
    <button
      onClick={onClick}
      className={"px-4 py-2 rounded bg-blue-600 text-white " + className}
    >
      {children}
    </button>
  );
}