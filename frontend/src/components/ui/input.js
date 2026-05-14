export function Input(props) {
  return (
    <input
      {...props}
      className={
        "w-full px-3 py-2 border rounded " + (props.className || "")
      }
    />
  );
}