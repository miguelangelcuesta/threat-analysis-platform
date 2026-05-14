export function Textarea(props) {
  return (
    <textarea
      {...props}
      className={
        "w-full px-3 py-2 border rounded min-h-[120px] " +
        (props.className || "")
      }
    />
  );
}