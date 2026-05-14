import { useState } from "react";

export function Tabs({ value, onValueChange, children }) {
  return <div>{children}</div>;
}

export function TabsList({ children }) {
  return <div style={{ display: "flex", gap: 10 }}>{children}</div>;
}

export function TabsTrigger({ value, children, onClick }) {
  return (
    <button onClick={() => onClick(value)}>
      {children}
    </button>
  );
}

export function TabsContent({ children }) {
  return <div>{children}</div>;
}