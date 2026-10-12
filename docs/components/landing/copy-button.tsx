"use client";

import { useEffect, useRef, useState } from "react";
import { Check, Copy } from "lucide-react";

export function CopyButton({
  value,
  label = "Copy code",
}: {
  value: string;
  label?: string;
}) {
  const [status, setStatus] = useState("");
  const timer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  useEffect(() => () => clearTimeout(timer.current), []);
  async function copy() {
    clearTimeout(timer.current);
    try {
      await navigator.clipboard.writeText(value);
      setStatus("Copied");
    } catch {
      setStatus("Select the code to copy");
    }
    timer.current = setTimeout(() => setStatus(""), 2500);
  }
  return (
    <span className="copy-control">
      <button
        type="button"
        className="icon-button"
        onClick={copy}
        aria-label={label}
        title={label}
      >
        {status === "Copied" ? <Check size={16} /> : <Copy size={16} />}
      </button>
      <span className="copy-status" role="status">
        {status}
      </span>
    </span>
  );
}
