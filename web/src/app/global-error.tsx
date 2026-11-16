"use client";

import * as React from "react";

// Root error boundary: when the layout / global provider layer throws, app/error.tsx
// cannot catch it — global-error.tsx must (and it has to bring its own <html>/<body>).
// Inline styles only, deliberately: by the time we get here the style system itself may
// be broken.
type ErrorProps = {
  error: Error & { digest?: string };
  reset: () => void;
};

export default function GlobalError({ error, reset }: ErrorProps) {
  React.useEffect(() => {
    console.error("[pojun] application-level error:", error);
  }, [error]);

  const text = [error?.name, error?.message].filter(Boolean).join(": ") || String(error);
  return (
    <html lang="zh-CN">
      <body
        style={{
          margin: 0,
          minHeight: "100vh",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          fontFamily: "system-ui, -apple-system, sans-serif",
          background: "#0b0b0c",
          color: "#e5e5e5",
          padding: 24,
        }}
      >
        <div style={{ maxWidth: 720, width: "100%" }}>
          <h1 style={{ fontSize: 18, margin: "0 0 8px" }}>The app failed to start</h1>
          <p style={{ fontSize: 13, color: "#a3a3a3", margin: "0 0 16px" }}>
            The page threw while initializing. The information below helps locate the cause
            (screenshot it directly to report).
          </p>
          <pre
            style={{
              whiteSpace: "pre-wrap",
              wordBreak: "break-all",
              fontSize: 12,
              lineHeight: 1.5,
              background: "#171717",
              border: "1px solid #2a2a2a",
              borderRadius: 8,
              padding: 12,
              maxHeight: 260,
              overflow: "auto",
            }}
          >
            {text}
          </pre>
          <button
            type="button"
            onClick={() => reset()}
            style={{
              marginTop: 16,
              padding: "8px 14px",
              borderRadius: 8,
              border: "1px solid #3a3a3a",
              background: "#1f1f1f",
              color: "#e5e5e5",
              cursor: "pointer",
            }}
          >
            Retry
          </button>
        </div>
      </body>
    </html>
  );
}
