import { ImageResponse } from "next/og";

export function GET(request: Request) {
  const title = (
    new URL(request.url).searchParams.get("title") ||
    "Modular authentication for Go"
  ).slice(0, 150);
  return new ImageResponse(
    <div
      style={{
        background: "#232a23",
        color: "#f8f7f3",
        width: "100%",
        height: "100%",
        display: "flex",
        flexDirection: "column",
        justifyContent: "space-between",
        padding: 72,
      }}
    >
      <div style={{ display: "flex", fontSize: 32, color: "#f2a07b" }}>
        GoAuth / Documentation
      </div>
      <div
        style={{
          display: "flex",
          fontSize: 64,
          lineHeight: 1.1,
          fontWeight: 700,
        }}
      >
        {title}
      </div>
      <div style={{ display: "flex", fontSize: 24, color: "#b3bea9" }}>
        Import it. Configure it. Ship it.
      </div>
    </div>,
    {
      width: 1200,
      height: 630,
      headers: {
        "Cache-Control": "public, max-age=86400",
        "X-Robots-Tag": "noindex",
      },
    },
  );
}
