import { useId } from "react";
import { renderMermaidSVG } from "beautiful-mermaid";
import { CodeBlock, Pre } from "fumadocs-ui/components/codeblock";

export function Mermaid({ chart }: { chart: string }) {
  const id = `diagram-${useId().replace(/[^a-zA-Z0-9_-]/g, "")}`;
  // A light canvas preserves the explicit pastel fills in the original diagrams.
  let svg = renderMermaidSVG(chart, {
    font: "system-ui",
    bg: "#fafaf9",
    fg: "#27272a",
  });
  // Inline SVG styles and marker IDs must be scoped to this diagram.
  svg = svg
    .replace(
      /<style>([\s\S]*?)<\/style>/g,
      (_, css: string) =>
        `<style>${css
          .replace(/@import[^;]+;/g, "")
          .replace(/\btext\s*\{/g, `#${id} text {`)
          .replace(/\bsvg\s*\{/g, `#${id} {`)}</style>`,
    )
    .replace(/(?<=\s)id="([^"]+)"/g, `id="${id}-$1"`)
    .replace(/url\(#([^)]+)\)/g, `url(#${id}-$1)`)
    .replace(
      "<svg ",
      `<svg id="${id}" role="img" aria-label="Architecture diagram; text source is available below" `,
    );

  return (
    <figure className="mermaid-figure not-prose" data-mermaid-diagram>
      <div
        className="mermaid-canvas"
        tabIndex={0}
        role="region"
        aria-label="Scrollable architecture diagram"
        dangerouslySetInnerHTML={{ __html: svg }}
      />
      <figcaption>Scroll to explore the diagram.</figcaption>
      <details>
        <summary>Diagram source</summary>
        <CodeBlock title="Mermaid">
          <Pre>
            <code>{chart}</code>
          </Pre>
        </CodeBlock>
      </details>
    </figure>
  );
}
