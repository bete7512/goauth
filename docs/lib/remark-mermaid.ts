import { remarkMdxMermaid } from "fumadocs-core/mdx-plugins";
import type { Root, Nodes } from "mdast";
import type { VFile } from "vfile";

// Retain diagram source in the Markdown/LLM endpoints after the MDX transform.
export function remarkMermaid() {
  const transform = remarkMdxMermaid();
  return (tree: Root, file: VFile) => {
    transform(tree, file, () => {});
    function preserve(node: Nodes) {
      if (node.type === "mdxJsxFlowElement" && node.name === "Mermaid") {
        const chart = node.attributes.find(
          (attribute) =>
            attribute.type === "mdxJsxAttribute" && attribute.name === "chart",
        );
        if (
          chart?.type === "mdxJsxAttribute" &&
          typeof chart.value === "string"
        ) {
          node.data = {
            ...node.data,
            _stringify: { text: `\`\`\`mermaid\n${chart.value}\n\`\`\`` },
          };
        }
      }
      if ("children" in node) node.children.forEach(preserve);
    }
    preserve(tree);
  };
}
