import { defineConfig, defineDocs } from "fumadocs-mdx/config";
import { metaSchema, pageSchema } from "fumadocs-core/source/schema";
import { remarkDirectiveAdmonition } from "fumadocs-core/mdx-plugins";
import remarkDirective from "remark-directive";
import { z } from "zod";
import { remarkMermaid } from "./lib/remark-mermaid";

const schema = pageSchema.extend({
  sourcePath: z.string(),
  date: z.string().optional(),
  tags: z.array(z.string()).default([]),
  authors: z.array(z.string()).default([]),
});

const options = {
  docs: { schema, postprocess: { includeProcessedMarkdown: true } },
  meta: { schema: metaSchema },
};

export const docs = defineDocs({ dir: "content/docs", ...options });
export const blog = defineDocs({ dir: "content/blog", ...options });
export const pages = defineDocs({ dir: "content/pages", ...options });

export default defineConfig({
  mdxOptions: {
    remarkPlugins: [remarkDirective, remarkDirectiveAdmonition, remarkMermaid],
  },
});
