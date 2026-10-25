// Keep authored Markdown unchanged; adapt only generated Fumadocs content.
import {
  mkdirSync,
  readFileSync,
  readdirSync,
  writeFileSync,
  unlinkSync,
} from "node:fs";
import { dirname, join, posix } from "node:path";
import { fileURLToPath } from "node:url";
import { load, dump } from "js-yaml";

export const root = fileURLToPath(new URL("../", import.meta.url));

function files(dir) {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) =>
    entry.isDirectory()
      ? files(join(dir, entry.name))
      : [join(dir, entry.name)],
  );
}

function write(path, text) {
  mkdirSync(dirname(path), { recursive: true });
  try {
    if (readFileSync(path, "utf8") === text) return;
  } catch {
    /* new file */
  }
  writeFileSync(path, text);
}

export function syncContent() {
  const inputs = [
    ...files(join(root, "docs"))
      .filter((path) => /\.mdx?$/.test(path))
      .map((path) => ({ path, kind: "docs" })),
    ...files(join(root, "blog"))
      .filter((path) => /\.mdx?$/.test(path))
      .map((path) => ({ path, kind: "blog" })),
    { path: join(root, "standalone/markdown-page.md"), kind: "pages" },
  ];
  const records = inputs.map(({ path, kind }) => {
    const text = readFileSync(path, "utf8");
    const frontmatter = text.match(/^---\r?\n([\s\S]*?)\r?\n---(?:\r?\n|$)/);
    if (!frontmatter) throw new Error(`Missing frontmatter: ${path}`);
    const data = load(frontmatter[1]);
    const content = text.slice(frontmatter[0].length);
    const relative = path.slice(root.length).replaceAll("\\", "/");
    const within =
      kind === "pages" ? "markdown-page.md" : relative.slice(kind.length + 1);
    const stem = within.replace(/\.mdx?$/, "");
    const slug =
      kind === "blog"
        ? (data.slug ?? stem.replace(/^\d{4}-\d{2}-\d{2}-/, ""))
        : data.slug === "/"
          ? ""
          : (data.slug?.replace(/^\//, "") ??
            posix.join(posix.dirname(stem), data.id ?? posix.basename(stem)));
    const url = `${kind === "pages" ? "" : `/${kind}`}${slug ? `/${slug}` : ""}`;
    return { data, content, relative, kind, slug, url, title: data.title };
  });
  const links = new Map(records.map((record) => [record.relative, record.url]));
  const urls = new Set();
  const outputs = new Set();
  for (const record of records) {
    if (urls.has(record.url))
      throw new Error(`Duplicate content URL: ${record.url}`);
    urls.add(record.url);
    // These are unused theme imports in the existing API guide.
    let body = record.content
      .replace(/^import .* from '@theme\/(Tabs|TabItem)';\r?\n/gm, "")
      .replace(/<!-- truncate -->/g, "{/* truncate */}");
    body = body.replace(/^\s*# .+\r?\n/, "\n"); // DocsTitle supplies the single H1.
    let fence;
    body = body
      .split("\n")
      .map((line) => {
        const marker = line.match(/^\s*(`{3,}|~{3,})/);
        if (marker) {
          if (!fence) fence = marker[1];
          else if (
            marker[1][0] === fence[0] &&
            marker[1].length >= fence.length
          )
            fence = undefined;
          return line;
        }
        if (fence) return line;
        line = line.replace(/^(#{1,6} .*?)\s*\{#([^}]+)\}\s*$/, "$1 [#$2]");
        line = line.replace(
          /^:::(info|note|tip|warning|danger)(?: (.+))?$/,
          (_, type, title) => `:::${type}${title ? `[${title}]` : ""}`,
        );
        return line.replace(/\]\(([^)\s]+)\)/g, (match, href) => {
          if (/^(?:[a-z]+:|\/|#)/i.test(href)) return match;
          const [target, hash] = href.split("#");
          if (!/\.mdx?$/.test(target)) return match;
          const resolved = posix.normalize(
            posix.join(posix.dirname(record.relative), target),
          );
          const url = links.get(resolved);
          if (!url)
            throw new Error(`Unresolved link in ${record.relative}: ${href}`);
          return `](${url}${hash ? `#${hash}` : ""})`;
        });
      })
      .join("\n");
    const paragraph =
      body
        .trim()
        .split(/\n\s*\n/)
        .find((text) => !/^(#|```|~~~|<|\||:::|[-*] )/.test(text)) ??
      record.title;
    const plain = paragraph
      .replace(/\[([^\]]+)\]\([^)]+\)/g, "$1")
      .replace(/[*_`]/g, "")
      .replace(/\s+/g, " ")
      .trim();
    const description =
      record.data.description ??
      (plain.length > 160
        ? `${plain.slice(0, 157).replace(/\s+\S*$/, "")}…`
        : plain);
    const frontmatter = {
      title: record.title,
      description,
      sourcePath: record.relative,
      ...(record.kind === "blog"
        ? {
            date: posix.basename(record.relative).slice(0, 10),
            tags: record.data.tags ?? [],
            authors: record.data.authors ?? [],
          }
        : {}),
    };
    const output = join(
      root,
      "content",
      record.kind,
      `${record.slug || "index"}.mdx`,
    );
    outputs.add(output);
    write(output, `---\n${dump(frontmatter)}---\n\n${body.trimStart()}`);
    record.description = description;
  }
  const navigation = {
    "": {
      pages: [
        "index",
        "intro",
        "installation",
        "quickstart",
        "architecture",
        "modules",
        "---Guides---",
        "security",
        "production",
        "storage",
        "migrations",
        "upgrade",
        "performance",
        "compliance",
        "enterprise",
        "frameworks",
        "api",
        "---Community---",
        "showcase",
        "community",
        "...",
      ],
    },
    modules: {
      title: "Modules",
      defaultOpen: true,
      pages: [
        "core",
        "---Authentication---",
        "session",
        "stateless",
        "---Optional modules---",
        "notification",
        "passkeys",
        "twofactor",
        "oauth",
        "admin",
        "audit",
        "captcha",
        "ratelimit",
        "csrf",
        "magiclink",
        "invitation",
        "organization",
        "...",
      ],
    },
    frameworks: { title: "Frameworks", pages: ["gin", "..."] },
    api: {
      title: "API Reference",
      defaultOpen: true,
      pages: ["api-auth", "endpoints", "errors", "models", "..."],
    },
  };
  for (const [dir, meta] of Object.entries(navigation)) {
    const output = join(root, "content/docs", dir, "meta.json");
    outputs.add(output);
    write(output, JSON.stringify(meta, null, 2));
  }
  // Delete only stale files in the generated directory (e.g. a renamed article).
  for (const output of files(join(root, "content")))
    if (!outputs.has(output) && /\.(mdx?|json)$/.test(output))
      unlinkSync(output);
  console.log(
    `Synced ${records.filter((p) => p.kind === "docs").length} guides, ${records.filter((p) => p.kind === "blog").length} posts, and standalone pages.`,
  );
  return records;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) syncContent();
