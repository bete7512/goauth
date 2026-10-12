// Smoke-check the production server: npm run build && npm start, then npm run check.
import assert from "node:assert/strict";
import { syncContent } from "./sync-content.mjs";
import { indexable, siteUrl } from "../lib/site.mjs";

const base = process.env.CHECK_URL || "http://localhost:3000";
const records = syncContent();
const cache = new Map();
const decode = (text) =>
  text.replace(
    /&(?:amp|lt|gt|quot|apos|#x27|#39|#x([\da-f]+)|#(\d+));/gi,
    (entity, hex, decimal) =>
      hex
        ? String.fromCodePoint(parseInt(hex, 16))
        : decimal
          ? String.fromCodePoint(Number(decimal))
          : ({
              "&amp;": "&",
              "&lt;": "<",
              "&gt;": ">",
              "&quot;": '"',
              "&apos;": "'",
              "&#x27;": "'",
              "&#39;": "'",
            }[entity] ?? entity),
  );
async function get(path) {
  if (!cache.has(path))
    cache.set(
      path,
      (async () => {
        const response = await fetch(`${base}${path}`);
        assert.equal(response.status, 200, `${path}: HTTP ${response.status}`);
        return response.text();
      })(),
    );
  return cache.get(path);
}

const pagePaths = ["/", "/blog", ...records.map((record) => record.url)];
const links = [];
let codeBlocks = 0;
let diagrams = 0;
for (const path of pagePaths) {
  const html = await get(path);
  assert.equal(
    (html.match(/<h1(?:\s|>)/g) ?? []).length,
    1,
    `${path}: expected one H1`,
  );
  assert.ok(html.includes('<html lang="en"'), `${path}: missing language`);
  if (path !== "/markdown-page") {
    assert.ok(
      html.includes(
        `rel="canonical" href="${siteUrl}${path === "/" ? "" : path}"`,
      ),
      `${path}: wrong canonical`,
    );
    assert.match(
      html,
      /<meta name="description" content="[^"]+"/,
      `${path}: missing description`,
    );
    assert.match(
      html,
      /<meta property="og:image" content="[^\"]+"/,
      `${path}: missing social image`,
    );
    assert.ok(
      html.includes(
        `name="robots" content="${indexable ? "index" : "noindex"}, follow"`,
      ),
      `${path}: incorrect indexing policy`,
    );
  }
  const record = records.find((record) => record.url === path);
  if (record) {
    const charts = [
      ...record.content.matchAll(/^```mermaid\n([\s\S]*?)^```/gm),
    ];
    const figures = [
      ...html.matchAll(
        /<figure\b[^>]*data-mermaid-diagram[^>]*>([\s\S]*?)<\/figure>/g,
      ),
    ];
    assert.equal(
      figures.length,
      charts.length,
      `${path}: missing rendered Mermaid diagrams`,
    );
    const svgIds = new Set();
    for (const [index, figure] of figures.entries()) {
      assert.match(
        figure[1],
        /<svg\b[^>]*role="img"/,
        `${path}: diagram ${index + 1} has no accessible SVG`,
      );
      assert.match(
        figure[1],
        /<(?:polyline|path|line)\b/,
        `${path}: diagram ${index + 1} has no connections`,
      );
      assert.ok(
        !figure[1].includes("fonts.googleapis.com"),
        `${path}: diagram depends on external fonts`,
      );
      for (const match of figure[1].matchAll(/\sid="([^"]+)"/g)) {
        assert.ok(
          !svgIds.has(match[1]),
          `${path}: duplicate SVG ID ${match[1]}`,
        );
        svgIds.add(match[1]);
      }
      diagrams++;
    }
    if (charts.length) {
      const markdown = await get(`/llms.mdx${path}/content.md`);
      for (const chart of charts) {
        assert.ok(
          markdown.includes(chart[1].trim()),
          `${path}: diagram source lost in Markdown export`,
        );
      }
    }
    const details = (record.content.match(/^<details>/gm) ?? []).length;
    if (details)
      assert.equal(
        (html.match(/<details(?:\s|>)/g) ?? []).length,
        details,
        `${path}: endpoint disclosures were lost`,
      );
    const rendered = [...html.matchAll(/<pre\b[^>]*>([\s\S]*?)<\/pre>/g)].map(
      (match) => decode(match[1].replace(/<[^>]*>/g, "")).trim(),
    );
    for (const match of record.content.matchAll(
      /^```[^\n]*\n([\s\S]*?)^```/gm,
    )) {
      assert.ok(
        rendered.includes(match[1].trim()),
        `${path}: code sample changed: ${match[1].slice(0, 80)}`,
      );
      codeBlocks++;
    }
  }
  for (const match of html.matchAll(/href="([^\"]+)"/g)) {
    const href = decode(match[1]);
    if (!href.startsWith("/") && !href.startsWith("#")) continue;
    if (
      href.startsWith("/_next/") ||
      href.startsWith("//") ||
      href.endsWith(".svg")
    )
      continue;
    links.push({ from: path, url: new URL(href, `${base}${path}`) });
  }
  assert.ok(!html.includes(":::info"), `${path}: unrendered callout`);
  assert.ok(!html.includes("@theme/Tabs"), `${path}: leaked Docusaurus import`);
}
for (const { from, url } of links) {
  const html = await get(url.pathname);
  if (url.hash)
    assert.ok(
      html.includes(`id="${decodeURIComponent(url.hash.slice(1))}"`),
      `${from}: missing anchor ${url.pathname}${url.hash}`,
    );
}
const robots = await get("/robots.txt");
const sitemap = await get("/sitemap.xml");
assert.ok(
  robots.includes(indexable ? "Allow: /" : "Disallow: /"),
  "Wrong robots rule",
);
if (indexable) {
  assert.ok(robots.includes(`Sitemap: ${siteUrl}/sitemap.xml`));
  for (const path of pagePaths.filter((path) => path !== "/markdown-page"))
    assert.ok(
      sitemap.includes(`<loc>${siteUrl}${path === "/" ? "" : path}</loc>`),
      `${path}: missing from sitemap`,
    );
} else
  assert.ok(
    !sitemap.includes("<loc>"),
    "Unconfigured preview should not publish a sitemap",
  );
for (const [old, target] of [
  ["/docs/api/auth", "/docs/api/api-auth"],
  ["/docs/index", "/docs"],
]) {
  const response = await fetch(`${base}${old}`, { redirect: "manual" });
  assert.equal(response.status, 308, `${old}: missing permanent redirect`);
  assert.equal(
    new URL(response.headers.get("location"), base).pathname,
    target,
  );
}
for (const path of [
  "/docs/does-not-exist",
  "/blog/does-not-exist",
  "/blog/tags/does-not-exist",
]) {
  const response = await fetch(`${base}${path}`);
  assert.equal(response.status, 404, `${path}: expected 404`);
}
const search = JSON.parse(await get("/api/search?query=session"));
assert.ok(
  Array.isArray(search) &&
    search.some((entry) => entry.url?.includes("/docs/")),
  "Search returned no documentation results",
);
assert.ok((await get("/llms.txt")).includes(`${siteUrl}/docs/quickstart`));
assert.ok(
  (await get("/llms.mdx/docs/quickstart/content.md")).startsWith(
    "# Quick Start",
  ),
);
assert.ok((await get("/llms-full.txt")).includes("# API Endpoints"));
const image = await fetch(`${base}/og/image.png?title=GoAuth`);
assert.equal(image.status, 200);
assert.match(image.headers.get("content-type"), /image\/png/);
assert.ok(
  (await image.arrayBuffer()).byteLength > 1000,
  "Empty social preview",
);
console.log(
  `Verified ${pagePaths.length} content pages, ${codeBlocks} unchanged code samples, ${diagrams} server-rendered diagrams, ${links.length} internal links, SEO, redirects, 404s, search, and social images.`,
);
