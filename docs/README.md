# GoAuth documentation

Next.js + Fumadocs documentation, ported from the Pulse docs site. The original
GoAuth Markdown guides and blog posts remain the source of truth.

## Development

Use Node.js 22 or later (`nvm use` reads `.nvmrc`).

```bash
cd docs
npm ci
npm run dev
```

Open http://localhost:3000. `./start-docs.sh` is also available. The dev server
watches the original Markdown files and regenerates content automatically.

## Content

- `docs/`: existing guides, modules, framework integration, and API reference.
- `blog/`: existing blog posts, preserving their slugs, dates, tags, and author.
- `standalone/markdown-page.md`: preserved standalone example page (noindex).
- `app/`, `components/`, `lib/`: presentation, routes, search, and metadata.
- `scripts/sync-content.mjs`: adapts frontmatter, relative Markdown links, headings,
  and Docusaurus callouts into generated `content/`. Never edit `content/` directly.

Add a guide with `title` frontmatter and optionally a unique `description`. The
sync step automatically includes it. Adjust the navigation in `sync-content.mjs`
when it needs an explicit position. Keep existing `id` and `slug` fields stable:
they preserve public URLs, including `/docs/api/api-auth`.

## Production and SEO

The production origin defaults to **https://goauth.beteg.dev**. Override `SITE_URL`
before building only if the domain changes (HTTPS, no path or query). All canonical
URLs, Open Graph/Twitter images, structured data, robots, sitemap, and `llms.txt`
use this origin.

```bash
npm run check:api
npm run typecheck
npm run build
npm start
# In another terminal (with the same SITE_URL if overridden):
npm run check
```

Set `CHECK_URL` if the running server is not at http://localhost:3000.
`check:api` requires the repository's Go toolchain and SQLite build dependencies.
It compiles the quickstart and module registration examples, compares model
declarations to source, and verifies the endpoint inventory plus authentication
flows using temporary SQLite databases. It makes no provider network calls.
The smoke check verifies all content routes, authored code samples, internal
links and anchors, metadata, sitemap, robots, redirects, search, and social images.
It also checks that every Mermaid block produces an accessible SVG and retains
its original source in the page and Markdown exports.

Development mode and Vercel preview builds emit `noindex`, disallow crawling,
and publish an empty sitemap. Rebuild when changing the public origin or moving
from preview to production.

Deploy `docs/` as a Next.js application (build: `npm run build`; start:
`npm start`; Node 22+). The generated `.next` output requires a Next.js runtime;
it is not the former Docusaurus static `build/` directory. No deployment runs as
part of local development. `npm` and `package-lock.json` are the supported install
path.

On Vercel, set the project's Root Directory to `docs`. The `vercel.json` in this
directory selects the Next.js framework, runs `npm run build`, and sets the output
directory to `.next`, overriding any previous Docusaurus framework or `build`
output setting. Redeploy after applying this configuration.

The Markdown serializer is pinned to `2.1.2` because newer versions trigger
[a Fumadocs stringifier regression](https://github.com/fuma-nama/fumadocs/issues/3604)
with the reference site's Fumadocs version. Recheck the override when upgrading
Fumadocs.

The site includes responsive navigation, a table of contents, local full-text
search, light/dark mode, syntax highlighting, copyable code blocks, and edit links
that point to the original Markdown on GitHub. Guide and blog URLs are preserved. Technical content now tracks the current Go
checkout, including unreleased changes. The upgrade guide identifies changed
contracts. When changing APIs, update examples and run `npm run check:api` from
this directory as well as the website checks.

The homepage has its own layout in `app/(landing)/` with locally hosted Manrope
and IBM Plex Mono fonts. `components/landing/` contains the mobile navigation,
copy controls, and interactive module example. Blog and documentation pages keep
the Fumadocs navigation.

Fenced `mermaid` blocks render on the server through `beautiful-mermaid` (flowcharts,
sequence, state, class, ER, and XY diagrams). The original diagram colors appear
on a light, horizontally scrollable canvas in either site theme. Each diagram
includes a copyable source disclosure. Rendering errors fail the build so broken
diagrams cannot silently ship as code. `lib/remark-mermaid.ts` retains the fenced
source for Markdown/LLM exports.

MIT — see [LICENSE](../LICENSE).
