# GoAuth Documentation

Docusaurus-based documentation for GoAuth.

## Development

```bash
npm install
npm start       # Dev server
npm run build   # Production build
npm run serve   # Serve production build
```

## Structure

```
docs/
├── intro.md           # Introduction
├── installation.md    # Installation guide
├── quickstart.md      # Quick start tutorial
├── index.md           # Overview page
├── community.md       # Community & contributing
├── showcase.md        # Examples
├── modules/
│   ├── core.md        # Core module
│   └── notification.md # Notification module
└── api/
    └── endpoints.md   # API reference
```

## Adding Documentation

1. Create a markdown file in the appropriate directory
2. Add frontmatter with `id`, `title`, `sidebar_label`, and `sidebar_position`
3. Update `sidebars.ts` if needed
4. Test locally with `npm start`

## License

MIT — see [LICENSE](../LICENSE)
