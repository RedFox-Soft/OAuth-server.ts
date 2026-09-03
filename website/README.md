# foxauth.dev

The public site for OAuth-server.ts: marketing pages plus Starlight documentation under `/docs`. It
is a separate, source-available Astro project — its own `package.json` and lockfile, no Bun
workspace — that treats the repository root as its data source. See the "The website" section in the
root [`AGENTS.md`](../AGENTS.md) for how the two are wired together.

## Prerequisites

- [Bun](https://bun.sh/), and a `bun install` run **at the repository root** (the site's generator
  scripts import from `lib/`).
- `bun install` inside `website/` as well, for the site's own dependencies.
- `bunx playwright install chromium`, once, for the screenshot/OG capture script.

## Developing

```bash
bun run generate   # writes website/generated/ from the root repo; run before dev, and after it changes
bun run dev        # serves whatever is currently in generated/
```

`bun run dev` does not regenerate anything itself — rerun `bun run generate` after changing a setting
catalog, a route classification, or anything else the export reads.

## Building

```bash
SITE_SKIP_CAPTURE=1 bun run build   # fast local build: skips screenshots and OG images
bun run build                       # full build: also runs scripts/capture.ts (needs chromium)
```

## Checking

```bash
bun run check   # astro check; the site has no test suite by decision
```

There is no `website` step in the root `bun test` run — the two are independent.

## Configuration

Copy `.env.example` to `.env` and fill in what you need. Every variable is optional: with none set,
forms fall back to a `mailto:` link and no analytics script is emitted.

## Where content lives

- Hand-written docs: `src/content/docs/docs/<section>/*.mdx` (Starlight autogenerates the sidebar per
  section; order pages with `sidebar.order` in frontmatter).
- Comparison pages: `src/content/compare/*.mdx`.
- Everything else (home, features, pricing, changelog, …): `src/pages/*.astro`.
- Reference docs are generated, never hand-written: they render from `generated/docs-export.json`
  (produced by `bun run generate`) through the schema in `src/data/export.ts`. To change what they
  say, change the source in the root repo — `lib/admin/settings/catalog.ts` for settings,
  `lib/consts/route_classification.ts` for routes — and regenerate.

Nothing generated is committed: `generated/`, `public/screenshots/` and `public/og/` are gitignored,
and `/changelog/`, `/security/` and `/license/` read `CHANGELOG.md`, `SECURITY.md`, `LICENSE` and
`NOTICE` from the repository root at build time rather than copying them in.
