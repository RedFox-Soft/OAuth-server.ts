# foxauth.dev

The public site for OAuth-server.ts: marketing pages plus Starlight documentation under `/docs`. It
is a separate, source-available Astro project — its own `package.json` and lockfile, no Bun
workspace — that treats the repository root as its data source. `.github/workflows/site.yml` builds
and deploys it to GitHub Pages on every push to `main` that touches the site or its inputs.

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

Astro 7's `astro dev` runs as a background daemon: the command returns at once and prints the URL
(`http://localhost:4321/`). `bunx astro dev logs` tails it, `bunx astro dev status` shows it,
`bunx astro dev stop` stops it. The server listens on both `127.0.0.1` and `::1`.

## Building

```bash
SITE_SKIP_CAPTURE=1 bun run build   # fast local build: skips screenshots and OG images
bun run build                       # full build: also runs scripts/capture.ts (needs chromium)
```

The capture boots the server in-process on the in-memory adapter and drives the **hydrated** console with
Playwright, so the root `bun run build` — which produces the gitignored `public/*.js` bundles — must have
run once first, or the capture times out on a blank page. The workflow does this for you. Because it
drives the real admin API and a real sign-in, a server change can break the site build while the root
`bun test` stays green — and a failed deploy is silent, since the published site simply goes stale.

`robots.txt`, both sitemaps, `llms.txt`, the Markdown alternates and the social cards are written into
`dist/` after the build rather than kept in `public/`; `SITE_SKIP_CAPTURE` skips the cards too.

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
  The links validator fails the build on a broken internal link but cannot see links into `src/pages`
  — the Reference pages and the other `src/pages` routes — so a renamed route there must be grepped for
  by hand.
- Comparison pages: `src/content/compare/*.mdx`.
- Everything else (home, features, pricing, changelog, …): `src/pages/*.astro`.
- Reference docs are generated, never hand-written: they render from `generated/docs-export.json`
  (produced by `bun run generate`) through the schema in `src/data/export.ts`. To change what they
  say, change the source in the root repo — `lib/admin/settings/catalog.ts` for settings,
  `lib/consts/route_classification.ts` for routes — and regenerate.

Nothing generated is committed: `generated/`, `public/screenshots/` and `public/og/` are gitignored,
and `/changelog/`, `/security/` and `/license/` read `CHANGELOG.md`, `SECURITY.md`, `LICENSE` and
`NOTICE` from the repository root at build time rather than copying them in.

## How the build keeps the site honest

`scripts/postbuild.ts` runs after `astro build`, parses every emitted page into one `PageRecord`
(`scripts/seo/collect.ts`), and hands that same set to every generator — the image sitemap, `llms.txt`,
the `.md` alternates, the social cards — and then to `scripts/seo/verify.ts`, which fails the build on
any of twenty-two rules, naming the page and the rule. Three things to know before editing anything
here:

- **Every indexing decision lives in `src/data/seo.ts`** — the non-indexable list, the title and
  description bands, the route→section map, the AI-crawler allowlist and `STRUCTURED_COVERAGE`.
  `Seo.astro` and the sitemap filter in `astro.config.mjs` both read it, because they used to disagree:
  a page could say `noindex` while the sitemap advertised it.
- **Docs pages never reach `Seo.astro`.** Starlight builds its own head, so
  `src/components/StarlightHead.astro` adds what it omits.
- **Structured data is checked for being present, not only correct.** `STRUCTURED_COVERAGE` says what
  each kind of page must carry, and a route matching no entry fails as `unclassified-page-type` — added
  after the comparison pages shipped with no article markup past twenty passing rules.

So a new page needs a unique title (15–60 characters) and description (70–160), a section in the map, a
`STRUCTURED_COVERAGE` entry (`requires: []` is fine, but the `reason` is not optional), and a link from
somewhere reachable within three hops of the home page, or the build stops.

### Claims that outlive the code

A twenty-third rule checks something the others do not: whether a page's **claims** still hold. It
exists because PostgreSQL shipped and five comparison tables plus two marketing pages went on saying the
server stores its data in MongoDB — one of them arguing that as a reason to choose a competitor — while
twenty-two rules passed, since none of them reads what a page asserts. Three parts, and the split
matters:

- Copy that can be computed **is** computed, from `docs-export.json` via `src/data/storage.ts`, so it
  cannot drift at all.
- A comparison's own cell is checked in `src/content.config.ts`, at the source — on a comparison page
  the _competitor's_ cell routinely names PostgreSQL, so a check on the rendered page would be satisfied
  by text that says nothing about this server.
- Free prose on `/` and `/features/` is checked **per sentence** by `stale-datastore-claim`, for the same
  reason. It stops at the `/docs/` boundary, where naming one datastore is a procedure, not a claim.

Question sets are data: one array feeds both `FaqSection.astro` and `faqPage()`, so the visible and
machine-readable forms cannot drift, and the overclaim rule proves it. Comparison pages carry
`lastChecked`; past `FRESHNESS_LIMIT_DAYS` the build warns and the page shows a "due for review" notice,
but still passes — staleness is the passage of time, not a mistake to block on.

## Adding a page type: copy the blog

The blog (`src/content/blog/*.mdx`, rendered by `src/pages/blog/`) is the worked example. An author
writes one file and nothing else. `src/data/blog.ts` exports `publishedPosts()`, the **only** path from
the collection to any published surface — the index, the article route and `rss.xml` all call it, so
"a draft appears nowhere" is provable by reading one function rather than three call sites.

Everything else a page type gets, it gets by being **declared**, because `collectPages` walks `dist/`
and knows nothing about where a page came from:

- a section in `SECTION_PREFIXES` / `SECTION_ORDER`;
- two entries in `STRUCTURED_COVERAGE` — the index is not an article, so it needs its own `exact` entry;
- `BlogPosting` in the closed structured-data set, which lives in **four** files: `src/data/seo.ts`,
  `scripts/seo/types.ts`, `scripts/seo/verify.ts` (both the set and `REQUIRED_PROPS`) and
  `scripts/seo/collect.ts`. Miss one of the first three and the build says so. Miss the
  `assertedStringsOf` branch in the fourth and **nothing fails** — the article simply asserts nothing,
  and `structured-overclaim` can never fire for it.

`claimSurface` in `verify.ts` reaches `/blog/` too. An article genuinely about one backend earns its
exemption by declaring `storageScope`, read back from the article's own **rendered** scope line rather
than a list of excused routes, so the excuse rots in public. The feed is the one blog surface outside
the sweep entirely, since `collectPages` reads only `.html`.
