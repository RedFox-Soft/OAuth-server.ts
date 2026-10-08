---
type: concept
title: 'Site translations: who sees Russian and Chinese, and how the build keeps them honest'
tags: [architecture, gotcha]
sources: [oauth-server-codebase]
created: 2026-10-08
updated: 2026-10-08
---

# Site translations: who sees Russian and Chinese, and how the build keeps them honest

foxauth.dev (`website/`) publishes Russian under `/ru/` and Simplified Chinese under `/zh-cn/` for the
marketing pages, the docs landing page and "Get started", and the whole blog. English is unprefixed and is the
site; nobody whose browser does not put Russian or Simplified Chinese **first** is ever shown another language.
The server's own screens (sign-in, consent, the console) are not translated. Spec 074.

## The first-language rule, and why it needs a script

Eligibility is the first entry of the browser's language list only: `ru`/`ru-*`, or `zh`, `zh-cn`, `zh-sg`,
`zh-hans`, `zh-hans-*` (`website/src/data/seo.ts:52`). Traditional Chinese is deliberately not eligible — the
translation is in the wrong script for it. Russian second in the list means English, untouched.

The site is static files on GitHub Pages, which cannot read `Accept-Language`, so an inline script at the end of
`<head>` decides (`website/src/i18n/language-script.ts:34`). That is the one exception to "no client JavaScript on
the marketing pages" (`website/src/components/Header.astro:10`); with scripts off every page is what its address
says and English pages are exactly the pre-translation site. Things that are easy to get wrong:

- **It redirects to the page's own `hreflang` link**, so it can never send a reader to a page that does not exist,
  and it navigates to the **path** of that link (`language-script.ts:79`) — the `hreflang` URL is absolute on the
  canonical origin, and following it verbatim sent every preview and staging reader to production.
- **It never redirects on a translated page** (an address someone opened is the page they get) **or for a
  crawler** (user agent only, `language-script.ts:104` — `navigator.webdriver` was dropped because it marks every
  automated browser, including the ones that verify this feature, without being a crawler).
- **A reader who just came from this page's translation is not sent back** (`language-script.ts:72`), whether or
  not storage could remember the choice. Without it, "switch to English" was undone instantly whenever
  `localStorage` was blocked.
- The remembered choice is stored as `<chosen>@<eligible>`, so a choice of English made while Russian came first
  stops applying if the browser later puts Chinese first.

## What is translated, and what a fallback is

A Russian reader in the docs who follows a link to Deploy, Administer or Security gets Starlight's **fallback
page**: the English body under Russian navigation. Starlight indexes fallbacks and declares every language as an
alternate on every docs page, translated or not; `website/src/route-middleware.ts:32` makes a fallback `noindex`
with no alternates, and prunes every other page's alternates to the languages it exists in, so the generated
Reference pages declare none. `isDocsFallback` (`website/src/data/seo.ts:121`) is the one definition the sitemap
filter and the verifier share.

English-only pages outside the docs (changelog, comparison articles, Reference) keep one English address; an
eligible reader sees an "only in English" notice **in the header**, never in `<main>`, so it never becomes part of
the text the verifier or a search engine reads as the page.

## One release, no switch

Both languages reach `main` together or neither does. There is no per-language flag: `LOCALES`
(`website/src/data/seo.ts:86`) lists the languages the build publishes, and while a language is being translated its
directories are left out of the docs and blog collections entirely (`website/src/content.config.ts:20`) — otherwise
half-finished Russian docs are published as English pages under `/ru/`, and their links fail the link validator.
The blog's single publication path holds a post back in **every** language until all its translations exist
(`website/src/data/blog.ts:148`).

## Freshness: hashes, not git dates

A translation records `source`, the first 12 hex digits of SHA-256 over its English file with CRLF normalised to LF
(`website/src/i18n/source-hash.ts:28`). A stale translation shows "the English version is newer" and is listed by
`bun run seo`; it warns and never fails, like an aged comparison. Hashes rather than commit dates because they work
on a shallow checkout and do not mark everything stale after a rename or a CRLF round-trip. `bun run i18n:stamp`
records a new hash after re-translating — never to silence the warning. It quotes an all-digit hash, which YAML
would otherwise read as a number and the schema reject.

## The build checks that know about languages

- `missing-lang` asserts `<html lang>` is the route's language, not merely present.
- Chinese has its own title/description bands (8–30 / 30–80, `seo.ts:77`): `.length` counts a Han character as one,
  but it takes two Latin widths in a result snippet.
- `counterpart-anchor` (`website/scripts/seo/verify.ts:216`) fails when an English heading id is missing on a
  translation. Translated `.mdx` headings carry the English id explicitly — `## Первый токен {#first-token}` —
  which Sätteri parses natively once `headingAttributes` is on (`website/astro.config.mjs:51`); no remark plugin.
- `stale-datastore-claim` splits Chinese sentences on `。！？；`, and the datastore names stay literal in every
  language so the check still sees them.

## Typography

Inter has no Han glyphs; `:lang(zh-CN)` (`website/src/styles/global.css:226`) names the Simplified system faces
before `system-ui` — otherwise Windows picks Japanese glyph forms — and turns off Latin letter-spacing and
upper-casing. No Han webfont ships to readers. Buttons use `word-break: keep-all` (`website/src/components/ui/Button.astro:18`):
Han text otherwise breaks between any two characters, which wrapped 快速开始 onto two lines in the header at
360 px, while `nowrap` instead pushed a long Russian label off the screen.
