# Writing an article

One file in this directory is one article. Its filename is its URL:
`what-dpop-protects-you-from.mdx` is published at
`https://foxauth.dev/blog/what-dpop-protects-you-from/`.

Nothing else is edited to publish. The page, the index entry, the sitemap entry with its date, the
social card, the plain-text alternate, the entry in `llms.txt` and the feed item are all derived
from this one file.

## Front matter

```yaml
---
title: What DPoP actually protects you from
description: >-
  A bearer token works for whoever holds it, including whoever stole it. DPoP binds it to a
  key the client keeps — here is what that buys, and what it does not.
publishedAt: '2026-09-18' # quoted, or YAML reads it as a date object
updatedAt: '2026-11-02' # optional; only when the article is really revised
draft: false # optional, defaults false
tags: [dpop, tokens, security] # optional; shown on the article, no page per tag
storageScope: PostgreSQL # optional; only for a backend-specific article
---
```

`title` and `description` are the two that need care, because the build enforces them:

- The rendered `<title>` is `<your title> — FoxAuth` and must land in **15–60 characters**, so the
  title you write has roughly 5–50 to play with. Write the claim, not the topic.
- `description` must be **70–160 characters** and unique across the whole site. It is the snippet
  under the title in a search result. If it could be pasted onto another article unchanged, it is
  too vague to earn the slot.

You never write an author (articles are published by FoxAuth), a slug (the filename is the slug), a
cover image (no binaries live in this repository; the card is generated), or any of the tags,
canonical URLs and structured data the site derives.

## Checking your work

```sh
cd website
bun run check
SITE_SKIP_CAPTURE=1 bun run build
```

If it builds, it ships correctly. Every failure names the article and the rule — the length bands,
duplicate titles, a skipped heading level, an image with no alternative text, a broken internal
link, or a sentence claiming something about the product that is no longer true.

## `storageScope`

Set it only when the article really is about running on one backend. It exempts the article's prose
from the rule that fails any marketing sentence naming one datastore and omitting another — and it
pays for that exemption by printing a line telling the reader the article is scoped.

If that rule fires on an article that is _not_ backend-specific, the sentence is the bug: it is
claiming something about where the server stores data that stopped being true when the second
backend shipped. Fix the sentence, do not reach for the flag.

## Withdrawing an article

Deleting a published file 404s a URL that search engines and other people's links already point at,
and nothing in the build will tell you. So deleting is not the default — choose one:

1. **Keep it and retract it.** Add a short note at the top saying what turned out to be wrong and
   what is true now, and link to the replacement. This is right when somebody might still arrive
   from a search result or a link, which is almost always.
2. **Redirect it.** If the article is genuinely replaced by another page, add a redirect from the
   old path to that page so the link keeps working.

Setting `draft: true` on a published article is the same as deleting it, with the same consequence:
the URL stops existing. It is for articles that were never published, not for retiring one that
was.

Renaming a file after publication changes a live URL and has exactly the same problem.
