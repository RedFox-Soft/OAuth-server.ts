---
type: concept
title: "The two interaction page families"
tags: [architecture, contract, gotcha]
sources: [oauth-server-codebase]
created: 2026-08-04
updated: 2026-08-04
graph:
  node_type: concept
  relationships:
    - predicate: depends_on
      object: subsystem:html-rendering
      source: oauth-server-codebase
      evidence: "export function page(title: string, bodyHtml: string, status = 200): Response { … return htmlResponse(html, { status }); }"
      confidence: high
      status: current
---

# The two interaction page families

Every screen an end user sees during an authorization request belongs to one of exactly two families, and
which one is not a style preference — it decides whether the page needs a client bundle, whether a message
on it survives, and where its document is built.

| | **antd shell** | **plain self-contained** |
|---|---|---|
| Modules | `serverRender.tsx` + `loginPage` / `registration` / `consentPage` | `plainPage.tsx` + `verifyPages` / `resetPages` / `registrationPages` |
| Document | `htmlTeamplate.html`, with `<!--app-title-->`, `<!--app-props-->` and `<!--app-html-->` substituted, plus `/public/loginClient.js` | one template literal, no script of any kind |
| Hydrates | yes — React takes over the DOM | no |
| Reached | inside an interaction, with the `_interaction` cookie | anywhere, including a different browser opened from an email |
| Use for | a page with a form the user works in | a page carrying a message, or one reached without the interaction cookie |

The plain family is **not** a lesser page. Its hand-written inline styles deliberately reproduce the antd
pages — `#f0f2f5` backdrop, white card, `padding:32px`, `border-radius:12px`,
`box-shadow:0 2px 8px rgba(0,0,0,0.1)`, `width:400px` — so a page reached from an inbox, with no bundle
loaded, does not look like a different product.

Both families build their `Response` through `htmlResponse`. That is enforced, not merely conventional:
see [[html-response-security-policy]].

## The hydration contract, and the way it fails

**A page in the antd family must substitute `<!--app-props-->`, and its arm of `loginClient.tsx` must
spread those props into the component.** Both halves, every time.

Violating either half fails **silently, in a browser only**. The server renders the correct page; the
document arrives; then hydration replaces the tree with what the component renders from props it never
received, and server-rendered content vanishes. Nothing logs. No test that reads the server's response body
can see it. The page still "works".

`registrationServer` substituted no props and `loginClient`'s `registration` arm passed only `uid` — from
the page's introduction until spec 021. Harmless while that page had nothing to say, which is exactly why
it survived: the defect was invisible until someone rendered a message into it. If you add a message to a
hydrated page, the props are half the change.

Never put a submitted password, a token, or any request text in a props object: `propsScript` escapes `<`
so a value cannot break out of the script tag, but that is containment, not permission — the object is
serialised into the document.

## A refusal carries its real status

A plain page reporting a refusal answers with a real status — 403, 400, 502, 429 — never 200 with an
apologetic sentence, because a non-browser client reads only the status. `resetFailurePage` is 400,
`resetRateLimitedPage` is 429, `registrationClosedPage` is 403, `registrationSendFailedPage` is 502.

Corollary from the same spec: **the status is behaviour, and replacing a body must not renumber it.** The
three registration refusals were `text/plain` bodies at 403/400/502; they became rendered pages at
403/400/502, and `test/email_verification/link.spec.ts` — which asserts only those statuses — passed
unedited. That is what made the change safe to make.

## Which family a refusal belongs to

The rule that decided spec 021's three cases:

- **A form the user was working in comes back in the antd family.** The password-mismatch re-render must
  carry the address they typed inside a live form, and only the hydrated family can.
- **A terminal message goes plain.** A closed bucket and a failed verification send have no form and no
  next action inside the deployment; an antd page would add a bundle and an inline props script to a page
  with nothing to hydrate.

## Query parameters into a rendered page

The login page takes a `notice` identifier and resolves it through a closed, server-owned vocabulary
(`lib/interactions/notices.ts`). Two properties are deliberate:

1. **An identifier selects a message; it never supplies one.** A login page that renders text from its own
   query string is a phishing surface.
2. **The schema is `t.Optional(t.String())`, not a literal union.** A union answers 422 for an unknown
   value, and the values that arrive unknown are stale bookmarks and old email links — they must render the
   ordinary page.

The `?notice=verify` redirect existed, unread, from the day registration was written: the producer used a
string literal and no consumer was ever added. Producer and consumer now share `NOTICE_VERIFY` through
`buildUILoginPath(uid, notice?)`, which is the actual fix — the message is the symptom.

## Related

- [[html-response-security-policy]] — the one constructor every page here goes through, and the origin of
  the rendered-error status rule.
- [[self-service-password-reset]] — the plain family's other user, and the feature that made the login
  page's "Forgot password" link real (which is why backlog § 17's request to delete it was refused).
- [[rich-authorization-requests]] — supplied the consent page's rich-detail group; § 021 gave every group
  a heading and stopped printing a token whose label is the token.
- [[feature-flag-gating]] — the other place a deployment's configuration decides what an end user is
  allowed to reach.
