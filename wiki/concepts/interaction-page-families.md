---
type: concept
title: "The two interaction page families"
tags: [architecture, contract, gotcha]
sources: [oauth-server-codebase]
created: 2026-08-04
updated: 2026-08-05
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

The login page joined the list of pages this matters for when federation gave it `passwordLogin` and
`providers`: buttons rendered from the bucket but absent from the props would appear and then vanish.

**And a page in this family cannot be rendered at a URL outside its own route.** `loginClient.tsx` derives
both the page name and the interaction id from `window.location.pathname`, so a login document served at
`/federation/callback` hydrates into an empty root. That is why a declined federated sign-in *redirects* to
the login path carrying a notice identifier rather than rendering the login page where it stands — see
[[upstream-federation]].

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

## zeroRuntime does not reach zero

The antd shell links a precompiled `antd.css`/`reset.css` and sets `theme={{ zeroRuntime: true }}`
(`lib/html/zeroRuntime.tsx`) instead of letting antd's cssinjs generate ~246 KB of CSS at runtime. That
flag genuinely eliminates the bulk of it — but not all of it, and not because of a misconfiguration.

`zeroRuntime` only gates `genComponentStyleHook` in `@ant-design/cssinjs-utils` (the hashed per-component
rule sets antd.css now supplies). A second, separate hook in the same module, `genCSSVarRegister`, injects
the small `--ant-xxx` custom-property block every cssVar-mode component needs its classes to resolve — and
it calls `useCSSVarRegister` **unconditionally**; it never reads `zeroRuntime` at all
(`node_modules/@ant-design/cssinjs-utils/es/util/genStyleUtils.js:62-97` versus the check at `:120-125` of
the same file, which exists only in `genComponentStyleHook`). Measured floor on `/admin`: 7
`style[data-css-hash]` tags, 17,540 B, injected after hydration regardless.

Two fixes were tried and both are dead ends, not just untried:

- **Pinning `cssVar.key`** (`theme.cssVar.key`) only renames the scope class the runtime writes on
  elements. Confirmed empirically in a live hydration check: the tag count and byte count were unchanged
  whether the key was left to default (`useId`) or pinned to an arbitrary literal. The antd.css shipped by
  the npm package already contains matching-looking scope classes (`_R_0_`, `_R_29f_`, `_R_39f_`) purely
  by useId coincidence — they are never actually read, since the runtime always injects its own live copy
  under whatever key is active, and styling was correct even under a deliberately non-matching key.
- **`StyleProvider`'s `layer` prop** feeds `!!layer` into `memoIconContextValue.zeroRuntime` in
  `node_modules/antd/es/config-provider/index.js:338-346` — a value consumed only by `IconStyle`
  (`@ant-design/icons`' own, unrelated style-injection mechanism). It is never read anywhere near
  `genCSSVarRegister`. Adopting `layer` would also require re-linking `antd.css` under a CSS `@layer`
  for no effect on this floor.

No theme prop in antd 6.5.1 suppresses `genCSSVarRegister`. The floor scales with the distinct
cssVar-participating components a given page actually mounts (Typography, Input, Form, Button, Card on
`/admin`), so it is not identical across pages, but it is never zero for a page that renders form
controls.

## Related

- [[html-response-security-policy]] — the one constructor every page here goes through, and the origin of
  the rendered-error status rule.
- [[self-service-password-reset]] — the plain family's other user, and the feature that made the login
  page's "Forgot password" link real (which is why backlog § 17's request to delete it was refused).
- [[rich-authorization-requests]] — supplied the consent page's rich-detail group; § 021 gave every group
  a heading and stopped printing a token whose label is the token.
- [[feature-flag-gating]] — the other place a deployment's configuration decides what an end user is
  allowed to reach.
- [[upstream-federation]] — added the login page's provider controls (plain anchors, so the policy is
  unchanged), the `federation_aborted` notice, and the terminal pages for every federated refusal.
