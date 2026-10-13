---
type: concept
title: "The two interaction page families"
tags: [architecture, contract, gotcha]
sources: [oauth-server-codebase]
created: 2026-08-04
updated: 2026-10-13
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
pages — the `page` backdrop, the `card`, `padding:32px`, `border-radius:12px`, the `shadow`, a 400 px card —
so a page reached from an inbox, with no bundle loaded, does not look like a different product. Since spec
096 every colour on it, as on the antd pages, is a palette role that follows the device's colour scheme
([[end-user-colour-scheme]]); the page carries one hashed `<style>`, the theme block, and still no script. Since spec 095 the card is fluid up to 400 px inside a 16 px
gutter (`width:100%; max-width:400px`): the fixed `width:400px` scrolled every plain page sideways on a 320 px
phone. A `wide` variant (640 px, top-aligned, left-aligned) serves the end user's connected-apps page — the
first plain page outside any interaction or email, chosen for the family because every step there must work
without JavaScript ([[connected-apps-page]]).

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

**And the props can be right while the page is still wrong.** Spec 052 found a third failure of the same
shape, one floor down: the login POST's refusal path called `loginServer` with an error message and
nothing else, so both the markup *and* the props were rendered from the function's defaults — password
form, no providers. Hydration was blameless; the server had already forgotten what the bucket offered. The
lesson the two halves share is that this page's content is only as good as the options reaching the render
call, and a resolver that exists to prevent drift prevents none of it at a call site that ignores it. See
[[upstream-federation]].

`registrationServer` substituted no props and `loginClient`'s `registration` arm passed only `uid` — from
the page's introduction until spec 021. Harmless while that page had nothing to say, which is exactly why
it survived: the defect was invisible until someone rendered a message into it. If you add a message to a
hydrated page, the props are half the change.

**A value only the server can compute is a prop too.** The login, registration and TOTP components called
`versionedAsset('logo.svg')` themselves. On the server that reads the file's build time from disk
(`lib/html/versionedAsset.ts`) and yields `/public/logo.svg?v=…`. In the browser there is no disk, so it yields
`/public/logo.svg`, and every hydration of those pages logged a mismatch. React keeps the server's attribute,
so nothing looked wrong, and the browser bundle carried a `node:fs` import it could never use. Since the spec
090 follow-up, the render functions in `lib/interactions/serverRender.tsx` compute `logoSrc` once and pass it
to both the markup and `window.PROPS`; the components only receive it. The same rule holds for anything a
component reads from the environment — the clock, the disk, the process.

The consent page follows the rule whole since spec 092. Its props are one view built on the server
(`consentViewFor`, `lib/interactions/index.ts:661`): `logoSrc`, the account's label and id, the client's
provenance tier, and pre-formatted dates such as "keeps access until". The view carries data and the
component words it from one catalog, so hydration reads the same values. `loginClient.tsx` starts from
`emptyConsentView` and spreads the server's props over it. See [[consent-screen-decisions]].

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

Since spec 096 the end-user antd pages (not the console) also **extract these blocks on the server** and
inline them, so the first paint — and a page with scripts off — has antd's colours; before, every
`var(--ant-…)` was undefined until the bundle ran. The key is pinned to `fox` there, not to shrink the floor
(it does not) but because the dark block names the scope class in selectors written once
([[end-user-colour-scheme]]).

No theme prop in antd 6.5.1 suppresses `genCSSVarRegister`. The floor scales with the distinct
cssVar-participating components a given page actually mounts (Typography, Input, Form, Button, Card on
`/admin`), so it is not identical across pages, but it is never zero for a page that renders form
controls.

## Related

- [[end-user-onboarding]] — the verification pages of the plain family, and the bucket flags behind the registration door
- [[html-response-security-policy]] — the one constructor every page here goes through, and the origin of
  the rendered-error status rule.
- [[self-service-password-reset]] — the plain family's other user, and the feature that made the login
  page's "Forgot password" link real (which is why backlog § 17's request to delete it was refused).
- [[rich-authorization-requests]] — supplied the consent page's rich-detail group; § 021 gave every group
  a heading and stopped printing a token whose label is the token. Since spec 092 no token is printed
  beside its label at all: technical names sit in a `<details>` disclosure, and only undescribed items show
  their code in the list ([[consent-screen-decisions]]).
- [[feature-flag-gating]] — the other place a deployment's configuration decides what an end user is
  allowed to reach.
- [[upstream-federation]] — added the login page's provider controls (plain anchors, so the policy is
  unchanged), the `federation_aborted` notice, and the terminal pages for every federated refusal.
