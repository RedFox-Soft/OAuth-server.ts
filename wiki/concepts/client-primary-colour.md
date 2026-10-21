---
type: concept
title: 'An application’s primary colour on its sign-in pages'
tags: [architecture, contract, gotcha, accessibility, security]
sources: [oauth-server-codebase]
created: 2026-10-19
updated: 2026-10-21
graph:
  node_type: concept
  relationships:
    - predicate: relates_to
      object: concept:consent-screen-decisions
    - predicate: relates_to
      object: concept:end-user-colour-scheme
    - predicate: relates_to
      object: concept:html-response-security-policy
    - predicate: relates_to
      object: concept:client-identity-from-database
---

# An application’s primary colour on its sign-in pages

Since spec 106, an administrator can give an application a primary colour. It works like the spec 094 logo
([[consent-screen-decisions]]). The colour paints the four hydrated pages of a sign-in to that application:

- sign-in;
- registration;
- both two-step pages;
- consent.

On those pages it paints:

- the filled button;
- the selection controls;
- the focus ring;
- the links.

It applies only for the organization's own people, in both colour schemes, and moves only as far as WCAG AA requires.

## Stored on the record, set only by an administrator

- **A base key.** `primaryColor` is a base key on the client record (`lib/configs/clientSchema.ts:190`,
  `lib/models/client/wire.ts:79`), next to `bucketId` and `corsOrigins`.
- **Not a separate area.** The logo lives in an area of its own (`ClientLogo`) because it is up to 87 KB, and
  the record is read on every resolution. A colour is seven characters.
- **What keeps registration out.** `translate` drops a canonical-only key from wire input. So dynamic
  registration, registration management and a metadata document can never carry it. If you remove that drop,
  `test/registration_management/internal_keys.spec.ts` and `test/cimd/internal_keys.spec.ts` fail.
- **The base-key list also lets the colour through validation.** `validate.ts` copies only base keys from a
  record. Without the entry, an administrator's colour would silently reach no client.
- **The admin surface.** It is edited with the existing client create and update routes:
  - `primaryColor` sets it, and `null` removes it;
  - the schema allows up to 32 characters (`lib/admin/clients/schema.ts:40`), and the service requires
    `#rrggbb` (`service.ts:231`), so a refusal names the accepted form;
  - MCP takes the same body schemas;
  - the audit trail records the field name, never its value.
- **Read back strictly.** A stored value that fails `#rrggbb` reads as no colour (`readPrimaryColor`,
  `lib/html/theme/accent.ts:225`), the way `readLogo` treats a logo.

## One decision per sign-in, from facts

`brandingFor` (`lib/interactions/branding.ts:33`) decides whether an application may look like itself on
this sign-in. It shows its colour on every page and its logo on the consent page only when all three facts
hold:

- its provenance tier is `this-organization`;
- the interaction is not a device flow (`payload.deviceCode`);
- not all of its redirect URIs are loopback.

It decides once, from facts, never from which warning a page happens to show:

- Sign-in and two-step pages show no warnings at all. A test on the shown warning would let them through
  while the consent page of the same sign-in refused.
- On the consent page, the administrator-rights warning outranks the device and own-device warnings. The 094
  gate tested the shown warning, so a device's consent page asking for the admin MCP displayed the logo.
  Spec 106 moved the logo onto this decision (`consentView.ts:678`, `lib/interactions/index.ts:727`);
  `test/client_branding/logo.spec.ts` holds it.

Every render of the sign-in, registration and two-step pages spreads `signInLook(interaction, signsInto)`
(`branding.ts:66`, `index.ts:992`; it was `accentFor` until 2026-10-21). On a POST, the handler's resolved
`bucketId` is the same value as `signsInto`.

## The names on the page (2026-10-21)

`signInLook` also returns a `face`, which `SignInMasthead` (`lib/interactions/signInMasthead.tsx`) draws at the top
of those three pages as the consent page opens: the server's mark beside the project's name, then the heading.

- **The project is always named**, by `shownNameOf` — the display name, else the issuer's host — never the
  console-only `name`. A page without a face (a direct `loginServer` call) names the instance's host.
- **The application is named by this decision, and only by it**, with its logo: "Sign in to Timesheets",
  "Create an account for Timesheets". Otherwise the heading names the account ("Sign in to your Acme account").
  These pages carry no warning that could qualify a name, so anyone could register "Acme Payroll" and have
  the page vouch for it. The name passes `sanitiseClientName` first, as on consent.
- The console's Sign-in tab preview gets the same name from the project detail's `shownName`
  (`lib/admin/buckets/routes.ts:760`): the console cannot compute a project's host without an address.
- `test/client_branding/names.spec.ts` holds it for the four shapes that are never named.

## The nearest legible shade (`paintedAccent`)

The module keeps hue and saturation (HSL) and moves only lightness, as little as the minimums of spec 096
require. It works per scheme. Light uses one value for button and link. Dark uses separate values, because
a link must be lighter than a button that carries a white label.

- **Bisection.** It searches by bisection over continuous lightness, on the one condition that only improves
  in the direction it moves. Too light for a white label, it goes darker. Too dark to stand out from the page,
  it goes lighter.
- **Then a check, then a fallback.** Everything is checked after the search. A fine scan for the nearest
  passing lightness takes over if the bisection's premise fails (`bisect`/`scan`, `accent.ts:107`, `:127`).
- **Why bisection.** The dark window is only 5–18 % of lightness wide, so a coarse sweep steps over it.

### Gotcha: antd re-derives `colorPrimary` and `colorLink` in the dark scheme

Under `theme.darkAlgorithm`, a `colorPrimary` or `colorLink` given in the token config is a seed, not a
value. antd paints step 6 of `generate(seed, { theme: 'dark' })`
(`antd/es/theme/themes/shared/genColorMapToken.js`), and the config cannot override that. For example, seed
`#2f7d32` is painted `#2b6d2e`. Hover and active are honoured as given.

So the dark search runs over the seed and judges what antd will paint (`darkPrimaryOf`, `accent.ts:95`;
`darkSeed`, `:159`). `dark.seed` and `dark.linkSeed` go to antd; `dark.primary` and `dark.link` are what
people see. Even antd's own default blue (`#1677ff`) is painted `#1668dc` in dark.

**The `@ant-design/colors` shortcut.** Calling `generate` directly costs microseconds;
`theme.getDesignToken` costs 1.1 ms, too slow for a bisection on the request path. `@ant-design/colors` is
therefore a direct dependency at antd's pinned range.

**The drift guard.** In `test/client_branding/accent.spec.ts`, the *is what antd paints* cases compare the
shortcut with `getDesignToken`. They are what caught the link re-derivation during implementation.

### `adjusted` flags the light colour only

`adjusted` is true when the light colour moved (`accent.ts:202`). The dark value always differs from the
input, so flagging it would flag every colour. The console and `paintedPrimaryColor` show the dark value
without flagging it.

## Getting it onto the page

- **The theme.** `EndUserTheme` takes `accent` and overlays `accentTokens(scheme, accent)` on
  `LIGHT_TOKENS`/`DARK_TOKENS`. In dark it also replaces `colorLinkActive`, which `DARK_TOKENS` sets to a blue.
- **The served page.** The light `--ant-*` block is per request already. The page also carries one extra
  `<style>` for `--fox-link` after the theme head (`accentStyle`, `serverRender.tsx:69`). `themeHead()` stays
  a constant.
- **Hydration.** `accent` travels in `window.PROPS` (`serverRender.tsx:72`) and into `EndUserTheme` in
  `clientRoot.tsx:35`.
  - The markup is identical without it, because antd 6's class hash ignores token values. Yet cssinjs
    re-injects its own light custom properties on hydration, which would put the default blue back after
    load, in the browser only.
  - `test/dark_theme/hydration.spec.ts` renders the client tree under a cssinjs cache and compares
    `--ant-color-primary`. A markup-only comparison cannot see this.
- **Dark-block memo key.** The memo in `dark.tsx` is keyed by the dark seeds as well as the selector set
  (`dark.tsx:53`). The selectors alone are the same whatever the token values. Without the seeds in the key,
  the first coloured page's dark block was served to every later page with the same components; that is what
  `test/client_branding/dark_memo.spec.ts` holds.
- **Dark-block memo bound.** The memo is bounded at 256 entries (`DARK_BLOCK_LIMIT`), and `paintedAccent`'s
  memo at 512, because the colours are operator-controlled.

## Why the per-request block needs no hash

The hydrated pages already serve `style-src-elem 'unsafe-inline'`, because they load a script
([[html-response-security-policy]]). So the accent block needs no CSP change, and also has no hash backstop.

What stands between a stored value and the page's CSS is validation, twice:

- on write, `#rrggbb`;
- on read, `readPrimaryColor`.

On top of that, every value written into a `<style>` or the token config comes from `paintedAccent`'s own
formatter, never from the stored string. `test/client_branding/pages.spec.ts` stores
`#2f7d32;}body{x:y` straight onto a record and checks that it reaches no page.
