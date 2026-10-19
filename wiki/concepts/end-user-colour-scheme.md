---
type: concept
title: 'End-user pages follow the device colour scheme'
tags: [architecture, contract, gotcha, accessibility]
sources: [oauth-server-codebase]
created: 2026-10-13
updated: 2026-10-19
graph:
  node_type: concept
  relationships:
    - predicate: relates_to
      object: concept:interaction-page-families
    - predicate: relates_to
      object: concept:html-response-security-policy
    - predicate: relates_to
      object: concept:consent-screen-decisions
---

# End-user pages follow the device colour scheme

Since spec 096, every page an end user sees is dark when the device prefers dark and light otherwise. That
covers all three families: the hydrated antd shell, the server-rendered terminal pages and the plain
script-free pages ([[interaction-page-families]]). The browser picks the scheme from
`prefers-color-scheme`.

There is no switch, no cookie, no script and no setting. The owner decided this, so a person is never thrown
from a dark page into a white one, and nothing reads the preference on the server. The admin console is
deliberately left out: it keeps `lib/html/zeroRuntime.tsx` and none of what follows.

## Two mechanisms

1. **A palette of `--fox-*` custom properties** covers every colour a page sets itself.
   - `FOX_PALETTE` (`lib/html/theme/palette.ts:27`) gives each role a light and a dark value.
   - `themeHead()` declares them once with a dark `@media` override, plus `<meta name="color-scheme">`
     (`lib/html/theme/head.ts:19`).
   - A page writes `foxVar(role)` (`palette.ts:162`), never a colour.
   - The server and the client therefore serialize the same `var(…)` text, so the scheme is invisible to
     hydration.
   - The `body` rule and the mark rule sit inside the dark block only, so a light page renders exactly as it
     did before.
2. **A dark block for antd.** `antd.css` reads every colour from `--ant-*` custom properties.
   - With the scope key pinned (`CSS_VAR_KEY = 'fox'`, `lib/html/theme/tokens.ts:8`), antd's light and dark
     extracted CSS are byte-identical except for those values.
   - `darkOverrides` renders the page's own tree a second time under `theme.darkAlgorithm` and keeps only the
     `--ant-*` declarations (`lib/html/theme/dark.tsx:41`).
   - The result is memoized by the set of light selectors and, since spec 106, the application's colour (see Gotchas).

## Gotchas

- **`:root ` on every dark selector** (`dark.tsx:65`). On a hydrated page cssinjs may append its own light
  block after the dark one. At equal specificity the later block wins, so one extra pseudo-class keeps the
  dark values in force whatever the order.
- **The hydrated pages now inline their antd custom properties.**
  - Before spec 096, their HTML carried no `--ant-*` definitions at all. Every `var(--ant-…)` in `antd.css`
    was undefined until the bundle ran, and stayed undefined with scripts off.
  - `renderEndUserTree` (`dark.tsx:78`) extracts them on the server for all antd pages, through
    `hydratedPage` (`lib/interactions/serverRender.tsx:36`).
  - A dark block without the light one would sit on a page with nothing to override.
- **One tree, two places.**
  - The server wraps a page in `EndUserTheme` (`lib/html/theme/provider.tsx:17`).
  - The browser hydrates `clientRoot` (`lib/interactions/clientRoot.tsx:15`), the same provider around the
    same page.
  - A disagreement on the key, the tokens or `zeroRuntime` would diverge hydration in the browser only.
    `test/dark_theme/hydration.spec.ts` renders both.
- **An application's colour changes the tokens per page (spec 106, 2026-10-19).**
  - On the four hydrated pages of a sign-in, an application's colour replaces the primary and link tokens and
    the `--fox-link` role ([[client-primary-colour]]).
  - The dark-block memo is now keyed by the colour's dark seeds as well as by the selector set, and is bounded
    at 256 entries (`dark.tsx:30`, `:53`). Before that, the selector set alone was the key, and the first
    coloured page's dark block would have reached every later page with the same components.
  - The colour has to reach `clientRoot` through `window.PROPS` too. The markup is identical without it, but
    cssinjs would put the default blue back after hydration.
  - `themeHead()` is still a constant.

## AA in both schemes, including light

antd's default palette fails WCAG 2.2 AA in light as well as in dark:

| Element | Light | Dark | Needed |
| --- | --- | --- | --- |
| Blue as text and under a white label | 4.1 | — | 4.5 |
| Error red | 3.3 | — | 4.5 |
| Secondary text | 3.4 | — | 4.5 |
| Field border against the field | 1.4 | 1.8 | 3.0 |
| Placeholder | 1.8 | 2.2 | 4.5 |

The repository's own `#8c8c8c` greys and the consent page's amber (`#ad6800`) also fell short. The owner
chose to correct all of it, accepting a visibly darker blue and darker field borders on the light pages.

- **Each scheme has its own token set** (`LIGHT_TOKENS`, `DARK_TOKENS`, `tokens.ts:18`, `:34`). The dark
  algorithm re-derives colours from the seeds, so a light blue fed to it comes out at 2.5:1.
- **`test/dark_theme/palette.spec.ts` holds the values to their minimums.** It checks every palette pair and
  every antd text, on-solid and boundary token, in both schemes. Change the values against that test, not
  against the comment beside them.

## What stays light

- **A client logo** (spec 094) sits on `logo-plate`, which is light in both schemes (`palette.ts:124`). It is
  drawn for a white page, and a dark mark would vanish.
- **The TOTP enrolment QR code** is drawn black on `qr-plate`, white in both schemes (`palette.ts:126`).
  antd draws it in `colorText` by default, which on a dark page inverts the code to light-on-dark, and many
  authenticator apps cannot scan that.
- **Monochrome provider marks** (Apple, GitHub) keep their black `fill`. In dark the class `fox-mark-mono`
  turns them exactly white (`palette.ts:152`), the only other colour their terms allow. The recognised
  provider button takes Google's own dark button colours.

## The policy

- A plain page's `style-src-elem` used to be `'none'`. It is now exactly the hash of the theme block: no
  `'unsafe-inline'`, and no other inline style becomes acceptable ([[html-response-security-policy]]).
- The terminal pages hash one more block.
- The hydrated pages keep the `'unsafe-inline'` their icon injection already needed.

## Related

- [[interaction-page-families]]: the three families the theme spans.
- [[consent-screen-decisions]]: the logo plate and the warning colours.
