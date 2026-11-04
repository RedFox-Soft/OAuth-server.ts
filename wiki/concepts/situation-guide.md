---
type: concept
title: 'The situation guide: a "What do you need?" page, one declaration, never hidden'
tags: [architecture, contract, gotcha]
sources: [oauth-server-codebase]
created: 2026-11-03
updated: 2026-11-04
graph:
  node_type: concept
  relationships:
    - predicate: relates_to
      object: concept:application-page
    - predicate: relates_to
      object: concept:admin-console-frame
    - predicate: relates_to
      object: concept:feature-flag-gating
    - predicate: relates_to
      object: concept:plans
---

# The situation guide

A page in every project's console (`What do you need?`, route `bucket.guide`, `lib/admin/ui/frame/routes.ts:91`)
that answers "I want X, what do I set up here?" for a person who does not know the protocol's words. It lists
situations ("sign people in to my web app", "let an AI agent call my API", "federate with Okta"), draws the
sequence of what happens, gives an agent prompt, and ends in one button that opens the right page or form. Phase 1
(the console) and phase 2 (the public page at foxauth.dev `/guide/`, in English, Russian and Chinese)
are built from the same data.

## One declaration

Every question, situation, step, diagram lane, prompt and target is plain, import-free data in
`lib/consts/situation_guide.ts` (`GUIDE_QUESTIONS` :171, `GUIDE_SITUATIONS` :320). The console renders it, the
availability function reads it, and the docs export hands the same list to the site (`situationGuide`,
`lib/docs_export/build.ts:321`), so the console and the site cannot drift. The chooser for a new application takes its preset titles and descriptions from the same entries
(`[[application-page]]`).

## Why this shape

Three concepts were mocked up and critiqued on 2026-11-03. Concept A, a gallery of about 13 recipe cards,
explained well but overloaded the page: some 18,000 px of scrolling on a phone. Concept C, an architecture map as the
entry, buried the button in a scrolling panel, could not show the difference between an app with a server and a
single-page app, and depended on hand-placed coordinates. What stayed is concept B, "two questions, answer in
place": two questions, and below them the chosen answer with a sequence diagram of who talks to whom, the one
button, and a prompt for an agent. The Enterprise tab's dashed "Your customer's company" zone is taken from C. The
mockups were throwaway references kept untracked, and were deleted with this page.

## Situations are never hidden

A situation the viewer cannot do right now is still listed, with a mark saying why. Hiding it would make the guide
lie about what the product can do, and an administrator who cannot do something needs to learn who can.
`availabilityOf` (`lib/situation_guide/availability.ts:57`) decides in a fixed precedence, first match wins:

1. Needs a super administrator and the viewer is not one: `ownServer` when `plans.enabled` is on (this is the
   hosted service: run your own server for that), otherwise `askSuperAdmin`.
2. A switched-off flag: `switchedOff`, with the setting's key and the Settings pane that holds it, from
   `GUIDE_FLAG_PANES` (`lib/consts/situation_guide.ts:67`). `test/situation_guide/availability.spec.ts:253` checks
   every flag's pane against the settings catalogue's domain, so a moved setting fails a test instead of sending
   the button to the wrong pane.
3. Every switch of `needs.anyOf` off: `switchedOff` naming all of them, with `anyOf: true` so the text says one is
   enough. The MCP answer needs an agent host to be able to identify itself, by a Client ID Metadata Document
   (`clientIdMetadataDocument.enabled`) or by registering (`registration.enabled`); both are off by default, and
   without this gate the answer read "ready" on a default instance where no agent host could connect.
4. A plan feature the project's plan lacks: `notOnPlan`.
5. The plan's limit on what the form adds (`needs.room`: applications, APIs or connected services) is reached:
   `planLimit`, worded by `limitReachedText` in `lib/admin/ui/planText.ts`, the sentence the page's disabled New
   button gives. `GuideViewer.room` comes from the summary's plan usage and limits and is null when plans are off,
   on a System project and for a super administrator, so none of them meets a limit here.
6. A project right the viewer lacks (`edit`, `manageUsers`, `changeAddress`): `needsRight`. The own-address answer
   needs `changeAddress`, not `edit`: for anyone but a super administrator that is a team owner's, and only while
   the project holds no application, identity provider, provisioning connection or connected service
   (`mayChangeBucketAddress`, `lib/admin/auth/can.ts:173`); a hostname is always a super administrator's.

`notOnPlan` and `planLimit` lead to the project's own Plan card on its Overview (`#plan`, `BucketPlanCard.tsx`),
not to foxauth.dev's pricing, which would be the wrong page on a server someone else hosts.

## `features` on `me`, not a route

The switches ride on `/admin/api/me` as `features` (`lib/admin/me.ts:50`, built by `guideFeatures()` in
`lib/situation_guide/features.ts`, read at call time, never cached). A new route would have needed a catalogue
decision and an MCP tool. On `me` the console gets them with who the caller is, `whoami` carries them to an agent
for free, and no tool was added. `lib/situation_guide/features.ts` is server-only; the browser bundle imports only
the declaration and `availability.ts`. The console reads `me` once and then only when told, so the guide page and
the Overview card call `useMe().reload()` when they mount, and Settings calls it after a save: a switch turned on
shows as ready on the next visit to the guide, without a page reload.

## `plans.enabled` means "hosted for you"

There is no environment variable and no separate "is this the cloud" switch. Plans being on is the signal that a
viewer who is not a super administrator is on someone else's server, which is what turns `askSuperAdmin` into
`ownServer`.

## The button

A "Set this up" button always opens a create form, never a bare page. Ten situations were changed from a form to
"Open ..." (commit `0f556e81`) because their pages have no create form: `platform`, `signup`, `totp`, `domain`,
`idjag`, `rar`, `ciba`, `ipsie`, `adminapps` and `consolesso` (a switch, a setting, the bare Identity providers page
for ID-JAG). Applications (`?situation=`), APIs (`?declare=1`), identity providers (`?add=`), provisioning
(`?new=1`) and connected services (`?add=1`) take the request from the address through `useQueryOffer`
(`lib/admin/ui/frame/queryOffer.ts:11`): it is read once at mount, handed over once and only when the page's own
create button would be offered (the viewer's right and, for applications, APIs and connected services, room under
the plan's limit), and then removed from the address by a replacing navigation (the router's `replace` option), so
a reload does not reopen the form. `?situation=custom`, the guide's "Open the full form", opens the full form
itself rather than the chooser's first step.

A project with no address (`issuer` null) is no issuer of its own, so `actionFor` (`guide/targets.ts`) answers
`needsAddress` for an application or API target, as it does for a page the project serves: its applications would
sign in at the server's bare endpoints, and its APIs sit in the root namespace, where only a super administrator
declares.

An application created from a preset with its name left blank is called by the preset's short `defaultName` in
`situations.ts` ("Web app", "Backend service"), not by the guide's title, which is a sentence and would show as one
on the consent page.

## Where it appears

- An empty project's Overview shows a card that starts from the guide (`OverviewGuide.tsx`, built from
  `guideViewerOf` in `guide/viewer.ts` so the card and the page agree). Its compact answer keeps "Good to know",
  since that is where an answer's limits are stated.
- It is not offered on the Administrators project: every answer's button there would be closed, and its
  applications live under Administrators' own page (`lib/admin/ui/frame/routes.ts:403`).

## `/admin/start`: the site's door

The public site's button links to `/admin/start?s=<id>` (or `?e=<id>`). A reader without a session is sent to sign in
or register and returns there; the page then reads the projects list, drops the administrators' project and any
project the reader cannot edit, and goes to that project's guide with the answer chosen
(`lib/situation_guide/start.ts:40`, `lib/admin/ui/pages/guide/StartPage.tsx`). One project: it replaces the address
at once; several: a short "Which project?" list; none (a new Cloud account has none yet): a page saying to create one
first, so the chosen answer is not silently dropped; an unknown answer: Projects. It lands on the guide and not
on the form, because the guide is what says whether the form can be used in that project yet (a setting off, a plan
limit, a missing right). An unknown id is not guessed at, since the guide would show its default answer, which the
link did not promise.

## The site page

`/guide/` (`website/src/views/Guide.astro`) is a page of its own on the marketing layout, not a docs page: it is
where someone starts who does not yet know which docs page they need, and it first shipped under `/docs/` with the
docs sidebar, which read as one more manual page (moved 2026-11-04). It renders every answer into the HTML and lets two radio groups and
CSS `:has()` pick the visible one, so the page works with scripts off; one small script keeps `#s=<id>` / `#e=<id>`
in the address, copies the agent prompt and replays the diagram. The chips under the questions are links to
`#answer-<id>`, not radios: in one radio group with the second question, Tab reached only one of the two.

Its marks are read for FoxAuth Cloud, not computed from a live instance (`cloudMark`, `website/src/data/guide.ts:42`):
"own server" when a switch is off on Cloud (`CLOUD_FLAGS_ON` in `website/src/data/cloud.ts`, checked by hand against
production) or the act is a super administrator's, "not on the Free plan" for a plan feature (`CLOUD_FREE_FEATURES`
:48). SCIM therefore reads "own server": the shared instance keeps `scim.enabled` off on purpose ([[plans]]). The
setting each switch names comes from the export (`flagSettings`), never rebuilt on the site.

Russian and Chinese texts live on the site by situation, lane and answer id (`messages/guideSituations/`), and are
stamped against `lib/consts/situation_guide.ts` itself ([[site-translations]]). `guideTextsFor`
(`website/src/i18n/guide-texts.ts:95`) fails the build when a translation lacks an id or has a different number of
steps, so a situation added in `lib/` cannot ship half-translated. Agent prompts stay English in every language.

## The console's blue

antd's default primary, `#1677ff`, is 4.1:1 behind a primary button's white label. Since 2026-11-04 the whole console
uses `#0958d9` (6.2:1), with a hover of `#1668dc` (5.2:1) rather than antd's lighter one (3.0:1), set once as theme
tokens in `lib/admin/ui/frame/ConsoleRoot.tsx` (`CONSOLE_TOKENS`); the precompiled antd.css reads them through its CSS
variables. It is the blue the end-user pages already used (`lib/html/theme/palette.ts`). Until then the guide
overrode the colour in its own scope through antd's internal `--ant-btn-color-*` names; that override is gone, so
nothing here depends on antd's private variable names any more.
