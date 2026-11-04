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
`lib/consts/situation_guide.ts` (`GUIDE_QUESTIONS` :237, `GUIDE_SITUATIONS` :386). The console renders it, the
availability function reads it, and the docs export hands the same list to the site (`situationGuide`,
`lib/docs_export/build.ts:348`), so the console and the site cannot drift. The chooser for a new application takes its preset titles and descriptions from the same entries
(`[[application-page]]`).

## The pictures: one rule, and FoxAuth where it really is

Every answer is drawn twice from its own data: "Your problem" and "With FoxAuth" (`sceneOf`,
`lib/situation_guide/scene.ts:284`). Each lane names a `part` (person, browser, server, agent, company, …), and each
situation names its `problem`: the lane it sits on, one of five marks (password, secret, open, copy, missing) and a
caption, with `lanes` to override which parts the problem picture shows (`lib/consts/situation_guide.ts:193`). The
parts are SVG path data in `lib/situation_guide/parts.ts`, with no text inside, so every label is HTML and translates.

The rule that matters is where FoxAuth stands. In most answers it stands **beside** the path: it hands the client a
token, and the client calls its own API or MCP server directly. The first drafts drew FoxAuth between the client and
the API, which reads as a gateway every call passes through, and that is not what the server is. FoxAuth is drawn in
the **middle** only when an outside party sends something to it (an identity provider, a company directory, Google
for a connected account): the rule reads the steps, not a list of situations (`scene.ts:142`). The spec proves that no
answer ever links FoxAuth to the resource a client calls, and that every situation can be drawn.

## Keeping the guide true

The guide is only useful while it matches the server, and no test can tell that a feature has no situation or that
a situation describes what a feature no longer does. So the rule (AGENTS.md, **The situation guide**) is that the
change which adds, changes or removes something a person sets up also touches the guide.

- **Added.** Declare a situation in `GUIDE_SITUATIONS`: its place in the two questions (`ask`) or a chip, `lanes` (an
  existing lane with its `part`, or a new one in `LANES`), `steps`, `sees`, `needs` (the flags, the plan feature, the
  role, the room), `action`, `goodToKnow`, `prompt`, a `problem` (the lane, one of five marks, a caption) and a
  `fixCaption`. Add its Russian and Chinese texts and stamp both files.
- **Changed.** Correct every field the change makes false. A renamed setting goes in `GUIDE_FLAG_SETTINGS`; a moved
  console form, in the situation's `action.target`; a preset change, in `lib/admin/ui/pages/applications/situations.ts`.
- **Removed.** Remove the situation, and any `next` that names it, from both languages too.

What fails if this is skipped half-way: `test/situation_guide/scene.spec.ts` (a situation that cannot be drawn),
`availability.spec.ts` (a flag that is not a real setting), `presets.spec.ts` (a form the route refuses), and the
site build (`guideTextsFor`, a translation that lacks an id or a field). What never fails: a situation that is
missing, or one whose words have stopped being true.

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
in the address, copies the agent prompt, steps and replays the diagram, and below 1024 px scrolls to the answer after
a choice in question 2 (not question 1, whose next step is question 2 just under it). The chips under the questions are links to
`#answer-<id>`, not radios: in one radio group with the second question, Tab reached only one of the two.

Since 2026-11-04 the page is split from 1024 px, the questions left and the answer right and sticky, and every
answer opens with a strip of three frames: "Your problem", "With FoxAuth" and "What you get", with the one button in
the third (`website/src/components/guide/Strip.astro`). The two pictures are the scenes `lib/situation_guide/scene.ts`
works out, layout included: `placement` (`beside` puts FoxAuth's one node in `above`, off the row the client calls
its resource along; `middle` is one row in lane order), `row`, `above`, an `arc` level on each link that skips a
neighbour on the row, and the solution's `fixed`, the lane that carries the check. `fixed` is left out where the
problem's lane is outside the reader's control or touches a refused (`broken`) link, so the thief in `bound` and the
person who left in `scim` never get a check; until the final review (2026-11-04) each renderer put the check on the
problem's lane itself. A page only turns that into sizes (`Scene.astro`, and the console's `Scene.tsx`, which reads the
same fields), so no page keeps a picture rule. The options' small pictures come from the same place:
`optionPartsOf` and `GUIDE_ACTOR_PARTS` in `lib/situation_guide/options.ts`, exported per situation as
`optionParts` and as `actorParts`. The strip lays itself out by its own width (container queries), so the same answer
is three across, two plus one, or stacked. Only a ready answer gets the accent button; a paid-plan answer gets a
secondary "Ask for a paid plan" (the waitlist's mail, its subject naming the answer) and an own-server answer the
Docker Compose page. The options and the expert table carry the same status glyph and word as the answer
(`Status.astro`). "What you get" draws the screen the answer's `sees.kind` names, with `GUIDE_EXAMPLES`; `signUp`,
`serviceConsent` (the outside service, Google) and `adminConsent` (the agent in FoxAuth's own console) exist so that
no screen contradicts the lines under it.

Its marks are read for FoxAuth Cloud, not computed from a live instance (`cloudMark`, `website/src/data/guide.ts:42`):
"own server" when a switch is off on Cloud (`CLOUD_FLAGS_ON` in `website/src/data/cloud.ts`, checked by hand against
production) or the act is a super administrator's, "not on the Free plan" for a plan feature (`CLOUD_FREE_FEATURES`
:48). SCIM therefore reads "own server": the shared instance keeps `scim.enabled` off on purpose ([[plans]]). The
setting each switch names comes from the export (`flagSettings`), never rebuilt on the site.

Russian and Chinese texts live on the site by situation, lane and answer id (`messages/guideSituations/`), and are
stamped against `lib/consts/situation_guide.ts` itself ([[site-translations]]). `guideTextsFor`
(`website/src/i18n/guide-texts.ts:100`) fails the build when a translation lacks an id or has a different number of
steps, so a situation added in `lib/` cannot ship half-translated. Agent prompts stay English in every language.

## The console draws the same pictures

Since 2026-11-04 the console's answer (`lib/admin/ui/pages/guide/AnswerPanel.tsx`) opens with the same strip, drawn
by `Scene.tsx` straight from `sceneOf` and `GUIDE_PARTS` (the console bundle imports lib; the site gets the same
result through the export): only the pixel math of `Scene.astro` is repeated there, never a picture rule or a path.
The strip is three across from 720 px of panel width, the two pictures beside each other with what you get under
them from 480 px, and one column below that (container queries, so the Overview's card agrees). Colours are antd
tokens through `useDiagramPalette`, FoxAuth's part in the console primary rather than the site's orange. The button
stays the console's own (`actionFor`), under the strip, followed by a "Next:" link to `?s=` / `?e=` of the same
page; the diagram's lane heads carry their parts. The options, tasks and table rows show a glyph and a word read
off the same `actionFor` (`statusOf` in `targets.ts`): Ready, Switched off, Own server, Not on your plan, Plan limit
reached, Needs an address, Needs a right, so the mark cannot disagree with the button. These words are for this
viewer on this server, unlike the site's, which are read for FoxAuth Cloud. "What the person will see" is gone as a
section of its own: its screen and lines are the strip's third frame.

## The console's blue

antd's default primary, `#1677ff`, is 4.1:1 behind a primary button's white label. Since 2026-11-04 the whole console
uses `#0958d9` (6.2:1), with a hover of `#1668dc` (5.2:1) rather than antd's lighter one (3.0:1), set once as theme
tokens in `lib/admin/ui/frame/ConsoleRoot.tsx` (`CONSOLE_TOKENS`); the precompiled antd.css reads them through its CSS
variables. It is the blue the end-user pages already used (`lib/html/theme/palette.ts`). Until then the guide
overrode the colour in its own scope through antd's internal `--ant-btn-color-*` names; that override is gone, so
nothing here depends on antd's private variable names any more.
