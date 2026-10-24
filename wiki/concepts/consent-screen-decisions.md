---
type: concept
title: 'The consent page: what it says, and why'
tags: [architecture, contract, gotcha]
sources: [oauth-server-codebase]
created: 2026-10-13
updated: 2026-10-19
graph:
  node_type: concept
  relationships:
    - predicate: depends_on
      object: concept:untrusted-redirect-confirmation
      source: oauth-server-codebase
      evidence: "clientProvenance: if (!(await redirectUrisVouchedFor(client)) && !(await connectionClientRecord(client.clientId))) return 'self-registered';"
      confidence: high
      status: current
    - predicate: complements
      object: concept:team-ownership
      source: oauth-server-codebase
      evidence: "clientBelongsToBucket — the one test of \"these users are the tenant's own\" … the consent waiver honours an operator's stored flag there, and `clientProvenance` counts such a client as the instance's own."
      confidence: high
      status: current
    - predicate: depends_on
      object: concept:form-action-redirect-chain
      source: oauth-server-codebase
      evidence: "The pending request's redirect URI goes to the page's policy because confirming starts a redirect chain — confirmation, then /ui/:uid/resume, then the client"
      confidence: high
      status: current
---

# The consent page: what it says, and why

The consent page is where a person decides whether an application gets into their account. Until spec 092
it said "Consent Required", printed the account id, and listed scope tokens. Since 092 it says who is
asking, what the app will be able to do, and for how long, in plain words. This page records the
decisions behind that wording. Each one is easy to undo by accident.

The work is split three ways. `consentViewFor` (`lib/interactions/index.ts:699`) only reads: the
interaction, the client, the project, the person and their grant. `buildConsentView`
(`lib/interactions/consentView.ts:529`) decides what to say, and reads no configuration. `ConsentPage`
(`lib/interactions/consentPage.tsx:771`) turns the result into words from one catalog. The view carries
**data, never sentences** (`consentView.ts:22-31`). The server render and the browser's hydration then
read the same values and the same words. A value computed only in the component would vanish on
hydration ([[interaction-page-families]]).

## Who stands behind the app: three tiers

`clientProvenance` (`lib/models/client/provenance.ts:68-78`) puts every client in one of three tiers:

- **self-registered** — nobody here created it: dynamic registration, or a metadata document.
- **this-organization** — the client belongs to the project being signed into, or it belongs to no project at
  all (the instance operator's own).
- **operator-registered** — an administrator of this server created it, but in another project — for example
  an application of the Default project that reaches this project through a declared resource. Until spec 099
  the test compared the administrator group (a team, since spec 100) owning the client's old Project entity (a
  retired project) with the group owning the bucket (today's project), and in a bucket shared by several
  groups' old Projects this tier was another tenant's app.

**Self-registered is tested first, and the order is the point.** A document client, and a dynamically
registered one at the root, belongs to no project. The consent waiver reads "no project" as "the operator's own"
(`lib/shared/consent_waiver.ts:33-44`). That reading is safe for the waiver only because such a client
cannot switch consent off. For wording it would be wrong: every DCR and CIMD client would be headed as the
organization's own app. The self-registered test reuses `redirectUrisVouchedFor` (`provenance.ts:25`), so
"who vouched for this client" has one definition for both this page and
[[untrusted-redirect-confirmation]]. A provisioning connection's client is synthesized, not stored, so it
is explicitly kept out of self-registered (`provenance.ts:70-73`). It never reaches consent, but the
function stays right for every client it can be handed.

The comparison itself is `clientBelongsToBucket` (`provenance.ts:40-47`): the stored client's `bucketId` is
the sign-in project's id. The waiver and the tiers share it. It answers `undefined` for a client that belongs to
no project, and each caller decides what that means. Until spec 099 it was `projectGroupOwnsBucket`, which
compared administrator groups (teams, since spec 100) through the client's old Project entity (a retired
project); a client that fell out of its old Project then read as the operator's own, which is one of the
defects that removed old Projects ([[project-is-the-only-container]]). See [[team-ownership]].

The project compared is the **sign-in project** — the one `resolveBucketForRequest` chose, which the
interaction resolve now returns as `signsInto` (`lib/interactions/index.ts:1150`). Its users are the
ones consenting. The addressed project would name the root service for an application's project reached at
the root address.

## No positive trust signals

The page never shows a shield, a check mark, "verified" or "added by your administrator". The tier only
chooses the wording and the warnings. Only a this-organization client may be headed "Sign in to {name}" or
"{name} wants access to your {service} account". Every other tier gets "The app “{name}” wants access to
your account" (`consentPage.tsx:598-623`). Every other tier also gets the quiet line "{service} hasn't
checked this app", except on a device approval (`consentPage.tsx:679`,
`lib/i18n/texts/consent/en.ts` `host.notChecked`). A trust badge on a page whose name and logo
a registrant chooses would be the first thing an impostor copies.

## At most one warning

`buildConsentView` picks one warning at most, and the gravest wins (`consentView.ts:589-598`):

1. **admin** — the request asks for this server's own administrative MCP. Red, with a key icon.
2. **loopback** — **all** registered redirect URIs are loopback (`index.ts:820-823`). Such a client
   cannot prove which local program receives the answer. A client that also registered a web address
   has proved a place the answer can go, so its loopback use is stated without alarm.
3. **device** — a device-flow approval: "Is this code shown on your device?"
4. **unverified** — amber, and only for a client that is not this organization's own. It shows only when
   the app acts (anything in the "act" or "not described" groups), asks for offline access, has a name
   confusable with the service, or is a document client whose document host differs from its redirect
   host (`consentView.ts:571-587`).

A warning on every page is a warning nobody reads. That is why a self-registered client asking only to
sign someone in gets the quiet line and no amber block.

## What is asked for: see, act, not described

Standard OpenID scopes become fixed phrases about data the person can picture. They are "see". Profile,
email, address and phone are named only when the person actually has a value
(`consentView.ts:257-287`). `openid` and `offline_access` are never items. A resource scope is "see"
only when its administrator declared `kind: 'see'`. **Described without a kind, it is "act"**
(`consentView.ts:436-442`). Understating what an app can do is the failure that matters on this page.
Anything nobody described is shown by its technical name under "Other permissions — not described". It is
not guessed at. Technical names of described items sit in a `<details>` disclosure
(`consentPage.tsx:97-109`), so they work before any script loads.

Sign-in mode (one sentence of shared data) is used only when nothing but standard personal data is asked.
No resource, no custom scope, no rich authorization detail, no offline access, no administrative MCP
(`consentView.ts:550-570`).

**The administrative MCP is recognised by the requested resource, not by scope**
(`index.ts:795-802`). Its only scope is `openid`. Once that is granted it drops out of the prompt's
details, and a second agent asking for the same power would be shown nothing.

## "Keeps access until"

The lifetime line appears only when a refresh token will really be issued (`index.ts:769-773`). That
means `offline_access` survived on the stored request, the instance supports the scope, and the client is
allowed the `refresh_token` grant. This is the default refresh-token rule. A deployment that overrides
`issueRefreshToken` is not second-guessed. The date is the grant's `exp`, because every refresh is bounded
by it and re-consenting never extends it. For a first consent it is now plus `ttl.Grant`. It is formatted
once on the server, in UTC (`lifetimeDate`, `index.ts:551`), so the browser's locale and clock cannot
change it during hydration.

## Asking again shows only what is new

The GET reads the hinted grant with `Grant.tryFind` (`index.ts:702`), never `find` — a first
consent's grantId names nothing stored ([[first-consent-grant-id]]). What it already holds becomes one
line, "You already allowed: …". The groups list only the prompt's missing items. A summary of everything
the app will then have appears only when the new items escalate: an act, an undescribed item, or offline
access (`consentView.ts:622-632`). For an application without partial consent there is no per-item
selection: Allow grants everything shown. The next section is the exception.

## Choosing what to allow (spec 093, 2026-10-13)

An administrator can mark a client as coping with partial access: the canonical-only base key
`consent.partial` (`lib/models/client/wire.ts:62`), admin `partialConsent`, off by default. Dynamic
registration and metadata documents cannot set it — the same rule that keeps `consent.require` an
operator's decision. For such a client the page gives every item beyond signing in its own checkbox,
**unticked**. What signing in needs — `openid`, `profile`, `email` and their claims — is fixed and shown
in a block of its own (`lib/interactions/consentChoices.ts:57`). Authorization details stay all or
nothing, and the page says so. A claim's `essential` is a hint, never a lock.

- **One function decides the offer, twice.** `consentChoices` (`consentChoices.ts:105`) runs for the GET
  and again for the POST (`choicesFor`, `lib/interactions/index.ts:611`). It reads only the prompt's
  details and two facts — the flag and whether this is a device approval — never the person's claims, so
  the page and the handler cannot disagree. Each row posts a content key (`oidc:phone`, `scope:billing`,
  `resource:<indicator> <scope>`). A value the page did not draw, or a selection where there was no
  choice, is refused with nothing written (`index.ts:1910`).
- **The posted list only narrows.** The grant is built from the details as before, then every unticked
  row is refused through the grant's `reject*` (`index.ts:521`). The details never hold an earlier
  allowance, so a partial allow cannot withdraw one. An Allow that leaves nothing at all is answered as
  the refusal it amounts to, without recording refusals (`allowsNothing`, `index.ts:623`).
- **Checkboxes appear only with two or more choices** (`consentChoices.ts:172`), and never in the device
  flow: it has no `prompt` parameter, so a refusal there could never be offered again.
- **A choosable category is shown even when empty** (`consentView.ts:410`). A checkbox decides a
  permission. Hidden, an empty phone number would be granted unseen the day the person adds one, or
  refused without being asked.
- **Summaries promise only what is certain.** With choices, "after you allow" lists what was allowed
  before plus the fixed items, and adds "and anything you select above" (`consentView.ts:625`); the
  long-lived-access date sits on its own row.
- **One form spans the rows and the buttons**, and **one `Checkbox.Group name="allow"` spans every row**,
  both laid out with `display: contents`, so the ticked keys post with the buttons without script. In antd
  a checkbox's `value` means something only inside a group: a lone `<Checkbox value>` warns "`value` is
  not a valid prop, do you mean `checked`?" (`antd/es/checkbox/Checkbox.js:60`, the check is
  `'checked' in props || !!checkboxGroup || !('value' in props)`), and it is the group that names each box
  through its context. The group's `role` is `none`: the rows already sit under the page's own headings.

**A refusal is not forever.** The grant subtracts what it refused from everything it issues, and the
consent checks count a refusal as answered — so the person is not asked on every sign-in. But until 093
they did so even under `prompt=consent`, and allowing never cleared a refusal: the first "no" was
permanent. Now a refusal counts as answered only while `prompt=consent` is not pending
(`refusalsCountAsAnswered`, `lib/helpers/interaction_policy/prompts/consent.ts:22`). Pending is true on
the request's first pass and false on the resume once the person answered, so offering it again cannot
loop. Allowing takes the refusal back (`withdrawRefusal`, `lib/models/grant.ts:165`). An item offered
again says "You didn't allow this last time". This holds for every client, flag or not.

## The app's logo and links (spec 094, 2026-10-13)

The organization's own app can show its logo beside the headline and link its privacy policy and terms
below the buttons. Every pixel and every link is something an operator put there, never something the app
said about itself.

- **Only an administrator sets the logo.** It travels as a `data:` URL on the existing client routes
  (`logo`, `null` removes it; `lib/admin/clients/schema.ts:36`). Its bytes decide what it is — PNG, JPEG
  or WebP, at most 64 KiB (`sniff`, `parseLogo`, `lib/models/client/logo.ts:30`, `:53`;
  `lib/consts/client_logo.ts:8`). SVG is refused: it is a document that can carry script and
  references, and a crisp vector "Verified" badge is the easiest forgery there is. A refused logo or
  link is checked before anything is written (`checkedPresentation`, `lib/admin/clients/service.ts:220`),
  and the logo is stored only after the client record is (`storeLogo`, `:247`). The audit entry names
  `logo`, never the image.
- **A client's `logo_uri` is never read.** Not fetched, not proxied, not rendered — for any client. A
  fetched logo can change after review, track every person who opens the page and point the server at an
  internal address (CIMD §8.8, §9.2). Dynamic registration and metadata documents cannot reach the
  operator's logo at all: it is not client metadata.
- **The logo lives beside the client record, not in it.** A model area of its own, `ClientLogo`, keyed by
  client id (`lib/consts/storage_inventory.ts:360`). The client record is read, serialized and hashed on
  every resolution — every authorization, token and introspection call (`tryFindClient`,
  `lib/models/client/validate.ts`) — and up to 87 KB of base64 would ride along on each for a picture
  only this page shows. Client-owned, so `cascadeForClient` sweeps it when the client is deleted. The
  project's application list says `hasLogo` and carries no image (`listClientView`, `service.ts:415`).
- **Only this organization's own app, and never in a sign-in that doubts the receiver.** The logo is
  attacker pixels the moment anyone else can set it, so tier `this-organization` alone. A device flow and an
  app whose redirects are all loopback also hide it: a familiar logo is exactly what makes a phished device
  code or a local program look like the real thing, so the device page never shows one.
  - Since spec 106 (2026-10-19) this is decided once per sign-in from those facts, by `brandingFor`
    (`lib/interactions/branding.ts:33`). The same decision gates the application's colour
    ([[client-primary-colour]]).
  - Spec 094 tested which warning the page showed (`warning?.kind`). Because the administrator-rights warning
    outranks the device and own-device ones, a device's consent page asking for the admin MCP displayed the
    logo.
  - The read happens only when the decision allows it (`lib/interactions/index.ts:727`), and the view builder
    passes on whatever it was given (`consentView.ts:678`).
- **On a light plate in either colour scheme** (spec 096). The tile is the palette's `logo-plate`, light even
  on a dark page, because the logo was drawn for a white one ([[end-user-colour-scheme]]).
- **Embedded, so the policy stays.** The image is in the page as `data:` (`ClientLogo`,
  `consentPage.tsx:634`), which `img-src 'self' data:` already allowed. It appears twice — in the markup
  and in `window.PROPS` — which the 64 KiB cap keeps small. Its `alt` is the sanitized client name; it
  sits outside the `<h1>` and never in the header.
- **Links only on the app's own site** (`linksOf`, `consentView.ts:727`). For a `this-organization` app,
  `policy_uri` and `tos_uri` are each shown only when https and on the hostname of one of the app's own
  http(s) redirect URIs, compared in the URL parser's ASCII form. A native app with a private-use scheme
  has no host, so it gets no links. RFC 9700 §4.2.4 says the authorization page should not link off-site;
  this is the narrow reading that still meets RFC 7591's "SHOULD display". Opened in a new tab with
  `noopener noreferrer`, marked external for a screen reader, darker than antd's link blue for contrast
  (`AppLinks`, `consentPage.tsx:584`). Administrators may set only https ones; dynamic registration may
  still store http ones, which are simply never shown.

## The decision belongs to the account it was shown for

The account is named by email, else name, else login. It is never shown as an id
(`accountLabel`, `consentView.ts:499`). The form carries the account id back as a hidden field. The POST refuses a
submission naming any other account, or none, **before** either branch (`index.ts:1887-1897`). The
refusal is the resolve's "session principal changed". `createGrant` saves at once, so a later check would
come after the grant was written. Declining for the wrong account would also end a flow the person on
screen never saw. The field is optional in the schema (`index.ts:1943`) so a missing field gets the
same answer as a mismatch, not a 422 naming the field.

"Switch account" links to the interaction's login page. It is hidden when the request names its account
in a way sign-in enforces: an `id_token_hint`, or `claims.id_token.sub` (`accountNamedByRequest`,
`index.ts:567`). `login_hint` is not enforced, so it does not hide the link. Switching to another account
of the same project goes through the sign-out confirmation. That page now gets the pending `redirect_uri`
as its hand-off, or the browser stops before the client ([[form-action-redirect-chain]]).

## A self-chosen name is shown with care

A client's name is whatever its registrant typed. `sanitiseClientName`
(`lib/interactions/clientName.ts:50-66`) removes control, format, line- and paragraph-separator
characters, which covers bidi overrides and zero-width characters. It trims leading and trailing symbols
and emoji ("✅ Acme"), keeping a closing bracket the name opened. It shortens the name to 40 graphemes.
The page renders it inside `<bdi>`, so it cannot reorder the sentence around it.

Confusability is a containment test on skeletons (`clientName.ts:68-109`). The skeleton is compatibility
decomposition, lower case, a look-alike map, then only `[a-z0-9]`. The map (`lib/consts/confusables.ts`)
is a vendored subset of Unicode's UTS #39 `confusables.txt`, version and date recorded in its header. No
npm dependency was added for one warning. The references are the service's display name, its host, and
four reserved words (`consentView.ts:573-579`). **A reference whose skeleton is shorter than four
characters is ignored.** A service called "ID" is contained in half the names there are. A miss costs a
warning, never access, which is why a subset is enough.

## The header is the server's, never the client's

The header shows the sign-in project's `displayName`, else the host of that project's issuer
(`index.ts:668-672`). It never shows the project's internal `name`, which may say "prod-eu-users"
(`UserBucket.displayName`, `lib/adapters/types.ts:1880-1881`). Nothing client-supplied appears there —
the own app's logo (spec 094) sits beside the headline, below it.

Hosts are the WHATWG parser's ASCII form (`redirectKind`, `consentView.ts:230-249`). An
internationalised name is never converted back to Unicode, because that is what lets a look-alike pass as
the original.

## One catalog of words

Every string the page shows is in the consent catalogue, `lib/i18n/texts/consent/{en,ru,zh-Hans}.ts`,
including the page title. It absorbed the old scope-label, group-heading and RAR field tables. Since spec
097 (which replaced `lib/interactions/consentTexts.ts`) each entry is a whole sentence with `{slots}`, so a
translation can put the application's name where its language wants it, and the page is shown in English,
Russian or Simplified Chinese ([[end-user-languages]]).

## What operators supply

- **Resource scope descriptions.** A declared resource takes `scopeDescriptions`: per scope a
  `description` (1–200) and an optional `kind` (`lib/admin/resources/schema.ts:17-30`). A key that is not
  one of the resource's scopes is a 400 naming `scopeDescriptions` (`routes.ts:131`). A PATCH that changes
  `scopes` without sending descriptions prunes the removed scopes' entries and names `scopeDescriptions`
  in the audit attributes (`routes.ts:150`, `:327-336`). Accepted values are trimmed and carry no
  `undefined` member (`lib/resources/scopes.ts:116-141`). See [[mcp-server-authorization]].
- **Custom OpenID scope descriptions.** The setting `consent.scopeDescriptions`
  (`lib/configs/application.ts:697-707`) is checked right after `collectScopes`
  (`checkConsentScopeDescriptions`, `lib/configs/configuration.ts:172`, called at `:724`). A key must be a
  defined scope and never a standard one (`lib/consts/oidc_scopes.ts`). Removing a described scope
  without its description is refused. See [[settings-console-descriptor]].
- **Project display name.** `displayName` (1–60, trimmed, blank refused) on create and update; `null` on
  update clears it (`lib/admin/buckets/schema.ts:43`, `:105`; `routes.ts:112`). See
  [[admin-project-settings]] and [[stored-document-schemas]] for how the field is removed.
- **Client logo, privacy policy and terms.** `logo`, `policyUri`, `tosUri` on the client routes (spec 094,
  above).

Nothing on the page is taken from protected-resource metadata, MCP tool metadata or the client beyond its
name, its redirect URIs, and — for this organization's own app only — its policy and terms links.

## Not here

- No per-item selection unless an operator turned it on for the client (spec 093, above).
- No logo for any app the organization does not stand behind, and no monogram or placeholder for one
  without a logo.
- Since spec 095 the "remove this access later" line is here, below the buttons, linking the sign-in project's
  connected-apps page in the same tab, absent in the administrators' project (`revokeHint`,
  `lib/interactions/index.ts:855`). It waited for that page to exist: see [[connected-apps-page]].
- CIBA never renders this page.
- No translation yet; the catalog is the seam.

## Related

- [[untrusted-redirect-confirmation]] — the same provenance, read on the error path
- [[team-ownership]] — the ownership comparison the tiers and the waiver share
- [[rich-authorization-requests]] — rich details on this page, under "act"
- [[form-action-redirect-chain]] — why the account-switch sign-out needed a hand-off
- [[first-consent-grant-id]] — why the grant is read with `tryFind`
- [[interaction-page-families]] — the hydration contract this page's data-only view honours
