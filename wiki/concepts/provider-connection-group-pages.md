---
type: concept
title: "Providers, provisioning connections and groups: a page each, and the deciding question as a wizard step"
tags: [architecture, admin, federation, scim, ux]
sources: [oauth-server-codebase]
created: 2026-10-11
updated: 2026-10-15
---

# Providers, connections and groups pages

Spec 084, phase 5 of the console redesign. A project's identity providers, SCIM provisioning connections and
groups of end users used to be edited in modals stacked on drawers. Each now has a page with its own address,
and creating a provider or a connection is a side-panel wizard. The tabs (`FederationPanel.tsx`,
`ProvisioningPanel.tsx`, `BucketGroupsPanel.tsx` under `lib/admin/ui/pages/`) only list, open, create, turn on
or off and delete. Since spec 088 the providers table is in sign-in page order and says so, and each row's menu
has Move up and Move down, C0 because only the order changes ([[upstream-federation]]).

| Page | Address | Component |
|---|---|---|
| Provider | `/admin/projects/:p/identity-providers/:id` (administrators' project: `/admin/administrators/identity-providers/:id`) | `pages/providers/ProviderPage.tsx` |
| Connection | `/admin/projects/:p/provisioning/:c` plus `/directory-setup` and `/settings` | `pages/provisioning/ConnectionPage.tsx` |
| Group | `/admin/projects/:p/groups/:g` | `pages/groups/UserGroupPage.tsx` |

Until spec 100 these were `/admin/buckets/:b/…`, and the group page `/admin/buckets/:b/user-groups/:g`; the old
addresses answer with a redirect (the `REDIRECTS` table, `lib/admin/ui/frame/routes.ts:390`), because hold
emails already sent link the old connection address. `providerHref`, `connectionHref` and `userGroupHref`
(`lib/admin/ui/frame/routes.ts:512-532`) build these addresses. Build them there rather than by hand: the
administrators' project's providers live under Administrators.

## The deciding question cannot be skipped

- **Provider wizard** (`ProviderWizard.tsx`). Its last step asks what happens at a first sign-in, and it has no
  default; Create stays disabled until it is answered.
  - The answer "create an account" ignores a closed Sign-up, and the step says so.
  - The server's create default (`jit`, or `existing_only` on the administrators' project) is unchanged for agents.
    Making the field required on the API was left out of scope.
- **Connection wizard** (`ConnectionWizard.tsx`). It creates the connection at the end of step three, and that
  step's safeguard choice has nothing preselected, by owner decision.
  - Holding protects against a wrong rule in the directory.
  - Applying at once is what the directory, and IPSIE, expect.

  Only the operator can weigh the two.

  Since spec 088 its first step asks which directory this is — Microsoft Entra ID, Okta or another — preset from
  the provider. That choice brings the directory's own field names, recommended credential and pitfalls, read
  from the server's directory guidance, to the later steps, the Directory setup tab and Copy setup details
  ([[scim-provisioning]]).
- **Recommended matching.** The rule the wizard calls "recommended" is the server's `defaultCorrelationFor`,
  read through the provider read. It is not a second copy in the browser.

## The provider page

- **One draft, one save bar.** A save that lets more people in is asked as a danger question
  (`provider.trust.widen`) that lists exactly those changes:
  - account creation turned on;
  - domains removed, or a domain list emptied;
  - linking by email turned on;
  - a logout signal accepted.

  Narrowing changes appear in the same question. The diff is computed in the browser (`trustLines`), because
  every input is on the page.
- **The issuer is read-only.** A link names the provider by id, so a new issuer would hand linked accounts to
  another upstream ([[upstream-federation]]). Connecting a new provider is the way out.
- **Disabling a provider a connection is bound to stays possible.** It carries the stronger warning. Blocking
  it, as the research proposed, would leave no way to cut off a compromised upstream, because the connection
  cannot be deleted while it manages anyone.
- **Delete states what the server does**: the links go with the provider. Delete is unavailable while a
  connection is bound.
- **The last-door check** (`isLastDoor`, `providerTypes.ts`): password sign-in off and no other enabled
  provider. In that case Disable and Delete are shown unavailable with the reason before anyone presses them.
  The administrators' project's stricter guard stays the server's.
- **The read behind the page.** It is one provider read, `GET …/federation/:providerId`
  (`lib/admin/federation/routes.ts:98`, `presentDetail` at `service.ts:129`; MCP `federation_provider_get`). It
  returns:
  - the callback and its stability;
  - which logout signals the provider can send at all (none for a `profile_api` provider such as GitHub);
  - whether the instance accepts them;
  - the bound connection and the linked-people count (`UserStore.countLinkedTo`);
  - warnings;
  - since spec 088, `capabilities.trySignIn`, which is `federation.enabled`.
- **Try sign-in** (spec 088, `pages/providers/TrySignIn.tsx`, C0) sends a new tab through the provider with the
  project's real callback and shows what the provider answered and what a real sign-in would do, with nothing
  written. It works on a disabled provider. See [[federation-try-signin]].

## The connection page and the hold

- **Overview** shows:
  - the counts, linked to the Users list (`?managedBy=`) and the Groups list (`?keptBy=`);
  - one Credentials row per slot — since spec 088 two while a replaced secret or static token still works,
    with Retire previous now (C1) and a static token's expiry ([[scim-credential-overlap]]);
  - a History card (since spec 085, replacing two links) with All (`connection=<id>`), By the directory
    (`actor=connection:<id>`) and By administrators (the connection as target), five entries each
    ([[admin-audit-trail]]);
  - the hold panel (`HoldPanel.tsx`).
- **Settings** holds name, matching, email trust and the safeguard under one save bar. Turning the safeguard
  off is a danger question.
- **The hold panel** lists who the directory is trying to remove, from the refused-removal record
  ([[scim-provisioning]]). It offers three ways out: the directory is right (release), it is misconfigured (fix
  it, then release), or someone else holds its credential (revoke or disable).
  - Release is `ConfirmDestruction` with the word `release` plus an acknowledgement checkbox. The
    `acknowledgement` prop is new and holds the button until it is ticked.
- **Where a hold shows**: the project list row, the Overview's attention item (which opens the held connection
  itself), a dot on the Provisioning tab, the connection's header, and the hold email, which now links to the
  connection page. Since spec 088 also a red count on Projects in the side menu, on every page, and the project
  list's On hold mark links to the held connection ([[scim-provisioning]]).

## Secrets are shown once, in place

`frame/SecretReveal.tsx` is the one way the console shows a value it will never show again. It is used for a
provisioning secret or static token, and for an OAuth client's secret.

- The value is masked until Show is pressed, and Copy announces politely.
- A checkbox ("I've put it into …") must be ticked before the surface may close or move on.

It is always rendered inside the surface that produced the value — a wizard step, the Credentials card, the
client's own dialog (which loses Cancel, close and click-away) — and never in a window stacked over another,
which an operator closes by reflex.

## Groups

- **The group page** pages its members from the server. It adds up to 1,000 people in one request, and removes
  them with the same question as a person's Groups tab (`userGroup.member.remove`).
- **Rename warns** with the old and new names that applications see the new one at each member's next token.
  The `groups` claim carries names ([[project-groups]]).
- **A directory-kept group** shows one sentence instead of controls.
- **Hand-over is C4** (`PreviewConfirm`): the server's preview names the members the connection does not manage,
  and the group's typed name confirms.

## Related

- [[scim-provisioning]] — the hold, the refused-removal record and release
- [[project-groups]] — the hand-over preview on the server
- [[admin-console-frame]] — action classes, `PreviewConfirm`, `ConfirmDestruction`
- [[project-workspace]] — the tabs these pages sit under
- [[console-federation]] — the administrators' project's providers and their guards
