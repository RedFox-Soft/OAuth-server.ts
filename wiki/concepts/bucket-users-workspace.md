---
type: concept
title: "Bucket users in the console: a server-paged list, a page per person, acts at their weight"
tags: [architecture, admin, console, contract]
sources: [oauth-server-codebase]
created: 2026-10-11
updated: 2026-10-11
---

# Bucket users in the console

Phase 3 of the console redesign (spec 082). The bucket's Users tab stopped reading the whole bucket into
the browser, and each person got an address of their own. The server half — the paged list, the single
read, the email change, the resend, the address check on verification — is in [[end-user-lifecycle]]; this
page is about the console.

## The list is the server's, and its state is the address

`lib/admin/ui/pages/BucketUsersPanel.tsx:61` reads one page of 50 (`PAGE_SIZE`, `:37`) from
`GET /admin/api/buckets/:id/users`, which answers `{ users, totalResults }`. Search (`q`), the four filters
(`status`, `managedBy`, `verified`, `authenticator`) and `page` live in the query string and nowhere else:
typing waits 300 ms, then replaces the address, and the list reads the address. A filtered list is
therefore a link, and Back undoes a filter. Any change other than the page drops `page`, so a narrower list
starts at its first page.

Search is a prefix of the email or username, or an exact id, decided by the server
([[postgresql-backend]] for how PostgreSQL serves it from an index). The console never filters rows
itself: a page is not the bucket.

Before the first answer the table shows nothing rather than its empty state (`:369`). "No users yet"
before the server has answered is a claim, and the walk caught it flashing.

Rows show who the person is and then only exceptions: Deactivated, Locked and Unverified tags
(`lib/admin/ui/accounts/AccountStatusTags.tsx`), groups (three, then `+N`), sign-in methods, and who manages
them. The row's email is the link to the person; the menu (`rowActions`, `:194`) holds the acts that need
no page. For a provisioned row, the items the directory owns fold into one disabled line naming the
connection — [[admin-console-frame]]'s RowActions rule.

## A page per person

`/admin/buckets/:b/users/:u` and its `sign-in-methods`, `groups` and `activity` areas are routes of their
own (`lib/admin/ui/frame/routes.ts:93`), rendered by `lib/admin/ui/pages/users/UserPage.tsx:35`, not by
`BucketDetail`. The administrators' bucket answers NoAccess there; its accounts stay on the Administrators
page until phase 4.

- **Header** (`headerActions`, `UserPage.tsx:141`): Sign out everywhere (C1), Lock… (the reason is the
  confirmation) / Unlock… (C2, the question repeats who locked them, when and why), and under More,
  Deactivate (C2) / Activate (C0). Deactivate is absent for a provisioned person: `active` is the
  directory's. Since spec 089 More also holds Send invitation… (C1), when the bucket takes passwords.
- **Profile**: whether they can sign in and every reason they cannot (`signInState`,
  `UserProfileTab.tsx:34`), including "locked by <email>" from the single read's
  `lockedLocally.byEmail`; the email with Change email… (C2), Resend verification and, since spec 089, Mark
  verified… (C1, local people only); since spec 089 a Profile card (`users/ProfileCard.tsx`) — editable for
  local people, read-only for a directory's — whose fields each name the claim and scope they reach tokens as;
  claims, edited in a drawer and saved in one PATCH, warned when the profile overrides one of them; a Danger
  zone with Hand over… (`can.edit`) and Delete user….
- **Sign-in methods**: the password is said to be set or not only when the record carries `passwordSet`;
  an older account says nothing either way, because an unusable password cannot be recognised afterwards.
  Removing the last identity link of someone with no usable password is asked as
  `user.identity.removeOnly` (C2) rather than `user.identity.remove` (C1): afterwards nobody can sign in as
  them. Since spec 089 a Sessions card (`users/SessionsCard.tsx`) lists the applications they are signed in
  to, with Sign out of this app (C1) per row ([[end-user-support]]).
- **Groups**: one request per membership, through the group's own routes. The old edit dialog diffed groups,
  status and claims and sent several requests, so a failure halfway left the person half changed; there is
  no longer a save that spans more than one request.
- **Activity**, for those with `can.edit`: the audit entries whose target is this person. Sign-ins are not
  recorded per person, and changes to a group they are in are recorded against the group; the tab says the
  first and links to Audit for the rest.

## The email change asks with the dialog out of the way

`onChangeEmail` (`UserProfileTab.tsx:89`) closes the form, asks the C2 question, sends, and on a refusal
naming `field: 'email'` reopens the form with the address and the server's sentence on the field. That keeps
the rule that no dialog opens on top of another while still putting a taken address where it was typed. The
change sends no message: the operator resends when the person expects it.

## Choosing people from a large bucket

The user-groups member picker used to be handed the whole user list. It is now
`lib/admin/ui/pages/users/UserSearchSelect.tsx:14`, which asks the server for the first 20 matches of what is
typed and keeps the labels of people already chosen.

## Shared with phase 4

`lib/admin/ui/accounts/` holds what an administrator's account will need too: the status tags, the set-
password dialog (with "Also sign out everywhere", one request), the lock dialog, and the claims drawer, whose
parser refuses a name in `lib/consts/reserved_claims.ts` on the field before the server does.
