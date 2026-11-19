---
type: concept
title: 'Passkeys: one RP ID per address, one origin, records that outlive a lock'
tags: [architecture, contract, gotcha]
sources: [oauth-server-codebase]
created: 2026-11-19
updated: 2026-11-19
graph:
  node_type: concept
  relationships:
    - predicate: relates_to
      object: concept:amr-reporting
      source: oauth-server-codebase
      evidence: "passkey: ['pop', 'user', 'mfa']"
      confidence: high
      status: current
    - predicate: relates_to
      object: concept:totp-second-factor
      source: oauth-server-codebase
      evidence: 'return freshPasskey(session) || freshCode(session);'
      confidence: high
      status: current
    - predicate: relates_to
      object: concept:project-is-an-issuer
      source: oauth-server-codebase
      evidence: 'rpId: issuer.hostname,'
      confidence: high
      status: current
---

# Passkeys

Since spec 139 (2026-11-19, uncommitted at the time of writing) a person signs in to a project with a passkey
(WebAuthn), and adds, renames and removes their own on **Sign-in and security** (`/account/security`, the page that was
"Two-step verification"). A project accepts passkeys only when an operator turns **Passkeys** on (`passkeyLogin`, off by
default) and never on the administrators' project (`passkeysAccepted`, `lib/passkeys/accepted.ts:12`). Spec 140 (A2,
same release) adds the operator's view and revocation, the agent's passkey tools, a holder count on the Sign-in tab and
a passkey block in the address change preview: see "Operator and agent" below.

## One RP ID and one origin, both from the issuer

`relyingPartyOf(bucket)` (`lib/passkeys/relying_party.ts:21`) derives both from `issuerFor(bucket)`
([[project-is-an-issuer]]): the RP ID is the issuer's hostname, the origin its origin, the name the project's shown name.
So:

- **Path projects** share the instance's host as RP ID and the instance's origin. A passkey of one path project is
  offered at another's page; the door refuses it because the lookup is by project (below), not by RP ID.
- **Subdomain and host projects** have their own host, so the browser offers only their own passkeys there.
- **The default project, and a legacy project with no address** (`unaddressed`), are served at the root: the
  instance's host and origin.
- Each record keeps the `rpId` it was made for. A project that moves between a path, a subdomain and a hostname, or an
  `ISSUER` whose host changes, strands its passkeys: they are listed on the person's page as made for an old address and
  refused at the door (`passkeyWorks`, `lib/passkeys/account.ts:286`). A rename of a path keeps them (same host).
- **Exactly one expected origin and one RP ID** reach the library (`verifySignIn`, `lib/passkeys/ceremony.ts:313`), both
  from the issuer and never from the request, so an `X-Forwarded-Host` changes neither.
- `passkeysPossible` (`relying_party.ts:41`) refuses an IP-address `ISSUER` (an IP cannot be an RP ID);
  `passkeysNeedHttps` (`:50`) only warns about plain `http` outside `localhost`, so this suite's `http://e.ly` can turn
  them on.

`Permissions-Policy` grants `publickey-credentials-create=(self)` and `publickey-credentials-get=(self)` on every
response (`lib/plugins/securityHeaders.ts:109`); `frame-ancestors 'none'` keeps the pages out of any frame, and the
ceremony refuses a response whose client data says `crossOrigin: true` or carries any `topOrigin`
(`ceremony.ts:128-135`).

## The library, behind one module

`lib/passkeys/ceremony.ts` is the only importer of `@simplewebauthn/server` (14.1.0; the browser package 14.0.0 is in
`loginClient.js`, the console bundle and `public/passkeyButton.js`). Every call passes one origin, one RP ID, one
challenge and `requireUserVerification: true`. What the library leaves to its caller is done there:

- **The user handle.** The library does not compare it; a response naming another handle than the account's
  `webauthnUserId` is refused (`ceremony.ts:352`). `webauthnUserId` is 32 random bytes written once
  (`ensurePasskeyIdentity`, `lib/end_users/service.ts:762`), never shared between two accounts of one person, and
  stripped from every administrative and agent read.
- **The counter is checked after the signature.** The library compares the counter *before* it verifies the signature,
  so it is given counter 0 and the comparison is made afterwards (`ceremony.ts:330-357`): otherwise anyone who saw a
  credential id could post a forged low counter and get the genuine passkey marked as copied. A counter that stays at
  0 is accepted (many synced passkeys never count); one that goes back with a valid signature returns `counter_back`,
  and the door marks the passkey (`copiedAt`), refusing it until the person removes it.
- **The `Reflect.getMetadata` polyfill.** Importing the library installs a global polyfill (its attestation code
  pulls in `@peculiar/x509`, which loads `reflect-metadata`). Nothing here reads it and attestation is always `none`,
  so it changes no behaviour; the comment at `ceremony.ts:7` records it because this import is the only way it arrives.

## The door: `POST /ui/:uid/passkey`

`judgePasskey` (`lib/passkeys/sign_in.ts:109`, route at `lib/interactions/index.ts:1971`) checks in this order:

1. the project still accepts passkeys (re-read);
2. the caller is under 30 failures an hour (`PasskeyAttemptTally`, `lib/passkeys/limits.ts:40`), **before any lookup**;
   past it, 429 with `Retry-After`. Only failures count; a success never does;
3. the interaction's challenge (`passkeyChallenge`, 5 minutes) is taken off whatever follows, so any attempt spends it;
   a missing or stale one re-renders "Try again" and is not counted;
4. the credential is looked up **in this project only** (`findByCredential(bucket._id, …)`), its account exists here,
   it was made for the current RP ID and is not marked;
5. the signature verifies (above), then the counter, then a conditional counter write (`recordUse`, "only where the
   stored counter is lower, or both are 0"), so two racing responses never both sign in;
6. then the password door's own gates (`accountGates`, `lib/interactions/index.ts:1188`): locked or deactivated is
   "This account can't sign in right now. Ask the people who run {service}.", an unconfirmed address where the project
   requires one is the password door's page.

Every failure from step 4 on is one sentence, "This passkey isn't for {service}. Choose another one, or sign in
another way.", whoever's passkey it was, so nothing says whether it is known elsewhere. Where the account is known,
the person's activity gets `passkey_refused`; never for an unknown passkey. There is no `noteAttack` and no
`signalUnknownCredential`.

The offer (`offerFor`, `sign_in.ts:59`) is on every sign-in page form (password, providers only, the attacker list's
refusal), with `allowCredentials` empty, the email field `autocomplete="username webauthn"` for autofill, and a button.
The script posts the answer natively through a hidden form, copying the password form's "Remember me" tick. **Gotcha**:
antd's `<Form name="login">` renders `id="login"`, not a `name` attribute, so the selector is `REMEMBER_TICK`
(`form#login …`, `lib/interactions/loginPage.tsx:50`); the first version used `form[name="login"]`, matched nothing in a
browser and remembered every passkey sign-in. Only the browser walk showed it, since the specs post the form
themselves; `test/passkeys/sign_in_page.spec.ts` now runs the selector over the rendered page.

It is **not** offered on a password-only re-authentication (the account page's own client asking `acr_values` =
the password value, `passwordOnlyReauthentication`, `sign_in.ts:39`), which turning two-step verification on or off
needs.

## What a passkey sign-in reports, and meets

`AMR_FOR_METHOD.passkey` is `['pop', 'user', 'mfa']` and `DISTINCTION_FOR_METHOD.passkey` is `multi_factor`
(`lib/consts/amr.ts:38-51`): one table both the `acr` and the `amr` writers read, so a passkey sign-in reports the
multi-factor context and therefore meets every requirement of two-step sign-in (an app's `signIn.requireCode`, an
API's sign-in requirement, a proxy condition `withCode`, an essential `acr`) with no code asked. The console and the
agent's tools say "two-step sign-in" for those requirements, and "a code or a passkey" where the project accepts
passkeys.

The **method** a record shows is read from `amr` before `acr`: `pop` means passkey (`lib/person_activity/record.ts:186`),
since `acr` alone cannot tell a passkey from a password and a code. A refusal at the passkey door carries
`method: 'passkey'` too, so a locked or deactivated account turned away there reads "Right passkey, but the account is
locked" and records what that door showed, not the password door's sentence (`lib/person_activity/words.ts`).

## The person's page: freshness

| Act | Needs |
| --- | --- |
| Add | a strong sign-in ≤ 15 min (`strongRecentSignIn` = `freshPasskey` or `freshCode`, `lib/totp/self_service.ts:117-132`), or a fresh password plus a link mailed to this browser (purpose `passkey_add`, 10 minutes, once, newest only) |
| Rename | any sign-in ≤ 15 min (`freshSignIn`) |
| Remove | as Add (link purpose `passkey_remove`, naming the passkey) |
| Two-step verification on / off | unchanged: a fresh password, or a fresh code; a passkey sign-in does not open them |

A provider-only person (no password, no passkey) cannot add one. Adding needs a confirmed address and mail. At most 20
per person. Adding never raises the session (`acr`, `amr`, `loginTs` unchanged). The add ceremony
(`PasskeyCeremony`, `add:<session uid>`, 5 minutes) is consumed and destroyed on use.

**The last-way-in rule** (`isLastWayIn`, `lib/passkeys/account.ts:299`): removing a working passkey is refused when
nothing else would let the person in: a password while the project's password sign-in is open, a link to a provider
the project offers, or another working passkey. A passkey that does not work (old address, marked) is never the last
way.

The page carries **one script**, `public/passkeyButton.js`, only while the add form is rendered; every other state,
and the list with its Rename and Remove forms, works with scripts off ([[interaction-page-families]]).

## "This wasn't me", on the record

The "added" mail carries a link valid 72 hours. Its state lives **on the passkey record** (`notMe: { digest, exp }`),
not in a session-owned or account-owned area, so whoever added the passkey cannot kill the owner's link by signing out
everywhere. The token is `<record id>.<secret>`, looked up only in the project the request is addressed to
(`notMePasskey`), so at another project's address it names nothing. A project served at the root with no address of
its own cannot be named by its address, so its link adds `&project=<id>`, accepted only for a project that is
`unaddressed` and shares the root's page address (`notMeBucketId`, `lib/passkeys/account.ts:447`). Opening only shows a
confirmation; the POST (`fromThisOrigin`) spends the link (`spendNotMe`, conditional) and runs `disownPasskeys`
(`lib/end_users/service.ts:583`): audit `enduser.passkey.disown`, remove that passkey **and every one added at or after
it**, `revokeAccountAccess`, then a password-reset mail where the person has a password and the project offers reset.

## Operator and agent (spec 140)

- **One rule for "another way in"** lives in `lib/passkeys/ways_in.ts`: a password while the project's password door is
  open, or a link to a provider the project has enabled (`otherWayIn`, `:62`). A passkey counts only in state `works`
  (`passkeyState`, `:20`: `copied`, then `old_address`, then `off`, judged in that order). The person's own removal
  (`isLastWayIn`), the turn-off preview (`passkeyOnlyPeople`, `lib/admin/buckets/sign_in_preview.ts:221`), the address
  change preview and the console's revocation dialog all read it. Before spec 140 the turn-off preview counted a passkey
  of an old address, or a copied one, as a way in.
- **Counting holders** is one store read, `holdingIn(bucketId, rpId)` (`lib/adapters/types.ts:2855`): the people
  holding passkeys of that RP ID and not marked copied, with how many each. It replaced `holdersIn`, which ignored both.
  People are then read a hundred at a time (`usersOf`, `ways_in.ts:34`), never all at once.
- **The console's view** is `GET /admin/api/projects/:id/users/:uid/passkeys` (`lib/admin/users-end/routes.ts:839`): an
  explicit projection (`passkeyView`, `ways_in.ts:92`) that never carries the credential id, public key, counter,
  transports, AAGUID, RP ID or `notMe`, plus `ways`, `restore` (`self`, `admin` or `none`: how someone left with no way
  in gets back) and `mailable` (`passkeysOfPerson`, `:125`). Not audited, like every read of a person.
- **Revocation**: `DELETE …/passkeys/:passkeyId` and `DELETE …/passkeys` (`:857`, `:890`), through `revokePasskey` and
  `revokeAllPasskeys` (`lib/end_users/service.ts:613`, `:636`).
  - The steps: check that the person exists and the passkey is theirs, write the audit entry, remove, then
    `revokeAccountAccess`. That ends sessions, grants and tokens, which is wider than clearing an authenticator: the
    operator revokes because someone else may be signed in with it.
  - A passkey already gone is a 404 that signs nobody out. The losing side of a race may leave an audit entry, as every
    audit-first act can.
  - The entry (`enduser.passkey.revoke`, `enduser.passkey.revoke.all`) counts what went (`cascade: { passkeys: N }`)
    and never names a passkey.
  - The mail (`revoked`, `revoked_all` in `lib/mail/templates/passkeys.ts`) says the people who run the project
    removed it. It carries no link and no name. `notifyPasskey` now answers whether it sent, which the route returns
    as `mailed`.
  - Revoking the last way in is allowed, with the console's dialog saying so first. It is allowed on a provisioned
    person, as clearing an authenticator is.
- **Agent tools**: `project_user_passkey_list` (read), `project_user_passkey_revoke` and
  `project_user_passkey_revoke_all` (both `high`, gated) (`lib/mcp/catalogue.ts:505`, `:1684`, `:1702`).
- **Address change**: `addressChangePreview` compares `rpIdFor(bucket)` with `rpIdFor(target)`
  (`lib/passkeys/relying_party.ts:36`; `lib/admin/buckets/routes.ts:532`).
  - When they differ and someone holds a passkey of the current RP ID, the preview gains `passkeys` (`passkeysLostByMove`,
    `ways_in.ts:175`): counts, the people with and without another way in after the move, and the first 20 addresses of
    those without.
  - It counts whether or not the project accepts passkeys now: a move ends them for good.
  - `expect` gains `passkeyPeople` and `passkeyOnly`, and `sameCounts` compares them with absent read as 0 (`:576`).
  - The move deletes no passkey; the old ones list as `old_address`.
  - Root to path and path to path keep the RP ID, so they say nothing about passkeys.
- **Sign-in tab**: the summary's `passkeyHolders` (`routes.ts:1247`; absent for the administrators' project) drives "N
  of M people have a passkey", "N people have passkeys, which don't work while passkeys are off", or, before anyone
  holds one at the root or a path, the advice to give the project its own address first.

## Storage: an unowned area, removed by hand

`passkeys` (`lib/consts/storage_inventory.ts:191`, `:825-837`) is **unowned**, unique on `(bucketId, credentialId)`,
because a person keeps their passkeys through a lock, a deactivation, a sign-out everywhere and a confirmed reset
(FR-032): an account owner would have swept them with every one of those. So every path that ends the person or the
project removes them itself, each with a why-comment:

- deleting the person: `removeEndUser` (`lib/end_users/service.ts:350`), console, bulk and SCIM alike;
- destroying the project: `destroyBucket` (`lib/admin/buckets/destroy.ts:239`);
- completing a reset of an **unconfirmed** account (`lib/password_reset/challenge.ts:385`), beside `unprovenFactor`;
- an invitation reclaiming an account whose address was never proven (`lib/admin/groups/accept.ts:166`).

`PasskeyCeremony` is account-owned; `PasskeyAttemptTally` is unowned (keyed by caller and UTC hour). Nothing is
sealed: a public key grants nothing (`DECLARED_PLAINTEXT`). A no-op migration fence `2026-11-19-passkeys-fence` marks
the schema version; `db:setup` / `db:setup:pg` provision the areas. `database/verify_passkeys.ts` checks the unique
index and the conditional writes on a real backend.

## Related

- [[amr-reporting]], [[authentication-context-reporting]]: the method table.
- [[totp-second-factor]]: the account page, the shared link store and throttle.
- [[person-activity]], [[new-sign-in-alerts]]: "Passkey" as a method.
- [[end-user-lifecycle]]: what a lock keeps.
- [[non-html-response-hardening]]: the `Permissions-Policy` value.
