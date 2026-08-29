---
type: concept
title: 'Admin console sign-in'
tags: [architecture, contract, gotcha, oidc]
sources: [oauth-server-codebase]
created: 2026-08-04
updated: 2026-08-27
graph:
  node_type: concept
---

# Admin console sign-in

The administrative control plane authenticates operators by running an OpenID Connect
authorization-code flow **against the very server it administers**. `GET /admin/login` redirects to this
server's own `/auth`; `GET /admin/callback` exchanges the code over loopback HTTP at `${ISSUER}/token`
and reads the resulting identity token to learn which operator arrived
(`lib/admin/auth/login.ts`).

So the console is a **relying party on its own issuer**, and that is the whole difficulty: being the
issuer is not a licence to skip verification. Nothing about receiving a token over a loopback exchange
tells the console the token came from that exchange.

## The console must verify, and for a year it did not

Until `specs/017-admin-idtoken-verification` the callback base64url-decoded the token's middle segment
and trusted the `sub` it found. The code said so, with a comment promising that it "MUST be replaced
with full signature verification". The consequence was the highest-value escalation available in the
product: anything shaped like a token named any operator, including the super-administrator who can
rewrite settings, mint clients and read every bucket. RBAC, the audit trail and the last-super-admin
guard all rest on the identity this one step establishes, so they were all defeated at the front door.

Verification now happens in `lib/admin/auth/verifyIdToken.ts` before any claim is read, and returns
only `sub` — the caller has no reason for another claim, so it cannot start using one.

## Verify with the client's registered algorithm, not the advertised list

`idTokenSigningAlgValues` (`lib/configs/jwaAlgorithms.ts`) looks like the natural allow-list and is the
wrong one, twice over:

1. It is `['HS256', ...alg.sign]` — it **contains a symmetric algorithm**. An allow-list that permits
   `HS*` invites verification against a shared secret rather than the server's keys.
2. It is computed at module load from the boot-time `JWKS_KEYS` snapshot, so it goes stale the moment
   the admin JWKS API hot-applies a key of a new type.

The tight answer is the admin client's own `idTokenSignedResponseAlg` — the *same field*
`lib/models/id_token.ts` reads when it signs. Issuer and verifier deriving the algorithm from one
source is what makes the check exact rather than merely plausible. Read it through
`Client.tryFind`, never off the stored payload: a stored client record mixes camelCase and snake_case
spellings (`lib/admin/seed.ts` writes `grantTypes` beside `token_endpoint_auth_method`) and only
`validateClient` normalizes them.

A symmetric algorithm is refused as **policy**, not left to fail on a missing key. The admin console is
registered with no client authentication, so no shared secret exists — refusing makes the state
unrepresentable instead of accidentally unreachable.

## `assertPayload` skips the future-`iat` check on every token that has an `exp`

`lib/helpers/jwt.ts` guards issuance-in-the-future with
`payload.iat !== undefined && payload.exp === undefined && payload.iat > timestamp + clockTolerance`.
Every ID token carries `exp`, so **that branch never runs on an ID token**. Any relying party inside
this codebase that wants the check must make it itself. Same family as the other latent-until-touched
constructs recorded here: harmless while nothing depends on it, silently absent the moment something
does.

`assertPayload` does cover `iss`, `aud` (membership), `exp` and the presence of `sub`, and
`verify()` covers key selection and the signature — which is why the admin verifier delegates to them
rather than re-implementing. See [[token-payload-access-contract]] for the neighbouring hazard.

## This server emits no `azp`

`grep -rn azp lib/ test/` finds nothing. OIDC Core 3.1.3.7 rule 4 requires that a token naming more
than one audience identify the party it was issued for, so the console implements that rule — and its
practical effect is that **a multi-audience ID token is always refused**, since this server cannot
produce one that satisfies it. That is the correct outcome (such a token is not one this server issues
to the console) and it is written as the rule, not as "reject arrays", so it stays right if `azp` is
ever emitted. Do not read the refusal as a bug.

## `IdToken.validate` is not reusable here

`lib/models/id_token.ts` already wraps the same verification engine, pre-wired with
`ignoreExpiration: true`. That is correct for its purpose — an `id_token_hint` at logout is expected to
be old — and fatal for a sign-in. Two callers of one engine beat one function with two meanings and a
security-relevant default one argument from every call site.

## Refusals: identical outside, named on the bus

Every identity-token failure answers with one byte-identical `401`
`{ error: 'invalid_id_token', message: 'login failed' }`, so probing reveals neither which check failed
nor anything about the token or the account. The specific check is emitted as
`admin.login.error` with a `{ reason }` payload and nothing else — the admin plane's first event-bus
emitter (see [[event-bus]]).

Nothing is written to the console, deliberately: `/admin/callback` is unauthenticated and
attacker-triggerable, so an unconditional log line per refusal is a log-amplification vector. This is
the same reasoning that keeps the audit trail's writes behind authorization
([[admin-audit-trail]]), one severity tier down. Sign-in is also **not** audited, for the same reason
`POST /admin/api/logout` is not: session lifecycle, not a state-changing administrative action.

## Signing out must end two sessions, not one

The console holds a session of its own (`_admin_session`, a BFF row) *and* is the subject of a
provider session (`_session`). Destroying only the first is indistinguishable from doing nothing:
`/admin/login` redirects to `/auth`, the `no_session` check
(`lib/helpers/interaction_policy/prompts/login.ts`) sees `accountId` still on the provider session
and returns `false`, and the console client is seeded with `'consent.require': false`
(`lib/admin/seed.ts`) — so `/auth` issues a code with no interaction at all and the operator is back
inside the panel with a fresh session. Being a relying party on your own issuer cuts both ways: it
is what makes sign-in verifiable, and what makes sign-out incomplete unless it is deliberate.

`POST /admin/api/logout` therefore destroys both, server-side, in one request
(`lib/admin/auth/login.ts`), reusing `destroyProviderSession` (`lib/shared/destroy_session.ts`) —
the same teardown the end-session `logout=true` branch runs, so backchannel logout and grant
revocation are not quietly skipped on this path.

It does **not** redirect the browser through the RP-initiated `/logout` endpoint, and the two
reasons are worth keeping: that route is gated on `rpInitiatedLogout.enabled`, so an operator
toggling a protocol feature would silently disable console sign-out; and it answers with a
"Do you want to sign-out?" confirmation page (`lib/html/logout.tsx`), a second click on a button the
operator has already pressed. The registered `post_logout_redirect_uris` such a redirect would need
is consequently still empty, and deliberately so.

The cost is real and is the point: the provider session is global to the browser, so leaving the
console signs that browser out of every relying party it had an SSO session with. That is what
ending a provider session means everywhere else in this codebase.

## Freshness is requested, not merely checked

The console generates a single-use `nonce` alongside the PKCE verifier and CSRF `state`, stores all
three in the short-lived `admin_oauth` binding cookie, and requires the token to carry the nonce back.
Checking a nonce "if present" would have been vacuous — the console controls its own authorization
request, and until this feature it asked for no nonce at all. Genuineness alone does not establish
freshness: without this, a genuine, unexpired, correctly-addressed token captured from another sign-in
is accepted.

## Testing it: mint real tokens, and convert jose's types once

Fixtures are minted through the server's own `JWT.sign` against the live keystore
(`test/admin/id_token_fixture.ts`), so a fixture and the issuer cannot drift — if signing and
verification ever disagree, the positive case fails first instead of a negative case passing for the
wrong reason. The loopback exchange stays stubbed because `ISSUER` points at a fake host under test;
what changed is that the stub returns a *genuine* token.

One type rule surfaced while building it, and it generalizes beyond this feature: **jose's `JWK` is an
interface, so it is not assignable to `Record<string, unknown>`** — TypeScript grants an implicit index
signature to anonymous object types only, never to interfaces. The key plumbing here is
`Record`-shaped (`KeyStore`'s members, `seedJwks`' parameter), so `test/keys.ts` returning
`exportJWK`'s value directly forced every consumer to cast. The fix belongs at that single boundary
(`return { ...jwk, alg }`), not at each call site: convert where a third-party type meets this
repository's vocabulary, once.

## Related

- [[admin-audit-trail]] — what the identity established here is trusted for, and the authorization-first
  rule this reuses.
- [[client-identity-from-database]] — why the admin client's metadata must be read through the model.
- [[token-payload-access-contract]] — the neighbouring class of bug: a claim read from the wrong place.
- [[event-bus]] — the diagnostic channel refusals are reported on.
- [[cookie-path-scoping]] — why the sign-out cookie was cleared under the wrong path, and never removed.
- [[feature-flag-gating]] — the other place a one-header or one-status difference was the whole
  fingerprint.
- [[group-ownership]] — the session this establishes now also carries the console's active scope,
  server-held because it sits on an authorization boundary.

Verified against [[oauth-server-codebase]] as changed by `specs/017-admin-idtoken-verification`.
