# Article ideas

The backlog of blog posts not written yet. Pick one, write it as `<slug>.mdx` in this directory with
`draft: true`, and delete its entry here in the same commit. This file is not part of the site: the blog
collection loads `*.mdx` only, and Prettier ignores this directory.

Before writing, read [README.md](README.md) (front matter, diagrams, the length bands the build
enforces) and the three published posts for the voice.

## How a post is shaped

- One claim practitioners get wrong, argued with specifics. The title is that claim, not the topic.
- Every H2 is itself a claim. The post ends with when to use the thing and when not.
- Open with a concrete situation, request or bug, not a definition. First person where it is earned.
- Two to four inline SVG diagrams, each placed where the reader needs the structure, with a sentence
  before saying what to look at and a paragraph after saying what follows from it.
- Real HTTP and real code from `lib/`, abridged honestly. No analogies, no bold inside paragraphs,
  no "In conclusion".
- Verify every fact against the code before writing it; the wiki can lag the code.
- Say what has not been tested. As of 0.9.0: global token revocation has not been run against a real
  Okta organisation, Okta's SCIM CRUD test has not been run, there is no `/Bulk`, and certification has
  not been applied for. Re-check this list before reusing it.

## Checking a draft

The build skips drafts, so its rules never see one. To check a post, set `draft: false` locally, run
`SITE_SKIP_CAPTURE=1 bun run build` in `website/`, read the `seo:` lines, and set `draft: true` again
before committing. Do not run Prettier on this directory: it reflows the SVGs, and the repository
ignores it on purpose. Braces inside an SVG `<text>` must be written `&#123;` and `&#125;`, or MDX
reads them as an expression.

## Ideas

### Rotate signing keys: publish, wait, promote

Claim: key rotation is a waiting problem, not a cryptography problem. Why promotion waits twice the
30-second per-instance cache, with no messaging between instances; one signer per algorithm (RS256 beside
PS256/ES256 for FAPI) and why "one per key type" was wrong; retired keys verify for a day and are hidden,
never deleted; the 0.8.0 migration picking the old signer (lowest kid on PostgreSQL); what a relying
party must do (select by `kid`, refetch on an unknown one with a cooldown). Diagram: a timeline of two
instances and a relying party cache across generate, promote, retire.
Sources: `wiki/concepts/signing-keys.md`, `per-issuer-isolation.md`, `lib/admin/key_lifecycle.ts`,
`lib/keys/issuer_keys.ts`, migration `2026-09-30-root-keys-lifecycle`.

### SCIM deprovisioning: 429 is the safe answer

Claim: the status code you refuse with is a contract with the client's retry logic. Okta retries only
a 429 by itself and turns a 5xx into a manual task; Entra escrows any failure and quarantines a job on
401/403/404. The hold, release-only, the email sent once (the one audit entry written after the write,
and why). Exact counting without transactions: a ring of slots claimed by insert-if-absent, proven on
real MongoDB with 100 concurrent requests and 10 admitted. Diagram: the ring of slots.
Sources: `wiki/concepts/scim-provisioning.md` (the guard section), `lib/provisioning/deprovision_guard.ts`,
`database/verify_deprovision_guard.ts`, CONFORMANCE.md deviation row.

### Groups in a token: names, 200, then userinfo

Claim: the groups claim is a list until it is not, and a resource server is the one that cannot follow
it. Display names rather than ids, and what a rename does; the 200 limit taken from Entra; the
distributed-claim reference (OIDC Core 5.6.2) in the ID token while UserInfo carries the whole list;
the snapshot in resource tokens (RFC 9068); `conformIdTokenClaims` keeping it out of the ID token by
default. Diagram: where the claim appears for 3 groups and for 300.
Sources: `wiki/concepts/bucket-groups.md`, `lib/consts/groups_claim.ts`, `lib/bucket_groups/claim.ts`,
`lib/addon/account.ts`.

### Group members are records, not an array

Claim: a member list on the group document is quadratic write volume and a size ceiling. Entra fills
groups in PATCH batches of 40-200; 100,000-member groups are real; MongoDB's 16 MB caps an array at about
370,000 members. All-or-nothing PATCH without multi-document transactions on a standalone `mongod`: every
refusal decided before the first write. Measured: a 50-member change into a 10,000-member group stays
around 10 ms. Diagram: write volume per batch, array against records.
Sources: `wiki/concepts/bucket-groups.md`, `lib/bucket_groups/service.ts`,
`lib/consts/storage_divergences.ts` (`bucket-group-change-atomicity`), CONFORMANCE.md.

### Back-channel logout should keep offline access

Claim: a logout token reports a sign-out, not a compromise, and treating it as one breaks offline
clients. What `sid` and `sub` each end; why the session stores a digest of the upstream `sid`; the
`UpstreamSession` index and its 14-day gap; `200` for a token that matches nobody; Keycloak's
`revoke_offline_access` ignored; older Keycloak sending no `exp`. Verified against a real Keycloak 26.8.0.
Diagram: which sessions a `sid` token and a `sub` token end.
Sources: `wiki/concepts/upstream-back-channel-logout.md`, `lib/upstream_signals/back_channel_logout.ts`.

### Your error response is a redirect too

Claim: an authorization error sent to an unvouched redirect URI is an open redirect (RFC 9700 4.11.2).
Which clients count as unvouched (dynamic registration, metadata documents), the interstitial that names
the destination host, and why administrator-created clients keep plain redirects.
Sources: `wiki/concepts/untrusted-redirect-confirmation.md`, `interaction-error-delivery.md`,
`lib/shared/authorization_error_delivery.ts`, `lib/models/client/provenance.ts`, CHANGELOG 0.8.0.

### `amr` present does not mean a second factor

Claim: testing for the presence of `amr` is how relying parties mistake a password for MFA. What the
server reports for password, one-time code, federated and CIBA sign-ins, and why the claim was recorded
since the second factor shipped but never emitted until 0.8.0. Short post.
Sources: `wiki/concepts/amr-reporting.md`, CHANGELOG 0.8.0 (#46).

### Discovery is a promise the token endpoint has to keep

Claim: advertising a grant type the token endpoint refuses, or accepting one it does not advertise, is
a bug either way. `refresh_token` tied to `offline_access` being a supported scope; the
`refreshToken.enabled` flag that changed nothing observable; algorithms that follow the live key set.
Sources: `lib/configs/discoverySupport.ts`, CHANGELOG 0.8.0.

### Single use is a property of the write, not the read

Claim: check-then-spend is broken under concurrency, and the tests that pass are sequential. One
authorization code yielding five token sets, a refresh token forking into chains, replayed assertions;
`consume` answering whether this call spent the record. Diagram: five parallel exchanges against one code.
Sources: `wiki/concepts/single-use-under-concurrency.md`, CHANGELOG 0.7.0 (Security).

### The issuer is the unit of tenant isolation

Claim: a shared key set makes every resource server's `iss` check a tenant boundary nobody reviews.
Per-bucket keys against the Entra `iss`/`tid` model; squatting on a resource identifier; why the switch
had no transition window.
Sources: `wiki/concepts/per-issuer-isolation.md`, `mcp-server-authorization.md`, CHANGELOG 0.7.0.

### An SSRF check that matches text is not a check

Claim: URL parsing rewrites addresses, so a pattern over the string lets the metadata endpoint through.
`[::ffff:169.254.169.254]` becoming `[::ffff:a9fe:a9fe]`, NAT64 and 6to4 forms, comparing numerically;
redirects re-checked per hop; DNS rebinding as the limit that needs an egress proxy.
Sources: `lib/shared/egress.ts`, CHANGELOG 0.7.0, threat model limitations.

### A client that is stored nowhere

Claim: synthesizing an OAuth client from the record that owns its credential beats storing a second
copy. The `scim-<connection id>` client: the whole token endpoint reused, rotation as one write, tokens
swept on reissue; secrets stored as digests, and why ordinary client secrets still cannot be.
Sources: `wiki/concepts/scim-provisioning.md`, `lib/provisioning/client.ts`, `lib/models/client/secret.ts`.
