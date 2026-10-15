---
type: concept
title: 'SCIM credential overlap: a replaced secret or static token works until the directory has moved'
tags: [architecture, contract, gotcha, oauth]
sources: [oauth-server-codebase]
created: 2026-10-12
updated: 2026-10-15
graph:
  node_type: concept
  relationships:
    - predicate: depends_on
      object: concept:scim-provisioning
      source: oauth-server-codebase
      evidence: "lib/provisioning/client.ts:71 emits previousClientSecretDigest on the synthesized connection client only while isPreviousLive(connection, 'secret')."
      confidence: high
      status: current
---

# SCIM credential overlap

Since spec 088. Before it, issuing a new client secret or static token for a provisioning connection
([[scim-provisioning]]) killed the old one in the same write. Provisioning then failed until someone pasted the
new value into the directory. Microsoft Entra ID quarantines a provisioning job on an invalid credential whatever
the failure count, and retries only after 6, 12 and 24 hours. So every rotation was an outage, and
administrators either skipped rotation or scheduled the outage.

Now a replacement keeps the replaced value working as the slot's single **previous** value, until the directory
has moved to the new one. Only a client secret and a static token overlap.

## The end rule, and why it is not "the first use of the new value"

`previousState` (`lib/provisioning/overlap.ts:71`) is the only place the rule is written. The synthesized client,
the SCIM principal and the connection view all ask it, so the token endpoint, a SCIM request and the console
cannot disagree about whether a previous value still works. A previous value is live while all three hold:

- less than 24 hours have passed since the replacement;
- its own expiry, if it has one (a static token's), has not passed (`latestEndOf`, `:64`);
- it is not the case that the new value has been used **and** an hour has passed since the later of the previous
  value's last use and the new value's first use.

The owner's first rule was simpler: the first use of the new value ends the old one. The standards review
rejected it. Entra's **Test Connection** and Okta's **Test Connector Configuration** both use the new value
before the administrator saves it. An administrator who tested and then cancelled would have lost the value the
directory still runs on, and Entra would have quarantined the job.

Two details of the rule are deliberate:

- **The new value's first use, not its last.** A directory uses the new value continuously, so a rule on its
  last use would never fire.
- **A quiet hour.** It is longer than one Entra provisioning cycle (about 40 minutes). So a directory still
  sending the previous value keeps it alive, up to the 24-hour limit. Meanwhile the view reports
  `stillUsedByDirectory` and the warning `previous_credential_in_use`, and the console card says "The directory
  still uses the previous secret. Update it before …".

The rule is computed on every read and never swept. The connections area is never reaped, and a lazy check is
exact. An end by itself leaves the previous value in the document, not live; the next administrator's act
removes it.

**Use is recorded for the rule** (`noteCredentialUse`, `lib/provisioning/credential_use.ts:14`). "Used" means a
token obtained with the secret, or a SCIM request accepted with the static token. The current value records its
first use, once. The previous value records its last use at most once a minute
(`PREVIOUS_USE_RESOLUTION_MS`, `overlap.ts:30`), so a directory's import does not turn every request into a
write and the quiet hour is still exact to a minute. Each write touches only its own field, so it cannot race
an administrator's replacement.

## Where a previous value is accepted

- **Client secret.** The synthesized client carries `previousClientSecretDigest` only while the previous secret
  is live (`lib/provisioning/client.ts:71`). It is a canonical-only attribute (`BASE_METADATA_KEYS`,
  `lib/models/client/wire.ts:74`), so it can never arrive as wire input, and it is in `ClientSchema`
  (`lib/configs/clientSchema.ts:199`). The client validation memo is keyed by the client's properties, so
  emitting or dropping the attribute takes effect on the next request with nothing to invalidate.
  `compareClientSecret` (`lib/models/client/secret.ts:45`) compares the presented value with **both** digests,
  always, with no short cut: whether a client has a previous secret, and which one matched, must not show in
  how long a refusal takes. It answers `'current' | 'previous' | null`. `tokenAuth` keeps the answer on
  `oidc.clientSecretMatch` (`lib/shared/token_auth.ts:193`), because the resolved client is frozen data.
- **Static token.** The SCIM principal makes two point reads: the current digest, then
  `findByPreviousStaticTokenDigest` (`staticTokenHolder`, `lib/scim/principal.ts:94`), so it knows which one
  matched. The previous digest has a sparse index (`lib/consts/storage_inventory.ts:592`). The index is **not
  unique**: 256-bit values do not collide, and a unique index would need its own duplicate-key mapping in both
  stores. An expired token, and a previous one the rule has ended, are refused as `unknown_token`, the same
  answer as an unknown token.

## A token knows which secret obtained it

A connection's client-credentials token carries `credentialRef`
(`lib/models/client_credentials.ts:17`): the first 16 hex characters of the digest that authenticated the
request, set by the grant for connection clients only (`lib/actions/grants/client_credentials.ts:137`). A
prefix of a 256-bit random value's digest reveals nothing usable. Introspection lists its members by name, so
the marker is never in an answer, and no admin read shows it.

That marker decides what an end does to tokens. The difference between "by an act" and "by itself" is the
point:

- **An end by an administrator's act** stops the previous secret's tokens at once and leaves the new secret's
  tokens working. The acts are retire now, stop now (`overlap: false`), revoke, and another replacement.
  `sweepTokensOfPrevious` (`lib/provisioning/service.ts:514`) destroys the client's tokens whose
  `credentialRef` is the previous value's **or absent**: a token minted before tokens were marked can only have
  come from the value that is now the previous one. The reading and destroying is
  `sweepClientTokensWhere` (`lib/helpers/cascade.ts:148`), which takes the area and owner field from the
  storage inventory like every other sweep.
- **An end by itself sweeps nothing.** Tokens the previous secret already obtained run out on their own, in ten
  minutes at most (`accessTokenTTL`, `lib/provisioning/token_policy.ts:27`).

Two alternatives were rejected. Refusing tokens by marker in the SCIM principal would kill live tokens in the
middle of a provisioning cycle when the rule fires by itself. Sweeping every token of the client would kill the
new value's tokens too, and invite the quarantine the overlap exists to avoid.

A static token obtains no tokens, so ending one sweeps nothing.

## What never overlaps

- **A key credential, and any change of kind**, replace at once with the full client cascade, as before
  (`replaceOauthCredential`, `service.ts:495`, which clears `previousSecret` in the same write). A directory
  rotates its own keys at its key-set address, chosen by `kid`, so a key needs no overlap.
- **More than one previous value.** A replacement during an overlap ends the older previous value first, by
  act, with its tokens. The sweep runs after the write, so the older value can no longer obtain tokens while
  they are being swept (`issueCredential`, `service.ts:369`).
- **A revoke** ends the current and the previous value together (`revokeCredential`, `service.ts:525`).
- With `scim.secretCredentials` or `scim.staticTokens` off, neither value works, as before for the current
  one.

## The administrator's side

- `POST …/credentials` takes `overlap` (default `true`) and answers `previousEndsAt`. The audit entry
  `provisioning.credential.issue` records in `to` the previous value's latest end, or `null` when it stopped at
  once.
- `DELETE …/provisioning-connections/:connectionId/credentials/:kind/previous`
  (`lib/admin/provisioning/routes.ts:267`; `retirePreviousCredential`, `service.ts:554`) ends a live previous
  value now. It is 404 when there is none: one that ended by itself has nothing left to end. It audits
  `provisioning.credential.retire` first. The store removes the value only while its digest is unchanged
  (`retirePrevious`, `lib/adapters/types.ts:1557`), so two administrators retiring together act once. MCP
  `provisioning_credential_retire` is **ordinary**, like revoke: it only removes access.
- An end by itself is not an act. It is shown, not recorded ([[admin-audit-trail]]).
- The connection view has `previous` only while it is live: issued, replaced, latest end, last use and
  `stillUsedByDirectory`. Never a digest or a `credentialRef`.
- The console's Credentials card shows two rows for the slot, with **Retire previous now**
  (`lib/admin/ui/pages/provisioning/ConnectionPage.tsx:582`). The replace question offers **Stop the current one
  now** for a leaked value (`:1106`).

## Static tokens expire

RFC 7644 §7.4 says "Bearer tokens MUST have a limited lifetime", and the IPSIE profile §8 says access tokens
"SHALL expire". Until spec 088 a static token lived until someone replaced it.

- An issue takes `lifetimeDays`, 90 or 365, default 365, and refuses it (422) for any other kind. The connection
  stores `staticTokenExpiresAt`. The principal refuses an expired token as `unknown_token`
  (`lib/scim/principal.ts:103`).
- A previous token keeps its own expiry, and whichever end comes first applies.
- Within 14 days of the expiry the view adds `static_token_expiring`, and after it `static_token_expired`. Both
  appear on the connection and in the project Overview's Needs attention
  (`lib/admin/ui/pages/BucketOverview.tsx:94`), with a link to the connection.
- **Tokens issued before spec 088** get an expiry from migration `2026-10-12-static-token-expiry`
  (`lib/consts/migrations.ts:905`). The expiry is one year after the issue, but never sooner than 90 days after
  the migration; a token with no known issue time gets the 90 days. It is a data change rather than a default
  computed on read, because such a default would expire every token older than a year on the day of the
  upgrade. It is safe to apply twice: it reads only tokens without an expiry and writes conditionally.

## Standards

- Overlap is compliant. RFC 6749 §2.3.1 and OAuth 2.1 §2.4.1 do not limit concurrent secrets. OAuth 2.1 §3.2.1
  calls periodic rotation best practice, and RFC 7592 Appendix A.1 lets a server issue new credentials over a
  client's lifetime. Okta itself keeps two active client secrets.
- RFC 6819 §5.2.3.6: revoking a client secret should invalidate what it obtained. That is why an act sweeps by
  `credentialRef`.

`test/provisioning/credential_overlap.spec.ts` and `test/provisioning/static_token_expiry.spec.ts` hold the
behaviour; `database/verify_088_scim_overlap.ts` is the real-database check of the previous-digest lookup, the
use writes, the conditional retire and the migration.

## Related

- [[scim-provisioning]] — the connection, its synthesized client and the deviation settings.
- [[deletion-and-revocation]] — the client cascade that a key or a change of kind still runs.
- [[admin-mcp-control-plane]] — the retire tool and its consequence class.

Verified against [[oauth-server-codebase]].
