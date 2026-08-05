import { Type as t, type Static } from '@sinclair/typebox';

/*
 * One upstream OpenID Provider, configured per user bucket and stored on the bucket document. Tenant
 * isolation is total: bucket A's Google application is not bucket B's, and a bucket manager configures
 * their own without a super-admin.
 *
 * Eleven fields, and each earns its place by being a decision two reasonable deployments differ on.
 * Everything else about the identity mapping is fixed — see COPIED_CLAIMS in ./consts.js — because a
 * setting nobody varies is surface with no requirement behind it, and every setting is a way to be
 * misconfigured.
 */
export interface FederationProvider {
	/* Slug, unique within the bucket. Appears in the start URL, so an operator needs it readable. */
	id: string;
	/* The button label on the login page. */
	displayName: string;
	/* A kill switch that keeps the credentials, so an incident costs no re-provisioning. */
	enabled: boolean;
	/* Discovery source. `https:` only, and validated at write time against its own metadata. */
	issuer: string;
	clientId: string;
	/*
	 * Write-only: masked on every read, absent-means-unchanged on update, and the mask itself refused as a
	 * value. Never in the audit trail — that trail records field names, never values.
	 */
	clientSecret: string;
	/* IdPs differ on which scope yields an email. Must contain `openid`. */
	scopes: string[];
	/*
	 * The linking trust decision, per provider rather than per bucket: Google verifies addresses, and a
	 * corporate Keycloak may assert whatever an operator typed into it.
	 */
	emailTrusted: boolean;
	/* Whether a first-time federated user gets an account at all. */
	provisioning: 'jit' | 'existing_only';
	/*
	 * Empty means any, which is the default — so this is opt-in tightening. Without it an enabled Google
	 * button provisions the entire internet, the classic misconfiguration of this feature. Bare lowercase
	 * domains, matched case-insensitively on the address's domain part. No subdomain wildcarding.
	 */
	allowedEmailDomains: string[];
	/*
	 * The one load-bearing claim mapping: no email means neither link nor provision. Corporate IdPs
	 * commonly use `upn` rather than `email`.
	 */
	emailClaim: string;
}

/*
 * That one account in one bucket holds one subject at one provider. Lives on the user row, which is what
 * makes deletion integrity free: the account cascade destroys the row and bucket deletion destroys the
 * area, so no cascade arm has to know this field exists.
 */
export interface FederatedIdentity {
	providerId: string;
	sub: string;
	linkedAt: Date;
}

/*
 * The short-lived record that stands in for the browser cookie which cannot survive the trip to the IdP.
 *
 * A TypeBox schema rather than an interface for the reason lib/password_reset/types.ts states about its
 * own payloads: the storage-ownership drift guard reads an area's fields at runtime, and an interface
 * erases. Records are written straight through `adapter('FederationState')` and never through a model
 * class, so nothing validates them against this schema — it exists to be introspected, not to gate a
 * write.
 *
 * One area, two stages. `stage: 'pending'` is written by the start route under sha256(state) and holds
 * what the callback needs to finish the exchange; `stage: 'complete'` replaces it under sha256(ref) and
 * holds only the interaction and the account it resolved to. Neither live identifier appears in any
 * field: the id is the digest, so a datastore dump yields nothing replayable (the PasswordResetChallenge
 * rule, applied to both identifiers because a `ref` in a URL is exactly as capturable as a `state`).
 */
export const FederationStatePayload = t.Object({
	stage: t.Union([t.Literal('pending'), t.Literal('complete')]),
	/*
	 * Which interaction this round trip belongs to. The `complete` route refuses a record whose value
	 * disagrees with the `uid` in its own path, which is what stops a handoff being spent on someone
	 * else's interaction.
	 */
	interactionUid: t.String(),
	/* Resolved from the client that started the interaction, never from a request. Stage 1 only. */
	bucketId: t.Optional(t.String()),
	/* Stage 1 only. The provider is re-resolved fresh at the callback, so this identifies, not configures. */
	providerId: t.Optional(t.String()),
	/* Binds the assertion to this attempt. Compared against the ID token's claim. Stage 1 only. */
	nonce: t.Optional(t.String()),
	/* Absent when the IdP advertises no S256, in which case no PKCE was sent. Stage 1 only. */
	codeVerifier: t.Optional(t.String()),
	/*
	 * Stage 2 only — and **optional is what makes one area hold both stages**. The inventory declares this
	 * area account-owned, because the reverse ownership check in
	 * test/storage_contract/inventory_drift.spec.ts fails any area whose payload carries `accountId`
	 * without declaring it. Stage-1 records carry no account, are matched by no sweep, and expire on their
	 * own; stage-2 records name one and die with it. (Task 18's text asked for `unowned`, which that guard
	 * makes unimplementable — see specs/022-oidc-federation-login/research.md D5.)
	 */
	accountId: t.Optional(t.String()),
	/*
	 * Epoch seconds. Mirrors the adapter's expiry *and* is compared to now on every read: MongoDB's TTL
	 * monitor deletes lazily, so a record can outlive its expiry by a minute or more — and a stale handoff
	 * is a sign-in as somebody else.
	 */
	exp: t.Number()
});

export type FederationStatePayload = Static<typeof FederationStatePayload>;
