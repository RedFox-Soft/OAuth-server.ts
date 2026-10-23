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
export const FederationProvider = t.Object({
	/* Slug, unique within the bucket. Appears in the start URL, so an operator needs it readable. */
	id: t.String(),
	/* The button label on the login page. */
	displayName: t.String(),
	/* A kill switch that keeps the credentials, so an incident costs no re-provisioning. */
	enabled: t.Boolean(),
	/* Discovery source. `https:` only, and validated at write time against its own metadata. */
	issuer: t.String(),
	clientId: t.String(),
	/*
	 * Write-only: masked on every read, absent-means-unchanged on update, and the mask itself refused as a
	 * value. Never in the audit trail — that trail records field names, never values.
	 *
	 * Optional since `specs/053-apple-microsoft-github`, because Apple issues no secret at all — it issues
	 * a signing key, and the credential is derived from it per exchange. Absent rather than an empty string
	 * on purpose: a sentinel is a value somebody eventually types, and `credential.ts` refuses the absence
	 * outright for a provider whose credential model needs one.
	 */
	clientSecret: t.Optional(t.String()),
	/* IdPs differ on which scope yields an email. Must contain `openid`. */
	scopes: t.Array(t.String()),
	/*
	 * The linking trust decision, per provider rather than per bucket: Google verifies addresses, and a
	 * corporate Keycloak may assert whatever an operator typed into it.
	 */
	emailTrusted: t.Boolean(),
	/* Whether a first-time federated user gets an account at all. */
	provisioning: t.Union([t.Literal('jit'), t.Literal('existing_only')]),
	/*
	 * Empty means any, which is the default — so this is opt-in tightening. Without it an enabled Google
	 * button provisions the entire internet, the classic misconfiguration of this feature. Bare lowercase
	 * domains, matched case-insensitively on the address's domain part. No subdomain wildcarding.
	 */
	allowedEmailDomains: t.Array(t.String()),
	/*
	 * The one load-bearing claim mapping: no email means neither link nor provision. Corporate IdPs
	 * commonly use `upn` rather than `email`.
	 */
	emailClaim: t.String(),
	/*
	 * The four below arrived with `specs/053-apple-microsoft-github`, and every one of them is here because
	 * it cannot be derived from anything else. All are optional, so every record written before them is
	 * valid unchanged and there was no migration.
	 *
	 * Note what is NOT here: nothing records which protocol this provider speaks, which recognised entry it
	 * is, or which route created it. The protocol is resolved from `issuer` through the catalogue on each
	 * use, exactly as the login page already resolves the button's mark — so no sign-in decision is *able*
	 * to branch on a provider's provenance. That was true before this feature and adding a field here
	 * would have quietly ended it.
	 */
	/*
	 * Which Microsoft accounts may sign in: `common`, `organizations`, `consumers`, or one organisation's
	 * identifier. A per-connection decision about who is admitted, so no catalogue entry can hold it — and
	 * the difference between one company's staff and everyone in the world with a Microsoft account.
	 */
	tenant: t.Optional(t.String()),
	/* Apple: the developer account the signing key belongs to. */
	teamId: t.Optional(t.String()),
	/*
	 * Apple: which key. Readable precisely so that an administrator whose key was revoked can tell which
	 * one to replace — the failure appears on Apple's page, so the only clue available is here.
	 */
	keyId: t.Optional(t.String()),
	/*
	 * Apple: the private key the credential is signed with, and the reason Apple needs no stored secret.
	 * Held to every rule `clientSecret` is — masked on every read for every role, absent-means-unchanged on
	 * update, the mask refused as a value, never in the audit trail. Masked by the *containing* bucket's
	 * projections as well; see the comment on `presentBucket`.
	 */
	signingKey: t.Optional(t.String()),
	/*
	 * Whether this provider may end its users' access here through global token revocation (specs/072) —
	 * Okta Universal Logout. Opt-in per provider, read as `=== true`: absent on every provider stored before
	 * it existed, which is off, so there was no migration.
	 */
	acceptsGlobalTokenRevocation: t.Optional(t.Boolean()),
	/*
	 * Whether this provider's OpenID Connect back-channel logout tokens are received (specs/073) — Keycloak,
	 * Auth0 and Ping send them. Its own option rather than a reading of the one above: a logout ends one
	 * upstream session's sessions here, a revocation ends everything, and an operator may want either alone.
	 * Read as `=== true`, so every provider stored before it is off and there was no migration.
	 */
	acceptsBackChannelLogout: t.Optional(t.Boolean()),
	/*
	 * Whether this project accepts identity assertion grants (ID-JAG, specs/108) signed by this provider: an
	 * agent its people signed in to through the provider then gets tokens for the project's APIs with no
	 * browser and no consent. The trust lives here because an ID-JAG's `sub` is the identifier this provider
	 * gives the project's own sign-in (ID-JAG §5), which is the link this provider already keeps. Read as
	 * `=== true`; absent is off, so there was no migration.
	 */
	acceptsIdentityAssertions: t.Optional(t.Boolean()),
	/*
	 * Plain RFC 7523 assertions about a person from this provider (specs/108 story 4). Unlike an ID-JAG a
	 * plain assertion names no client, so the trust says which of the project's applications may present
	 * one and the most it may yield; its presence is the trust.
	 */
	plainAssertions: t.Optional(
		t.Object({
			clientIds: t.Array(t.String()),
			resources: t.Array(
				t.Object({ identifier: t.String(), scopes: t.Array(t.String()) })
			)
		})
	)
});
export type FederationProvider = Static<typeof FederationProvider>;

/*
 * That one account in one bucket holds one subject at one provider. Lives on the user row, which is what
 * makes deletion integrity free: the account cascade destroys the row and bucket deletion destroys the
 * area, so no cascade arm has to know this field exists.
 */
export const FederatedIdentity = t.Object({
	providerId: t.String(),
	sub: t.String(),
	linkedAt: t.Date()
});
export type FederatedIdentity = Static<typeof FederatedIdentity>;

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
/*
 * An upstream identity waiting to be linked to an account, until that account's own sign-in completes.
 * `claims` are the profile claims a link copies, taken from the assertion that proved the address.
 */
export const PendingLinkIdentity = t.Object({
	providerId: t.String(),
	sub: t.String(),
	claims: t.Optional(t.Record(t.String(), t.Unknown())),
	/* The upstream session the identity was proven in, so the sign-in that completes the link answers to its logout. */
	sid: t.Optional(t.String()),
	/* When that upstream session ends (IPSIE SL1 §3.2.2), so the session the link completes ends with it. */
	sessionExpiry: t.Optional(t.Integer())
});
export type PendingLinkIdentity = Static<typeof PendingLinkIdentity>;

/*
 * Why the decision ladder refused a sign-in (lib/federation/resolve.ts). A schema rather than a bare union so
 * a try's stored result is checked against the same list the ladder answers from.
 *
 * - `no_email`: the assertion carries no address, so nothing can be linked or provisioned.
 * - `domain_not_allowed`: the address is outside a non-empty allow-list.
 * - `link_not_permitted`: an account holds this address, but this provider may not claim it.
 * - `provisioning_closed`: no account, and this provider does not provision.
 * - `inactive`: whichever branch produced it, the account is frozen.
 * - `not_provisioned`: the provider is bound to a SCIM provisioning connection, and no user that connection
 *   provisioned answers to this sign-in's correlation claim. Accounts there are created by the directory,
 *   never by a first sign-in, and never found by email.
 * - `link_conflict`: the correlated user is already linked to a different subject at this provider. Not
 *   re-linked: two upstream identities claiming one provisioned person is an incident, not a sign-in.
 * - `signups_paused`: nobody has an account, and the project's plan has reached its monthly active users
 *   (specs/102). Only a sign-in that would create an account is refused this way.
 */
export const RefusalReason = t.Union([
	t.Literal('no_email'),
	t.Literal('domain_not_allowed'),
	t.Literal('link_not_permitted'),
	t.Literal('provisioning_closed'),
	t.Literal('inactive'),
	t.Literal('not_provisioned'),
	t.Literal('link_conflict'),
	t.Literal('signups_paused')
]);
export type RefusalReason = Static<typeof RefusalReason>;

/*
 * What a try of a provider found (specs/088 US3): what the provider answered, and what a real sign-in would
 * do now — or what went wrong. Read back only by the console session that started the try, for ten minutes.
 * `claims` leaves out `nonce`, `at_hash` and `c_hash`, which describe the exchange rather than the person.
 */
export const TryResult = t.Object({
	providerEnabled: t.Boolean(),
	answer: t.Optional(
		t.Object({
			subject: t.String(),
			email: t.Optional(t.String()),
			emailVerified: t.Optional(t.Boolean()),
			claims: t.Record(t.String(), t.Unknown())
		})
	),
	outcome: t.Optional(
		t.Object({
			kind: t.Union([
				t.Literal('signin'),
				t.Literal('link'),
				t.Literal('password_required'),
				t.Literal('provision'),
				t.Literal('correlate'),
				t.Literal('refuse'),
				t.Literal('conflict')
			]),
			reason: t.Optional(RefusalReason),
			account: t.Optional(
				t.Object({ id: t.String(), email: t.Optional(t.String()) })
			),
			/* A new account's address would be recorded as verified. */
			verified: t.Optional(t.Boolean()),
			/* The provisioning connection whose correlation rule decided, for `correlate` and `conflict`. */
			connection: t.Optional(
				t.Object({ id: t.String(), displayName: t.String() })
			)
		})
	),
	error: t.Optional(
		t.Object({
			stage: t.Union([
				t.Literal('upstream'),
				t.Literal('rejected'),
				t.Literal('declined')
			]),
			reason: t.String(),
			description: t.Optional(t.String())
		})
	),
	/* The bucket has no address yet, so the callback the try used changes when it gets one. */
	callbackProvisional: t.Boolean()
});
export type TryResult = Static<typeof TryResult>;

/* The answer to starting a try: the address to open in a new tab, and the reference its result is read by. */
export interface TryStarted {
	tryRef: string;
	authorizationUrl: string;
	/* When the try's record, and so its result, is gone. */
	expiresAt: string;
}

/* What the console polls for while a try is out at the provider. */
export type TryStatus =
	{ status: 'waiting' } | { status: 'done'; result: TryResult };

export const FederationStatePayload = t.Object({
	/*
	 * `try` is the record a try of a provider writes its result into (specs/088): named by the digest of the
	 * `tryRef` the console polls with, bound to the console session that started it.
	 */
	stage: t.Union([
		t.Literal('pending'),
		t.Literal('complete'),
		t.Literal('try')
	]),
	/*
	 * Which interaction this round trip belongs to. The `complete` route refuses a record whose value
	 * disagrees with the `uid` in its own path, which is what stops a handoff being spent on someone
	 * else's interaction. Absent only on a try, which belongs to no interaction — and a handoff without it
	 * is refused by that same comparison.
	 */
	interactionUid: t.Optional(t.String()),
	/*
	 * Stage 1 only: present when the round trip is a try. Read only from this stored record, never from the
	 * returning request, so a sign-in cannot be turned into a try or a try into a sign-in (specs/088 FR-015).
	 */
	purpose: t.Optional(t.Literal('try')),
	/* Stage 1 of a try: the id of the try record the callback writes the result into. */
	tryId: t.Optional(t.String()),
	/* The try record only: SHA-256 of the console session cookie that started it — RFC 9700 §2.1.1's binding. */
	sessionDigest: t.Optional(t.String()),
	/* The try record only, once the provider has answered. */
	result: t.Optional(TryResult),
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
	 * Stage 2 only, and only when the address matched an account the assertion may not simply claim:
	 * the identity is then carried into the interaction to be linked once that account signs in, and
	 * nobody is signed in by this handoff.
	 */
	link: t.Optional(PendingLinkIdentity),
	/*
	 * Stage 2 only: which provider this sign-in came through and, when its ID token carried one, the
	 * provider's own session identifier — what a back-channel logout from that provider will later name
	 * (specs/073). The raw `sid` may sit here because this record lives only as long as the handoff; the
	 * session that outlives it stores a digest.
	 */
	upstream: t.Optional(
		t.Object({
			providerId: t.String(),
			sid: t.Optional(t.String()),
			/* Epoch seconds: when the provider said its session ends (IPSIE SL1 §3.2.2). */
			sessionExpiry: t.Optional(t.Integer())
		})
	),
	/*
	 * Epoch seconds. Mirrors the adapter's expiry *and* is compared to now on every read: MongoDB's TTL
	 * monitor deletes lazily, so a record can outlive its expiry by a minute or more — and a stale handoff
	 * is a sign-in as somebody else.
	 */
	exp: t.Number()
});

export type FederationStatePayload = Static<typeof FederationStatePayload>;
