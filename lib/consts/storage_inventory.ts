/*
 * The declared inventory of persistent storage areas: every collection the server writes to, and the
 * indexes each one carries. `bun database/mongodb.ts` provisions from this table, the MongoDB store
 * classes take their collection names from it, and a two-way drift guard
 * (test/storage_contract/inventory_drift.spec.ts) fails the suite when the table and the code
 * disagree in either direction.
 *
 * This module deliberately imports nothing. `lib/adapters/mongodb/db.ts` opens its connection at
 * module scope and throws without MONGODB_URI, so anything reaching it is unloadable from the test
 * suite — which runs with no MONGODB_URI on purpose. Keeping this file import-free is what lets the
 * drift guard verify production storage without a production datastore.
 */

export type AreaKind = 'model' | 'store' | 'perBucket';

export interface IndexSpec {
	readonly key: Readonly<Record<string, 1>>;
	readonly unique?: boolean;
	readonly expireAfterSeconds?: number;
}

/*
 * Which payload field names the principal an area's records belong to. One deletion engine reads this
 * for every area (lib/helpers/cascade.ts), so no call site enumerates collections: a cascade that was
 * hand-written per entity fails silently the first time an area is added, and two of the areas swept
 * here — ClientCredentials, which carries no grantId at all, and RegistrationAccessToken, which may be
 * issued with no expiry — are exactly the ones an author forgets.
 *
 * `reason` is required when nothing is owned and forbidden otherwise, so "no owner" is always a written
 * decision rather than a blank field. Same rule `reaped: null` follows, enforced the same way by
 * test/storage_contract/inventory_drift.spec.ts.
 */
export interface OwnerFields {
	readonly account: string | null;
	readonly client: string | null;
	readonly reason?: string;
}

export interface StorageArea {
	readonly name: string;
	readonly kind: AreaKind;
	/*
	 * The field an expiry index is built on, or null for an area whose records are permanent. Stated
	 * per area and never defaulted: the defect this table replaced was an `else` branch that applied
	 * an expiry index to every collection it did not otherwise recognise, so a new area inherited
	 * reaping by omission. `null` here has to be a decision someone wrote down.
	 */
	readonly reaped: string | null;
	readonly owners: OwnerFields;
	/*
	 * Indexes other than the expiry one, which indexesFor() derives from `reaped`, and the owner ones,
	 * which it derives from `owners` — so a field the cascade sweeps is always a field the datastore can
	 * find without a scan.
	 */
	readonly indexes: readonly IndexSpec[];
}

/*
 * Areas written through the model adapter (lib/adapters/mongodb/mongoAdapter.ts), stored as
 * `{ _id, payload, expiresAt? }`. This tuple is the runtime source of truth for KnownModelName —
 * the type is derived from it rather than the reverse, because only a value can be compared in a
 * test, and `keyof ModelPayloadByName` vanishes at runtime.
 */
export const MODEL_AREAS = [
	'AccessToken',
	'AuthorizationCode',
	'BackchannelAuthenticationRequest',
	'Client',
	'ClientCredentials',
	'DeviceCode',
	'FederationState',
	'Grant',
	'InitialAccessToken',
	'Interaction',
	'LoginThrottle',
	'PasswordResetChallenge',
	'PasswordResetThrottle',
	'PushedAuthorizationRequest',
	'RefreshToken',
	'RegistrationAccessToken',
	'ReplayDetection',
	'Session',
	'TotpAttempt',
	'TotpEnrollment',
	'VerificationChallenge',
	'VerificationResend'
] as const;

export type ModelAreaName = (typeof MODEL_AREAS)[number];

/*
 * Areas owned by a dedicated store class rather than by the model adapter. Imported by those classes
 * so each name is written exactly once in the repository — the two-places-one-name arrangement this
 * replaced is how `serviceConfig` came to be used at runtime and never provisioned.
 */
export const STORE_AREAS = {
	jwks: 'jwks',
	projects: 'projects',
	userBuckets: 'userBuckets',
	/* The owner of every project and user bucket, and the only thing that grants access to one. */
	groups: 'groups',
	/* Pending invitations into a group. Single-use, and reaped on their own expiry. */
	groupInvitations: 'groupInvitations',
	adminSession: 'adminSession',
	adminAudit: 'adminAudit',
	/* Pending confirmations for the MCP control plane's high-consequence operations. */
	mcpConfirmation: 'mcpConfirmation',
	/* Recorded internal server faults, grouped by fingerprint. */
	errorStore: 'errorStore',
	/* One area, four writers: configStore keeps the persisted ApplicationConfig, SmtpSettingsStore the
	 * SMTP credentials, and two SingletonSecretStore instances the server's DPoP nonce secret and its
	 * pairwise identifier salt — singleton documents distinguished only by a derived ObjectId. One
	 * inventory entry, therefore, not four. Both secrets joined this area rather than claiming one
	 * each because it is already declared permanent (`reaped: null` below): a secret that expired on
	 * its own would be silently regenerated at the next startup, churning every client's nonces for no
	 * visible reason — and, for the salt, permanently breaking every relying party's account linkage. */
	serviceConfig: 'serviceConfig'
} as const;

export type StoreAreaName = (typeof STORE_AREAS)[keyof typeof STORE_AREAS];

/* Each user bucket owns one end-user collection, named for the bucket. */
export const USER_AREA_PREFIX = 'user_';

export function userAreaFor(bucketId: string): string {
	return `${USER_AREA_PREFIX}${bucketId}`;
}

const EXPIRES_AT = 'expiresAt';

/*
 * Indexed on exactly the five areas revokeByGrantId deletes from (lib/helpers/revoke.ts). Grant
 * itself does not need it: a grant is addressed by _id, which *is* the grantId.
 */
const grantId: IndexSpec = { key: { 'payload.grantId': 1 } };

/* Ownership shorthands. Named rather than inlined so the table below reads as a matrix. */
const byAccountAndClient: OwnerFields = {
	account: 'accountId',
	client: 'clientId'
};
const byAccount: OwnerFields = { account: 'accountId', client: null };
const byClient: OwnerFields = { account: null, client: 'clientId' };
const unowned = (reason: string): OwnerFields => ({
	account: null,
	client: null,
	reason
});

const modelArea = (
	name: ModelAreaName,
	reaped: string | null,
	owners: OwnerFields,
	indexes: readonly IndexSpec[] = []
): StorageArea => ({ name, kind: 'model', reaped, owners, indexes });

const storeArea = (
	name: StoreAreaName,
	reaped: string | null,
	owners: OwnerFields,
	indexes: readonly IndexSpec[] = []
): StorageArea => ({ name, kind: 'store', reaped, owners, indexes });

/*
 * The templated per-bucket area. `name` holds the prefix rather than a real collection name; the
 * concrete areas are `userAreaFor(bucket._id)`, provisioned one per bucket. Uniqueness on `email`
 * is per area and therefore per bucket, and case-insensitive for free: UserStore lowercases on
 * both write and read, so the stored value is already normalised.
 *
 * Declared here rather than inline in the table below so PER_BUCKET_AREA can be exported directly.
 * Searching the table for it and asserting the result non-empty — which is what this replaced — was
 * claiming certainty about a search for something the module itself had just written.
 */
const perBucketArea: StorageArea = {
	name: USER_AREA_PREFIX,
	kind: 'perBucket',
	reaped: null,
	/* Holds the end-user principals themselves; destroyed with its bucket, never swept by owner. */
	owners: unowned('holds the account records a cascade sweeps on behalf of'),
	indexes: [
		{ key: { email: 1 }, unique: true },
		/*
		 * Resolves an account from the upstream identity it holds (UserStore.findByFederatedIdentity).
		 *
		 * Non-unique on purpose, and this is a recorded compromise rather than an oversight. A unique
		 * multikey index would index every password-only account as {null, null} and collide on the second
		 * one, so real uniqueness would need a partialFilterExpression — which IndexSpec above does not
		 * model, and extending it would mean extending the provisioning routine and the two-way
		 * reconciliation comparison with it. Uniqueness of (providerId, sub) is therefore enforced in code
		 * at link time. The residual race is a concurrent double-link, whose outcome is a duplicate entry
		 * naming the *same* account — never two accounts sharing an identity, because the lookup is by the
		 * pair.
		 *
		 * Bare field names, not `payload.*`: this area is written by UserStore directly rather than through
		 * the model adapter, so its documents have no `payload` wrapper.
		 */
		{ key: { 'federated.providerId': 1, 'federated.sub': 1 } }
	]
};

export const STORAGE_INVENTORY: readonly StorageArea[] = [
	modelArea('AccessToken', EXPIRES_AT, byAccountAndClient, [grantId]),
	modelArea('AuthorizationCode', EXPIRES_AT, byAccountAndClient, [grantId]),
	modelArea(
		'BackchannelAuthenticationRequest',
		EXPIRES_AT,
		byAccountAndClient,
		[grantId]
	),
	/*
	 * The one model area that is never reaped. Clients are upserted with no TTL argument
	 * (lib/admin/clients/service.ts), so an expiry index here would match nothing today — and would
	 * silently delete registered OAuth clients the moment a client record gained an `expiresAt`,
	 * which MongoAdapter.upsert can leave behind because it never $unsets a stale one. Inert now,
	 * unrecoverable later; that asymmetry is why this is explicit rather than inherited.
	 */
	modelArea(
		'Client',
		null,
		unowned('a client is itself a principal, not owned by one')
	),
	/*
	 * Client-owned and reachable by no other route: a client-credentials token carries no grantId at
	 * all, so collecting grant ids and revoking by them misses this area entirely. Sweeping by owner
	 * field is what reaches it.
	 */
	modelArea('ClientCredentials', EXPIRES_AT, byClient),
	modelArea('DeviceCode', EXPIRES_AT, byAccountAndClient, [
		grantId,
		{ key: { 'payload.userCode': 1 }, unique: true }
	]),
	/*
	 * The federated sign-in's round-trip record: one area holding two stages, because the interaction
	 * cookie provably cannot survive the trip to an upstream IdP (path-scoped and sameSite: 'strict',
	 * against a fixed callback reached by a cross-site navigation). Stage one is keyed by sha256(state)
	 * and holds the exchange context; stage two replaces it under sha256(ref) and holds only the
	 * interaction and the account it resolved to. Neither live identifier is ever a field.
	 *
	 * Account-owned, and that is a departure from what the backlog entry for this feature anticipated
	 * ("unowned, because it names no principal yet"). The stage-two payload carries `accountId`, and the
	 * reverse ownership check in test/storage_contract/inventory_drift.spec.ts fails any area whose
	 * payload holds an owner field the table does not declare — correctly, since such a record is one no
	 * cascade sweeps. Declaring it owned is also the better property: an outstanding handoff naming a
	 * deleted account dies with it. Stage-one records carry no `accountId`, so no sweep matches them and
	 * they simply expire, which is the true statement `unowned` was reaching for.
	 */
	modelArea('FederationState', EXPIRES_AT, byAccount),
	/*
	 * The consent record. Only a principal cascade destroys these — protocol revocation deliberately
	 * leaves them alive, because revoking a token is not withdrawing consent.
	 */
	modelArea('Grant', EXPIRES_AT, byAccountAndClient),
	/*
	 * InitialAccessToken and RegistrationAccessToken may be issued without an expiry. They keep the
	 * index regardless: MongoDB never expires a document that lacks the indexed field, so a
	 * non-expiring token simply survives, which is the intended behaviour.
	 */
	modelArea(
		'InitialAccessToken',
		EXPIRES_AT,
		unowned('deliberately not client-bound; the schema omits clientId')
	),
	modelArea('Interaction', EXPIRES_AT, byAccount),
	/*
	 * The password sign-in door's failure counters, addressed by `${bucketId}:${email}` exactly as the
	 * two areas below and VerificationResend are — which is what lets the account cascade destroy all
	 * three from the one id it computes before the account row goes.
	 *
	 * Unowned, and unlike its siblings that is a *requirement* rather than a consequence: a counter is
	 * written for any address submitted to an open password door, including one that resolves to no
	 * account, so that the presence of a record and the behaviour of the door never reveal whether an
	 * address is registered. There is frequently no principal to own it. Note the reading this inverts —
	 * a PasswordResetThrottle record is written only when mail is actually sent, so its existence does
	 * imply an account; a record here means only that somebody typed that address.
	 *
	 * Reaped, and the expiry is the control rather than housekeeping: the record carries the escalation
	 * step, so one that never expired would hold an address at the longest cooldown for good.
	 */
	modelArea(
		'LoginThrottle',
		EXPIRES_AT,
		unowned('addressed by the computed id `${bucketId}:${email}`, never swept')
	),
	/*
	 * The self-service password reset's two areas. The challenge is account-owned rather than merely
	 * expiring: an outstanding secret can take the account over, so it must not outlive the account it
	 * names — sweeping it is the declaration, not code somewhere else. Its record id is a digest of the
	 * emailed token, so an id here reveals nothing and the ownership index is the only way in.
	 */
	modelArea('PasswordResetChallenge', EXPIRES_AT, byAccount),
	/*
	 * Request counters, addressed by `${bucketId}:${email}` exactly as VerificationResend is — which is
	 * what lets the account cascade destroy both from the one id it computes before the account row goes.
	 * Owns nothing: it exists for an address, which may have no account yet or any more.
	 */
	modelArea(
		'PasswordResetThrottle',
		EXPIRES_AT,
		unowned('addressed by the computed id `${bucketId}:${email}`, never swept')
	),
	modelArea(
		'PushedAuthorizationRequest',
		EXPIRES_AT,
		unowned(
			'the client id lives inside the opaque `request` string, not in a field'
		)
	),
	modelArea('RefreshToken', EXPIRES_AT, byAccountAndClient, [grantId]),
	/*
	 * Swept first by the client cascade: this is the only swept area whose records may be issued with no
	 * expiry, so it is the only residue a partial failure would leave unbounded.
	 */
	modelArea('RegistrationAccessToken', EXPIRES_AT, byClient),
	modelArea(
		'ReplayDetection',
		EXPIRES_AT,
		unowned('keyed by iss/jti; belongs to no principal')
	),
	/*
	 * Account-owned only. `authorizations` nests a clientId per entry, but no index reaches into a
	 * sub-document and the entry is inert once its grant is destroyed, so client deletion deliberately
	 * leaves it (see lib/helpers/cascade.ts).
	 */
	modelArea('Session', EXPIRES_AT, byAccount, [
		{ key: { 'payload.uid': 1 }, unique: true }
	]),
	/*
	 * The second factor's two areas, both account-owned, and neither is owned by convention.
	 *
	 * Their payloads name `accountId`, and the reverse ownership check in
	 * test/storage_contract/inventory_drift.spec.ts fails any area whose payload holds an owner field
	 * this table does not declare — the finding already recorded for FederationState above, and correct
	 * for the same reason: such a record is one no cascade sweeps.
	 *
	 * Declaring them owned is also the better property in both cases. An outstanding enrolment offer
	 * naming a deleted account dies with it rather than sitting on a secret for nobody, and a deleted
	 * account's lockout window does not survive to greet an account later created under a reused id.
	 *
	 * Point-read by id in both cases — the enrolment by the interaction uid, the window by
	 * `${bucketId}:${accountId}` — so neither needs an index beyond the expiry and owner ones
	 * indexesFor() derives.
	 */
	modelArea('TotpAttempt', EXPIRES_AT, byAccount),
	modelArea('TotpEnrollment', EXPIRES_AT, byAccount),
	/*
	 * Verification challenges and resend counters are written with a TTL and were never provisioned,
	 * so before this table they auto-created on first write with no expiry index at all: expired
	 * challenges accumulated forever and a stale resend window could keep refusing a legitimate
	 * resend. This pair is the defect the inventory exists to close.
	 */
	/*
	 * Swept by accountId alone. `bucketId` would narrow nothing — an accountId is a nanoid, unique
	 * across every bucket — and asking for it would cost a two-field sweep on the adapter forever.
	 */
	modelArea('VerificationChallenge', EXPIRES_AT, byAccount),
	/*
	 * Its id *is* `${bucketId}:${email}`, so the account cascade destroys it by computed id rather than
	 * by scanning. That is also why the cascade must read the user's email before destroying the account
	 * row: nothing else records it, and the obvious ordering skips this record with no error anywhere.
	 */
	modelArea(
		'VerificationResend',
		EXPIRES_AT,
		unowned('addressed by the computed id `${bucketId}:${email}`, never swept')
	),

	/* Signing keys never expire; they are addressed by a unique kid. */
	storeArea(
		STORE_AREAS.jwks,
		null,
		unowned('server signing keys; no principal owns them'),
		[{ key: { kid: 1 }, unique: true }]
	),
	/*
	 * `clientIds` is not unique — a client belongs to one project, but nothing in the schema enforces
	 * that. It is indexed because projectStore.findByClientId runs on every browser-origin request to
	 * a client-based CORS endpoint, so the lookup has to be a point read rather than a scan.
	 */
	storeArea(
		STORE_AREAS.projects,
		null,
		unowned(
			'a container: guarded against deletion while occupied, never cascaded'
		),
		[
			{ key: { slug: 1 }, unique: true },
			{ key: { clientIds: 1 } },
			{ key: { ownerGroupId: 1 } }
		]
	),
	storeArea(
		STORE_AREAS.userBuckets,
		null,
		unowned(
			'a container: guarded against deletion while occupied, never cascaded'
		),
		[{ key: { ownerGroupId: 1 } }]
	),
	/*
	 * Groups own every project and user bucket, so `members.userId` is read on every admin request —
	 * `contextFor` resolves the caller's memberships there, where it previously scanned projects by
	 * manager. Indexed for that reason, not for reporting.
	 *
	 * Permanent, and unowned by an account or a client: destroying an administrator must not destroy a
	 * group other people belong to, and a group outliving its last member is prevented by a route
	 * invariant rather than by a cascade.
	 */
	storeArea(
		STORE_AREAS.groups,
		null,
		unowned(
			'a container of containers: an administrator is removed from it, never cascaded through it'
		),
		[{ key: { 'members.userId': 1 } }, { key: { kind: 1 } }]
	),
	/*
	 * Reaped on `expiresAt`, and the TTL is the point rather than housekeeping: an invitation that
	 * outlived its expiry is a standing offer of access to a group, which is the one thing an
	 * invitation must never become.
	 */
	storeArea(
		STORE_AREAS.groupInvitations,
		EXPIRES_AT,
		/*
		 * Unowned despite carrying `invitedBy`. Owner fields drive the account cascade, which sweeps
		 * *model* areas; declaring one here would claim a sweep that does not reach this area, and the
		 * drift guard refuses exactly that. Expiry is what bounds an invitation's life instead, which is
		 * the stronger guarantee anyway: it lapses whether or not the inviter is ever deleted.
		 */
		unowned('reaped on expiry; an invitation outlives no account by design')
	),
	/*
	 * Safe to reap on `expiresAt` despite the two expiry fields: touch() clamps the sliding
	 * `expiresAt` to `absoluteExpiresAt`, so it can never outlive the hard cap.
	 */
	/*
	 * The MCP control plane's confirmation tokens: one record per described-but-not-yet-performed
	 * high-consequence operation.
	 *
	 * Reaped on `expiresAt`, and the TTL is the point rather than housekeeping — a confirmation that
	 * outlived its window could be redeemed against state that has since changed, which is the failure
	 * the two-step gate exists to prevent. Redemption deletes the record before dispatching, so the
	 * reaper only ever collects confirmations nobody used.
	 *
	 * Unowned: a record names the administrator who was shown the description, but it is a few minutes
	 * of transient protocol state, not a possession. Sweeping it on principal deletion would buy
	 * nothing the TTL does not already do, and the principal's own deletion invalidates every
	 * confirmation it holds anyway, because redemption re-resolves the principal.
	 */
	storeArea(
		STORE_AREAS.mcpConfirmation,
		EXPIRES_AT,
		unowned(
			'transient confirmation state, reaped by TTL; a stale record cannot be redeemed because redemption re-resolves the principal'
		)
	),
	storeArea(
		STORE_AREAS.adminSession,
		EXPIRES_AT,
		unowned(
			'operator sessions, out of scope: admin deletion deactivates, and revoking their sessions is a separate concern'
		)
	),
	/*
	 * Append-only and permanent: the constitution requires an immutable admin audit trail, so no expiry
	 * on any of these — an entry is never removed.
	 *
	 * One index per shape the read surface actually queries. `{ timestamp, _id }` serves the total
	 * newest-first ordering: MongoDB traverses an index in either direction, so no descending twin is
	 * needed, and the `_id` tiebreaker is what keeps paging from dropping a row when two actions share a
	 * timestamp. The other four exist because the trail grows without bound while the filters must stay
	 * point lookups — including `actorEmail`, whose own index is what keeps the actor filter's second
	 * `$or` arm off a collection scan.
	 *
	 * Deployments provisioned before this feature also carry a bare `{ timestamp: 1 }` index, now a
	 * redundant prefix of the first entry below. Reconciliation does not drop it, deliberately: only
	 * expiry rules are safe to remove, since an unrecognised ordinary index may be an operator's.
	 */
	storeArea(
		STORE_AREAS.adminAudit,
		null,
		unowned(
			'append-only and immutable by constitution: no cascade may ever reach the trail'
		),
		[
			{ key: { timestamp: 1, _id: 1 } },
			{ key: { actorId: 1, timestamp: 1 } },
			{ key: { actorEmail: 1, timestamp: 1 } },
			{ key: { action: 1, timestamp: 1 } },
			{ key: { targetType: 1, targetId: 1, timestamp: 1 } },
			{ key: { targetScope: 1, timestamp: 1 } },
			/*
			 * The group-scoped read, which is every audit read a project administrator makes: their
			 * groups' entries, newest first. Compound rather than a bare `ownerGroupId` because the
			 * restriction and the ordering are never applied apart.
			 */
			{ key: { ownerGroupId: 1, timestamp: 1 } }
		]
	),
	/*
	 * The one area with an expiry field that is *advanced* rather than fixed at write: a group's
	 * `expiresAt` moves forward on every occurrence, so the retention window runs from the last time a
	 * fault was seen, not the first. A fault that has been happening for six weeks is the last thing
	 * that should age out.
	 *
	 * Unowned, and the reason is not a formality. A record naming a client is *about* that client's
	 * request; it is not the client's data. Deleting a client must not erase the evidence of the faults
	 * its requests caused, so no cascade arm may ever reach this area.
	 */
	storeArea(
		STORE_AREAS.errorStore,
		'expiresAt',
		unowned(
			'diagnostic evidence of a server fault; deleting the subject must not erase what happened'
		),
		/*
		 * Ascending throughout, though every read is newest-first: the listing sort is the exact reverse
		 * of `{ lastSeenAt, _id }`, which MongoDB serves by walking the same index backwards. Same
		 * arrangement, for the same reason, as the adminAudit area's `{ timestamp: 1, _id: 1 }`.
		 *
		 * The `_id` tiebreaker is what makes the order total. Two faults recorded in the same
		 * millisecond is ordinary here rather than a corner case — a storm is one of the things this
		 * store exists to show — and without the tiebreaker paging would drop or repeat a group.
		 */
		[
			{ key: { fingerprint: 1 }, unique: true },
			{ key: { lastSeenAt: 1, _id: 1 } },
			{ key: { errorCode: 1, lastSeenAt: 1 } },
			{ key: { route: 1, lastSeenAt: 1 } },
			{ key: { surface: 1, lastSeenAt: 1 } },
			{ key: { status: 1, lastSeenAt: 1 } },
			{ key: { 'samples.clientId': 1, lastSeenAt: 1 } },
			{ key: { 'samples.reference': 1 } }
		]
	),
	storeArea(
		STORE_AREAS.serviceConfig,
		null,
		unowned('server configuration; no principal owns it')
	),

	perBucketArea
];

export const PER_BUCKET_AREA: StorageArea = perBucketArea;

/* The fixed areas, i.e. everything the routine provisions without consulting the bucket list. */
export const FIXED_AREAS: readonly StorageArea[] = STORAGE_INVENTORY.filter(
	(area) => area.kind !== 'perBucket'
);

/* The fields a cascade sweeps an area by, in declaration order. */
export function ownerFieldsOf(area: StorageArea): string[] {
	return [area.owners.account, area.owners.client].filter(
		(field): field is string => field !== null
	);
}

/*
 * Every index an area should carry: its own, one per declared owner field, and the expiry index. The
 * single place the derived ones are computed, so the provisioning routine and the reconciliation
 * comparison cannot disagree about what "correct" means for an area — and so a field the deletion
 * cascade sweeps by is always a field the datastore can find without a collection scan. Deriving beats
 * hand-declaring for the same reason the ownership table does: an owner field added without its index
 * would work, slowly, and announce nothing.
 */
export function indexesFor(area: StorageArea): IndexSpec[] {
	return [
		...area.indexes,
		...ownerFieldsOf(area).map((field) => singleKeyIndex(`payload.${field}`)),
		...(area.reaped === null
			? []
			: [{ ...singleKeyIndex(area.reaped), expireAfterSeconds: 0 }])
	];
}

/* Built through a typed local rather than an object literal with a computed key, which widens `1` to
 * `number` and stops matching IndexSpec. */
function singleKeyIndex(field: string): IndexSpec {
	const key: Record<string, 1> = {};
	key[field] = 1;
	return { key };
}

/* The concrete area for one bucket: the per-bucket index declarations under a real collection name. */
export function areaForBucket(bucketId: string): StorageArea {
	return { ...PER_BUCKET_AREA, name: userAreaFor(bucketId) };
}

/*
 * Resolve a declared area by name, throwing when there is none. An area name the inventory does not
 * declare is a programming error, so failing here — with the name in the message — beats handing back
 * `undefined` for a caller to trip over later, or to silence with a cast.
 *
 * Note this resolves *declared* names only: the per-bucket entry is templated, so `user_redfox` is not
 * a declared name. Use areaForBucket for those.
 */
export function areaNamed(name: string): StorageArea {
	const found = STORAGE_INVENTORY.find((area) => area.name === name);
	if (!found) {
		throw new Error(`no storage area declared for '${name}'`);
	}
	return found;
}
