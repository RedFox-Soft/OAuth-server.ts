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
	/* Indexes other than the expiry one, which indexesFor() derives from `reaped`. */
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
	'Grant',
	'InitialAccessToken',
	'Interaction',
	'PushedAuthorizationRequest',
	'RefreshToken',
	'RegistrationAccessToken',
	'ReplayDetection',
	'Session',
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
	adminSession: 'adminSession',
	adminAudit: 'adminAudit',
	/* One area, three writers: configStore keeps the persisted ApplicationConfig, SmtpSettingsStore
	 * the SMTP credentials, and DPoPNonceSecretStore the server's nonce secret, as three singleton
	 * documents distinguished only by a derived ObjectId. One inventory entry, therefore, not three.
	 * The nonce secret joined them rather than claiming an area of its own because this area is
	 * already declared permanent (`reaped: null` below): a secret that expired on its own would be
	 * silently regenerated at the next startup, churning every client's nonces for no visible reason. */
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

const modelArea = (
	name: ModelAreaName,
	reaped: string | null,
	indexes: readonly IndexSpec[] = []
): StorageArea => ({ name, kind: 'model', reaped, indexes });

const storeArea = (
	name: StoreAreaName,
	reaped: string | null,
	indexes: readonly IndexSpec[] = []
): StorageArea => ({ name, kind: 'store', reaped, indexes });

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
	indexes: [{ key: { email: 1 }, unique: true }]
};

export const STORAGE_INVENTORY: readonly StorageArea[] = [
	modelArea('AccessToken', EXPIRES_AT, [grantId]),
	modelArea('AuthorizationCode', EXPIRES_AT, [grantId]),
	modelArea('BackchannelAuthenticationRequest', EXPIRES_AT, [grantId]),
	/*
	 * The one model area that is never reaped. Clients are upserted with no TTL argument
	 * (lib/admin/clients/service.ts), so an expiry index here would match nothing today — and would
	 * silently delete registered OAuth clients the moment a client record gained an `expiresAt`,
	 * which MongoAdapter.upsert can leave behind because it never $unsets a stale one. Inert now,
	 * unrecoverable later; that asymmetry is why this is explicit rather than inherited.
	 */
	modelArea('Client', null),
	modelArea('ClientCredentials', EXPIRES_AT),
	modelArea('DeviceCode', EXPIRES_AT, [
		grantId,
		{ key: { 'payload.userCode': 1 }, unique: true }
	]),
	modelArea('Grant', EXPIRES_AT),
	/*
	 * InitialAccessToken and RegistrationAccessToken may be issued without an expiry. They keep the
	 * index regardless: MongoDB never expires a document that lacks the indexed field, so a
	 * non-expiring token simply survives, which is the intended behaviour.
	 */
	modelArea('InitialAccessToken', EXPIRES_AT),
	modelArea('Interaction', EXPIRES_AT),
	modelArea('PushedAuthorizationRequest', EXPIRES_AT),
	modelArea('RefreshToken', EXPIRES_AT, [grantId]),
	modelArea('RegistrationAccessToken', EXPIRES_AT),
	modelArea('ReplayDetection', EXPIRES_AT),
	modelArea('Session', EXPIRES_AT, [
		{ key: { 'payload.uid': 1 }, unique: true }
	]),
	/*
	 * Verification challenges and resend counters are written with a TTL and were never provisioned,
	 * so before this table they auto-created on first write with no expiry index at all: expired
	 * challenges accumulated forever and a stale resend window could keep refusing a legitimate
	 * resend. This pair is the defect the inventory exists to close.
	 */
	modelArea('VerificationChallenge', EXPIRES_AT),
	modelArea('VerificationResend', EXPIRES_AT),

	/* Signing keys never expire; they are addressed by a unique kid. */
	storeArea(STORE_AREAS.jwks, null, [{ key: { kid: 1 }, unique: true }]),
	/*
	 * `clientIds` is not unique — a client belongs to one project, but nothing in the schema enforces
	 * that. It is indexed because projectStore.findByClientId runs on every browser-origin request to
	 * a client-based CORS endpoint, so the lookup has to be a point read rather than a scan.
	 */
	storeArea(STORE_AREAS.projects, null, [
		{ key: { slug: 1 }, unique: true },
		{ key: { clientIds: 1 } }
	]),
	storeArea(STORE_AREAS.userBuckets, null),
	/*
	 * Safe to reap on `expiresAt` despite the two expiry fields: touch() clamps the sliding
	 * `expiresAt` to `absoluteExpiresAt`, so it can never outlive the hard cap.
	 */
	storeArea(STORE_AREAS.adminSession, EXPIRES_AT),
	/* Append-only and permanent: the constitution requires an immutable admin audit trail. Indexed by
	 * time for reads, with no expiry so an entry is never removed. */
	storeArea(STORE_AREAS.adminAudit, null, [{ key: { timestamp: 1 } }]),
	storeArea(STORE_AREAS.serviceConfig, null),

	perBucketArea
];

export const PER_BUCKET_AREA: StorageArea = perBucketArea;

/* The fixed areas, i.e. everything the routine provisions without consulting the bucket list. */
export const FIXED_AREAS: readonly StorageArea[] = STORAGE_INVENTORY.filter(
	(area) => area.kind !== 'perBucket'
);

/*
 * Every index an area should carry, expiry index included. The single place the expiry index is
 * derived, so the provisioning routine and the reconciliation comparison cannot disagree about what
 * "correct" means for an area.
 */
export function indexesFor(area: StorageArea): IndexSpec[] {
	return area.reaped === null
		? [...area.indexes]
		: [...area.indexes, { key: { [area.reaped]: 1 }, expireAfterSeconds: 0 }];
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
