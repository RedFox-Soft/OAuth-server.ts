import type { UnnormalizedJWK } from 'lib/configs/verifyJWKs.ts';
import type {
	FederatedIdentity,
	FederationProvider
} from '../federation/types.js';

export interface User {
	_id: string;
	email: string;
	verified: boolean;
	password: string;
	active: boolean;
	roles: string[];
	createdAt: Date;
	updatedAt: Date;
	lastLoginAt: Date | null;
	// Optional extra OIDC claims sourced with the account (e.g. profile claims
	// like given_name, or distributed/aggregated `_claim_names`/`_claim_sources`).
	// Merged into the account's claims() output; the provider masks by scope.
	claims?: Record<string, unknown>;
	/*
	 * Upstream identities this account holds, at most one per (providerId, sub) within the bucket.
	 * Embedded rather than given an area of its own, which is what makes deletion integrity free: the
	 * account cascade destroys this row and bucket deletion destroys the whole area, so no cascade arm
	 * needs to know the field exists.
	 */
	federated?: FederatedIdentity[];
}

export interface ModelAdapter<TPayload = unknown> {
	upsert(id: string, payload: TPayload, expiresIn?: number): Promise<void>;
	find(id: string): Promise<TPayload | undefined>;
	findByUserCode(userCode: string): Promise<TPayload | undefined>;
	findByUid(uid: string): Promise<TPayload | undefined>;
	destroy(id: string): Promise<void>;
	revokeByGrantId(grantId: string): Promise<void>;
	consume(id: string): Promise<void>;
	/*
	 * Destroys every record in *this* area whose `field` equals `value`, returning how many went. The
	 * one way to reach a principal's records: nothing else can enumerate by owner, and a grant walk
	 * misses ClientCredentials (no grantId) and RegistrationAccessToken (no expiry) entirely.
	 *
	 * `field` always comes from lib/consts/storage_inventory.ts, never from a caller — which, with the
	 * identifier check the drift guard applies to the table, is what keeps a `$`-prefixed or dotted name
	 * from ever reaching a query. Field first in the signature so a value passed where a field belongs
	 * cannot silently work.
	 */
	destroyByOwner(field: string, value: string): Promise<number>;
}

export interface ModelAdapterConstructor {
	new (name: string): ModelAdapter<Record<string, unknown>>;
}

export type {
	KnownModelName,
	ModelPayloadByName,
	PayloadForModel
} from './modelTypes.js';

export interface AdapterConfigStore {
	get(): Promise<Record<string, unknown> | null>;
	set(config: Record<string, unknown>): Promise<void>;
}

export interface SmtpSettings {
	host: string;
	port: number;
	secure: boolean;
	username: string;
	// Stored as provided; never returned to clients (masked) and never logged.
	password: string;
	fromName: string;
	fromEmail: string;
}

// Runtime, super-admin-editable SMTP transport config. Read live by the mailer on
// every send so changes take effect without a provider restart (kept out of the
// boot-only ApplicationConfig for that reason).
export interface SmtpSettingsStoreInstance {
	get(): Promise<SmtpSettings | null>;
	set(settings: SmtpSettings): Promise<void>;
}

export interface SmtpSettingsStoreConstructor {
	new (): SmtpSettingsStoreInstance;
}

/*
 * A singleton secret the server provisions for itself: one 32-byte value per deployment, generated at
 * startup and never supplied by an operator. Two documents use it — the DPoP nonce secret and the
 * pairwise identifier salt — told apart by the name each instance is constructed with, which is what
 * keeps them separate records inside the one `serviceConfig` area. Contracts:
 * specs/014-dpop-nonce-safety/contracts/nonce-secret-store.md and
 * specs/023-pairwise-identifier-salt/contracts/pairwise-salt-store.md.
 *
 * Two properties are load-bearing and neither is expressible in the signatures alone.
 *
 * `unknown` rather than `Buffer` is deliberate. This interface deliberately does NOT promise that a
 * value reads back in the shape it was written: a buffer written to a document store returns as the
 * driver's binary wrapper, and that mismatch — a value arriving in a shape the declared type calls
 * impossible — is the whole defect this feature closes. Promising fidelity the storage layer cannot
 * keep is how it arrived. Callers narrow with their own predicate — isUsableNonceSecret
 * (configs/nonceSecret.ts) or isUsablePairwiseSalt (configs/pairwiseSalt.ts).
 *
 * Both writes return the record AS READ BACK, not the candidate handed in. That is what makes the
 * round-trip check structural rather than a step a caller can forget, and what hands a losing writer
 * the winner's value from the very call that failed to take effect — so concurrent provisioning
 * converges with no second code path.
 *
 * `null` means absent. Nothing here expires or deletes the record: serviceConfig is declared
 * `reaped: null` in the storage inventory, pinned by test/storage_contract/inventory_expiry.spec.ts.
 */
export interface SecretStoreInstance {
	read(): Promise<unknown>;
	/* Writes only if no record exists. On conflict the write does not take effect. */
	create(secret: Buffer): Promise<unknown>;
	/*
	 * Writes only if the stored value is still `observed`. On mismatch the write does not take effect.
	 *
	 * Reachable from the nonce secret's resolver, which repairs an unusable value, and from nothing
	 * else: the pairwise salt has no repair path, because replacing a salt permanently breaks every
	 * relying party's account linkage.
	 */
	replace(observed: unknown, secret: Buffer): Promise<unknown>;
}

export interface SecretStoreConstructor {
	/* The document this instance owns inside the shared `serviceConfig` area. */
	new (documentName: string): SecretStoreInstance;
}

export interface UserStoreInstance {
	find(id: string): Promise<User | null>;
	findByEmail(email: string): Promise<User | null>;
	/*
	 * `id` lets the caller allocate the identifier before the record exists, which is what makes
	 * audit-first possible for a creation: the audit entry must name the real id and must be written
	 * before the account is created. Omitted, each adapter generates one as it always did.
	 */
	create(
		email: string,
		password: string,
		roles?: string[],
		verified?: boolean,
		id?: string
	): Promise<User>;
	/*
	 * Resolve an account by the upstream identity it holds. A point read in MongoDB, served by the
	 * per-bucket area's `{ 'federated.providerId': 1, 'federated.sub': 1 }` index.
	 *
	 * Uniqueness of the pair is enforced in code at link time rather than by that index, deliberately: a
	 * unique multikey index would index every password-only account as {null, null} and collide on the
	 * second one, so it would need a partialFilterExpression, which IndexSpec does not model. The residual
	 * race yields a duplicate entry naming the *same* account, never two accounts sharing an identity —
	 * which is why this returns one account rather than an array.
	 */
	findByFederatedIdentity(
		providerId: string,
		sub: string
	): Promise<User | null>;
	list(): Promise<User[]>;
	/*
	 * `claims` and `federated` are patchable because a just-in-time provisioned account is created and
	 * then completed: create() takes positional arguments and neither value is always present, so widening
	 * the patch beats a sixth and seventh parameter at every existing call site.
	 */
	update(
		id: string,
		patch: Partial<
			Pick<
				User,
				'roles' | 'active' | 'password' | 'verified' | 'claims' | 'federated'
			>
		>
	): Promise<User | null>;
	destroy(id: string): Promise<void>;
	/*
	 * Destroys the area itself, called when its bucket is deleted — the half of bucket deletion that was
	 * missing, which left a `user_<bucket>` collection behind for good. Only reached after the occupancy
	 * guard has passed, so it never destroys a non-empty area.
	 */
	destroyArea(): Promise<void>;
}

export interface UserStoreConstructor {
	new (name?: string): UserStoreInstance;
}

/*
 * The key store reads back what was persisted, so what it returns is `UnnormalizedJWK`, not `JWKS`:
 * a key provisioned out of band may be missing `kid` or `use`, which only verifyJWKs fills in. The
 * store used to claim `JWKS` — normalization it never performs — which is precisely how a bug that
 * compared a stored key's absent `kid` against a live one went unnoticed by the compiler.
 *
 * `set` accepts either, since `JWKS` is the normalized form of the same key.
 */
export interface JWKSStoreInstance {
	get(keyId: string): Promise<UnnormalizedJWK | null>;
	set(keyId: string, key: UnnormalizedJWK): Promise<void>;
	delete(keyId: string): Promise<void>;
	getAll(): Promise<UnnormalizedJWK[]>;
}

export interface JWKSStoreConstructor {
	new (): JWKSStoreInstance;
}

export interface AdminAuditEntry {
	_id: string;
	actorId: string;
	actorEmail: string;
	action: string;
	targetType: string;
	targetId: string;
	/*
	 * The container within which `targetId` resolves — in practice a bucket id, set only by the
	 * end-user operations. Kept separate from `targetId` rather than fused into it so exact-match
	 * retrieval on a bare target identifier keeps working. Absent where the target resolves alone.
	 *
	 * Written as a string or omitted; read back as a string or `null`, so a consumer never has to tell
	 * "absent" from "not applicable".
	 */
	targetScope?: string | null;
	/*
	 * Names of the fields the request set — never their values, so no secret can reach the trail
	 * through this field. Optional because entries written before it existed do not carry it, and the
	 * trail is immutable: there is no backfill, only a read-side default.
	 */
	attributes?: string[];
	timestamp: Date;
}

export interface AdminAuditQuery {
	// Matches actorId OR actorEmail: a reviewer reads emails, but a deleted admin's entries are
	// findable only by id, and the caller should not have to know which they are holding.
	actor?: string;
	action?: string;
	targetType?: string;
	targetId?: string;
	targetScope?: string;
	/* Inclusive bounds on `timestamp`; either is valid alone. */
	from?: Date;
	to?: Date;
	limit?: number;
	offset?: number;
}

export interface AdminAuditPage {
	entries: AdminAuditEntry[];
	// Records matching the filters, independent of limit/offset — the reader needs a page count.
	total: number;
}

// Append-only by construction: there is intentionally no update or delete method, so an
// admin audit trail cannot be tampered with through the adapter (constitution: immutable
// audit log for every state-changing administrative action).
export interface AdminAuditStoreInstance {
	record(
		entry: Omit<AdminAuditEntry, '_id' | 'timestamp'>
	): Promise<AdminAuditEntry>;
	/*
	 * Newest first, ordered by (timestamp desc, _id desc). The `_id` tiebreaker makes the order total,
	 * which is what stops paging from dropping or repeating an entry when timestamps collide.
	 */
	list(query?: AdminAuditQuery): Promise<AdminAuditPage>;
}

export interface AdminAuditStoreConstructor {
	new (): AdminAuditStoreInstance;
}

export interface Project {
	_id: string;
	name: string;
	slug: string;
	type: 'admin' | 'regular';
	managedBy: string[];
	bucketId: string | null;
	clientIds: string[];
	/*
	 * Web origins whose browser code may read cross-origin responses on behalf of this project's
	 * clients. Operator-managed, empty by default — a project grants nothing until one is added.
	 * Stored canonical and matched by exact equality (lib/helpers/cors_origin.ts).
	 */
	corsOrigins: string[];
	createdAt: Date;
	updatedAt: Date;
}

export interface ProjectStoreInstance {
	create(data: {
		_id?: string;
		name: string;
		slug: string;
		type?: 'admin' | 'regular';
		managedBy?: string[];
		bucketId?: string | null;
		clientIds?: string[];
		corsOrigins?: string[];
	}): Promise<Project>;
	find(id: string): Promise<Project | null>;
	findBySlug(slug: string): Promise<Project | null>;
	list(): Promise<Project[]>;
	listByManager(userId: string): Promise<Project[]>;
	update(
		id: string,
		patch: Partial<
			Pick<
				Project,
				'name' | 'managedBy' | 'bucketId' | 'clientIds' | 'corsOrigins'
			>
		>
	): Promise<Project | null>;
	destroy(id: string): Promise<void>;
	countByBucket(bucketId: string): Promise<number>;
	findByClientId(clientId: string): Promise<Project | null>;
}

export interface ProjectStoreConstructor {
	new (): ProjectStoreInstance;
}

export type VerificationMethod = 'link' | 'code';

export interface UserBucket {
	_id: string;
	name: string;
	managedBy: string[];
	roles: string[];
	/*
	 * Whether this bucket accepts an email and a password at all. Replaces `authMethods`, which was a
	 * dead field: nothing read it, and the admin bodies omitted it entirely, so no operator could set it.
	 *
	 * `false` means the login page renders no password form and every password-only door — sign-in,
	 * both registration methods, both forgot-password methods — answers 403. Defaulted `true` on read in
	 * both adapters, so a bucket document written before this field existed keeps the behaviour it had.
	 *
	 * Federation availability is deliberately NOT the mirror of this: it is derived from
	 * `federation.some((p) => p.enabled)`, so a provider is enabled in exactly one place. Two fields that
	 * both claim to say whether federation works is the shape that disagrees after the first edit.
	 */
	passwordLogin: boolean;
	/* This bucket's upstream providers, credentials included. Managed only through their own routes. */
	federation: FederationProvider[];
	// Whether self-service registration is accepted for this bucket. The reserved
	// admin bucket seeds this false; every other bucket defaults true.
	//
	// Governs the PASSWORD registration form only. Federated provisioning is the
	// per-provider `provisioning` knob — which is what lets a bucket close password
	// sign-ups while still accepting anyone from its corporate IdP.
	registrationOpen: boolean;
	// Whether a newly registered account must verify its email before it counts as
	// verified (and, when required, before it can sign in).
	emailVerificationRequired: boolean;
	// Which proof the registrant uses when verification is required.
	verificationMethod: VerificationMethod;
	createdAt: Date;
	updatedAt: Date;
}

export interface UserBucketStoreInstance {
	create(data: {
		_id?: string;
		name: string;
		managedBy?: string[];
		roles?: string[];
		passwordLogin?: boolean;
		federation?: FederationProvider[];
		registrationOpen?: boolean;
		emailVerificationRequired?: boolean;
		verificationMethod?: VerificationMethod;
	}): Promise<UserBucket>;
	find(id: string): Promise<UserBucket | null>;
	list(): Promise<UserBucket[]>;
	listByManager(userId: string): Promise<UserBucket[]>;
	update(
		id: string,
		patch: Partial<
			Pick<
				UserBucket,
				| 'name'
				| 'managedBy'
				| 'roles'
				| 'passwordLogin'
				| 'federation'
				| 'registrationOpen'
				| 'emailVerificationRequired'
				| 'verificationMethod'
			>
		>
	): Promise<UserBucket | null>;
	destroy(id: string): Promise<void>;
}

export interface UserBucketStoreConstructor {
	new (): UserBucketStoreInstance;
}

export interface AdminSession {
	_id: string;
	userId: string;
	bucketId: string;
	tokens: { accessToken?: string; idToken?: string; refreshToken?: string };
	createdAt: Date;
	expiresAt: Date;
	absoluteExpiresAt: Date;
}

export interface AdminSessionStoreInstance {
	create(data: {
		userId: string;
		bucketId: string;
		tokens: AdminSession['tokens'];
		ttlSeconds: number;
		absoluteTtlSeconds: number;
	}): Promise<AdminSession>;
	find(id: string): Promise<AdminSession | null>;
	touch(id: string, ttlSeconds: number): Promise<void>;
	destroy(id: string): Promise<void>;
}

export interface AdminSessionStoreConstructor {
	new (): AdminSessionStoreInstance;
}
