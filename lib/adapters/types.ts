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
	/*
	 * This account's authenticator, when it has one. Present ⇔ enrolled: there is deliberately no
	 * separate `enrolled` boolean, because two fields claiming to say the same thing disagree after
	 * the first edit. A secret that has been offered but not yet proved lives in the TotpEnrollment
	 * area and never here.
	 *
	 * Embedded rather than given an area of its own, for exactly the reason `federated` is: the
	 * account cascade destroys this row and bucket deletion destroys the whole area, so no cascade
	 * arm needs to know the field exists.
	 *
	 * `secret` is recoverable by construction — TOTP verification is symmetric, so it cannot be
	 * hashed the way a password is. It is therefore barred from every read surface instead:
	 * `presentUser` in lib/admin/users-end/routes.ts removes it from every administrative read, and
	 * test/mcp/secrecy.spec.ts sweeps every published read to keep that true. Nothing outside
	 * lib/totp/ reads it.
	 */
	totp?: {
		/* Base32, RFC 4648 §6. */
		secret: string;
		enrolledAt: Date;
		/*
		 * The time step of the most recently accepted code. A submitted code whose step is at or below
		 * this is refused, which is what stops a code observed in flight being replayed for the rest of
		 * its ~90-second acceptance band.
		 */
		lastStep: number;
	};
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
				| 'roles'
				| 'active'
				| 'password'
				| 'verified'
				| 'claims'
				| 'federated'
				/* Set when an enrolment is confirmed, and set back to undefined when an operator clears one. */
				| 'totp'
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
	/*
	 * The agent that performed the action, and the surface it arrived on. Written together or not at
	 * all; absent means the console.
	 *
	 * Optional for the reason `attributes` above is optional and says so: the trail is append-only,
	 * there is no backfill, only a read-side default. A required field would invalidate every entry
	 * written before agents existed.
	 *
	 * The actor stays the administrator. These record *who else* was involved, never instead of them,
	 * which is what lets the constitution's "attributable to the agent and the authorizing principal"
	 * hold without redefining an existing field.
	 */
	viaClientId?: string | null;
	viaSurface?: 'mcp' | null;
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
	/*
	 * Which surface the action arrived on. `'mcp'` selects agent-initiated actions; `'console'` selects
	 * the rest, which store the field absent rather than set — so the filter translates rather than
	 * compares. `matchesAuditQuery` does that translation, once, for both adapters.
	 */
	viaSurface?: string;
	viaClientId?: string;
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

/*
 * A described-but-not-yet-performed high-consequence MCP operation, and the operator's approval of it.
 *
 * Single-use and expiring, both enforced by this record's existence: redemption deletes it, so a token
 * cannot be spent twice, and the TTL index reaps what nobody confirmed. A self-contained signed token
 * would need no storage but could be neither revoked nor spent once.
 */
export interface McpConfirmation {
	_id: string;
	/* The tool the token authorizes. A token for one tool never authorizes another. */
	tool: string;
	/*
	 * Canonical target identity — the resolved path parameters, joined. Human-readable on purpose: it
	 * appears in the refusal when a confirmation is presented for the wrong target.
	 */
	targetKey: string;
	/*
	 * SHA-256 over the canonicalised arguments. What makes "the parameters differ from what was
	 * described" checkable rather than aspirational.
	 */
	argumentsHash: string;
	/* One operator's confirmation must not authorize another's call. */
	principalId: string;
	/* Nor one agent's a different agent's. */
	viaClientId: string;
	/* The description the operator was shown, retained so a redemption can be checked against it. */
	report: Record<string, unknown>;
	createdAt: Date;
	expiresAt: Date;
}

export interface McpConfirmationStoreInstance {
	issue(
		data: Omit<McpConfirmation, '_id' | 'createdAt' | 'expiresAt'> & {
			ttlSeconds: number;
		}
	): Promise<McpConfirmation>;
	/*
	 * Deletes and returns the record in one step, so a concurrent second redemption of the same token
	 * finds nothing. Returns null when the token is unknown, already spent, or expired — the caller
	 * cannot tell those apart, and does not need to.
	 */
	redeem(id: string): Promise<McpConfirmation | null>;
	/* Test seam: the count of live confirmations. No product surface lists them. */
	count(): Promise<number>;
}

export interface McpConfirmationStoreConstructor {
	new (): McpConfirmationStoreInstance;
}

/* Which plane raised a fault. Drives the surface filter, and is captured, never inferred. */
export type ErrorSurface = 'oauth' | 'admin' | 'mcp' | 'interaction';

/* How much of the caller's address a record keeps. See errorStore.originCaptureLevel. */
export type OriginCaptureLevel = 'omitted' | 'anonymized' | 'full';

/*
 * Where in the server a fault arose. Parsed rather than stored as a raw stack: an interpolated error
 * message is the likeliest way a request value reaches this record by accident, so nothing keeps a
 * verbatim stack.
 */
export interface ErrorOrigin {
	file: string;
	line: number | null;
	frame: string;
}

/*
 * One occurrence of a fault. Immutable once written — there is no path through any surface that edits
 * one, which is why the store interface below offers no update.
 */
export interface ErrorRecord {
	/* The opaque identifier handed to the caller, and the only thing they can report back. */
	reference: string;
	at: Date;
	/*
	 * `null` throughout means "not known" and is written explicitly rather than inferred — an
	 * unauthenticated malformed request genuinely has no client, and guessing one would make the record
	 * lie about who was involved.
	 */
	clientId: string | null;
	actor: { id: string; email: string } | null;
	scope: string | null;
	requestId: string | null;
	/*
	 * The caller's origin at the configured level. `'not-captured'` is distinct from `null`: the first
	 * says the operator chose not to look, the second that there was nothing to see. A reader must not
	 * have to tell those apart by consulting the configuration.
	 */
	origin: string | null | 'not-captured';
	userAgent: string | null;
	/*
	 * Names of the fields the request carried — never their values, so no secret can reach the store
	 * through this field. Same rule, and the same reason, as AdminAuditEntry.attributes.
	 */
	submittedFields: string[];
}

/*
 * A distinct fault, and the unit both the caps and the reader work in. One row per fingerprint, so a
 * fault repeating a thousand times reads as one problem with a magnitude.
 */
export interface ErrorGroup {
	_id: string;
	fingerprint: string;
	errorCode: string;
	status: number;
	surface: ErrorSurface;
	/*
	 * Elysia's declaration form (`/admin/api/clients/:id`), never the concrete URL — a concrete path
	 * would split one fault into one group per identifier.
	 */
	route: string;
	method: string;
	origin: ErrorOrigin;
	message: string;
	/* Exact, always. The sample cap bounds retained detail, never the tally. */
	occurrences: number;
	firstSeenAt: Date;
	lastSeenAt: Date;
	/* Advanced on every occurrence, so a fault that is still happening does not age out mid-life. */
	expiresAt: Date;
	samples: ErrorRecord[];
}

/* What the capture path hands the store: one occurrence, already redacted and fingerprinted. */
export interface ErrorOccurrence {
	fingerprint: string;
	errorCode: string;
	status: number;
	surface: ErrorSurface;
	route: string;
	method: string;
	origin: ErrorOrigin;
	message: string;
	record: ErrorRecord;
}

export interface ErrorStoreQuery {
	errorCode?: string;
	route?: string;
	surface?: string;
	status?: number;
	clientId?: string;
	/*
	 * Matches actor id OR actor email, like AdminAuditQuery.actor: a reviewer reads emails, but a
	 * deleted administrator's records are findable only by id, and the caller should not have to know
	 * which they are holding.
	 */
	actor?: string;
	reference?: string;
	/* Inclusive bounds on lastSeenAt; either is valid alone. */
	from?: Date;
	to?: Date;
	limit?: number;
	offset?: number;
}

export interface ErrorGroupPage {
	groups: ErrorGroup[];
	/* Groups matching the filters, independent of limit/offset — the reader needs a page count. */
	total: number;
	/*
	 * Failures the queue could not accept since this process started. Non-zero means the page below is
	 * missing faults that really happened, which is a caveat a diagnostic surface must state about
	 * itself rather than leave an operator to assume completeness.
	 */
	dropped: number;
}

export interface ErrorSummaryBucket {
	key: string;
	count: number;
}

export interface ErrorSummary {
	/* Occurrences, not group rows: one fault seen 900 times must outrank nine seen once. */
	total: number;
	byErrorCode: ErrorSummaryBucket[];
	byRoute: ErrorSummaryBucket[];
	dropped: number;
}

export interface ErrorPurgeEstimate {
	groups: number;
	occurrences: number;
}

/*
 * The diagnostic record of server faults. Deliberately offers no update and no per-record delete: an
 * occurrence is immutable, and only a purge removes, and only whole groups.
 *
 * `record()` never rejects to its caller — unlike AdminAuditStoreInstance, which does so that an
 * unaudited mutation is refused. The trade is the opposite here: a fault that cannot be stored must
 * not become a second fault the caller sees.
 */
/*
 * The bounds a write enforces, passed in rather than read by the store.
 *
 * An adapter cannot import ApplicationConfig — configs/application.ts imports the adapter registry, so
 * reading config here would close a cycle. Passing them per write also matches how featureGate reads
 * flags flat per request: settings are applied by restart in a deployment, but the test suite drives one
 * long-lived instance and flips them between cases.
 */
export interface ErrorStoreBounds {
	retentionDays: number;
	maxGroups: number;
	samplesPerGroup: number;
}

export interface ErrorStoreInstance {
	record(
		occurrence: ErrorOccurrence,
		bounds: ErrorStoreBounds
	): Promise<ErrorGroup | undefined>;
	/* Newest first by (lastSeenAt desc, _id desc) — a total order, so paging cannot skip or repeat. */
	list(query?: ErrorStoreQuery): Promise<ErrorGroupPage>;
	get(id: string): Promise<ErrorGroup | undefined>;
	/*
	 * Returns undefined when no such reference exists, so the caller can say "no such record" rather
	 * than showing an empty page the operator has to interpret.
	 */
	findByReference(
		reference: string
	): Promise<{ group: ErrorGroup; sample: ErrorRecord } | undefined>;
	summarize(query?: ErrorStoreQuery): Promise<ErrorSummary>;
	previewPurge(query: ErrorStoreQuery): Promise<ErrorPurgeEstimate>;
	/* Returns how many groups went, which is what the audit trail records. */
	purge(query: ErrorStoreQuery): Promise<number>;
}

export interface ErrorStoreConstructor {
	new (): ErrorStoreInstance;
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
	/*
	 * Whether a **password** sign-in to this bucket must also carry a one-time code from an
	 * authenticator app. Defaulted `false` on read in both adapters, so a bucket document written
	 * before this field existed keeps the behaviour it had.
	 *
	 * A boolean beside `passwordLogin` rather than an enum replacing it, deliberately. An enum
	 * `'password' | 'password_totp'` would be a second field claiming to say whether the password
	 * door is open — precisely the shape `passwordLogin` above warns about, and it disagrees with
	 * `passwordLogin` the first time somebody edits one and not the other. As a boolean the two
	 * compose: `passwordLogin` says whether the door exists, this says whether it needs two keys.
	 *
	 * Governs the password door only. Federated sign-in is never gated by it — the upstream provider
	 * owns its own factor policy, exactly as `passwordLogin` governs password doors and federation
	 * availability is derived per provider.
	 *
	 * Permitted, and inert, while `passwordLogin` is false. The admin route says so rather than
	 * refusing: an operator recording intent ahead of opening the door is doing something reasonable.
	 */
	totpRequired: boolean;
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
		totpRequired?: boolean;
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
				| 'totpRequired'
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
