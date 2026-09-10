import {
	MemoryAdapter,
	JWKSStore as MemoryJWKS,
	UserStore as MemoryUser,
	GroupStore as MemoryGroupStore,
	GroupInvitationStore as MemoryGroupInvitationStore,
	ProjectStore as MemoryProjectStore,
	ProtectedResourceStore as MemoryProtectedResourceStore,
	McpClientPermissionStore as MemoryMcpClientPermissionStore,
	UserBucketStore as MemoryUserBucketStore,
	AdminSessionStore as MemoryAdminSessionStore,
	AdminAuditStore as MemoryAdminAuditStore,
	ErrorStore as MemoryErrorStore,
	McpConfirmationStore as MemoryMcpConfirmationStore,
	SmtpSettingsStore as MemorySmtpSettingsStore,
	SingletonSecretStore as MemorySingletonSecretStore,
	SchemaMigrationStore as MemorySchemaMigrationStore,
	MigrationLeaseStore as MemoryMigrationLeaseStore,
	configStore as memoryConfig
} from './memory/index.js';
import type {
	AdapterConfigStore,
	AdminAuditStoreConstructor,
	AdminAuditStoreInstance,
	ErrorStoreConstructor,
	ErrorStoreInstance,
	GroupStoreConstructor,
	GroupStoreInstance,
	GroupInvitationStoreConstructor,
	GroupInvitationStoreInstance,
	AdminSessionStoreConstructor,
	AdminSessionStoreInstance,
	JWKSStoreConstructor,
	McpConfirmationStoreConstructor,
	McpConfirmationStoreInstance,
	JWKSStoreInstance,
	ModelAdapter,
	ModelAdapterConstructor,
	PayloadForModel,
	ProjectStoreConstructor,
	ProjectStoreInstance,
	ProtectedResourceStoreConstructor,
	ProtectedResourceStoreInstance,
	McpClientPermissionStoreConstructor,
	McpClientPermissionStoreInstance,
	MigrationLeaseStoreConstructor,
	MigrationLeaseStoreInstance,
	SchemaMigrationStoreConstructor,
	SchemaMigrationStoreInstance,
	SecretStoreConstructor,
	SecretStoreInstance,
	SmtpSettingsStoreConstructor,
	SmtpSettingsStoreInstance,
	UserBucketStoreConstructor,
	UserBucketStoreInstance,
	UserStoreConstructor,
	UserStoreInstance
} from './types.js';
import { selectBackend } from './selectBackend.js';
import { withDeadline } from '../helpers/deadline.js';

let Adapter: ModelAdapterConstructor = MemoryAdapter;
let UserStore: UserStoreConstructor = MemoryUser;
let JWKSStoreClass: JWKSStoreConstructor = MemoryJWKS;
let GroupStoreClass: GroupStoreConstructor = MemoryGroupStore;
let GroupInvitationStoreClass: GroupInvitationStoreConstructor =
	MemoryGroupInvitationStore;
let ProjectStoreClass: ProjectStoreConstructor = MemoryProjectStore;
let ProtectedResourceStoreClass: ProtectedResourceStoreConstructor =
	MemoryProtectedResourceStore;
let McpClientPermissionStoreClass: McpClientPermissionStoreConstructor =
	MemoryMcpClientPermissionStore;
let BucketStoreClass: UserBucketStoreConstructor = MemoryUserBucketStore;
let AdminSessionStoreClass: AdminSessionStoreConstructor =
	MemoryAdminSessionStore;
let AdminAuditStoreClass: AdminAuditStoreConstructor = MemoryAdminAuditStore;
let ErrorStoreClass: ErrorStoreConstructor = MemoryErrorStore;
let McpConfirmationStoreClass: McpConfirmationStoreConstructor =
	MemoryMcpConfirmationStore;
let SmtpSettingsStoreClass: SmtpSettingsStoreConstructor =
	MemorySmtpSettingsStore;
let SecretStoreClass: SecretStoreConstructor = MemorySingletonSecretStore;
let SchemaMigrationStoreClass: SchemaMigrationStoreConstructor =
	MemorySchemaMigrationStore;
let MigrationLeaseStoreClass: MigrationLeaseStoreConstructor =
	MemoryMigrationLeaseStore;
export let configStore: AdapterConfigStore = memoryConfig;

/*
 * Decided before anything is constructed, so a deployment that configured two datastores is refused
 * here rather than discovered later by whichever store happened to be built first. The decision is a
 * pure function of the environment (selectBackend.ts) precisely so it can be tested without importing
 * this module, which builds every store as a side effect.
 */
const backend = selectBackend(process.env);

if (backend === 'postgres') {
	const postgres = await import('./postgres/index.js');
	Adapter = postgres.SqlAdapter;
	configStore = postgres.configStore;
	UserStore = postgres.UserStore;
	JWKSStoreClass = postgres.JWKSStore;
	GroupStoreClass = postgres.GroupStore;
	GroupInvitationStoreClass = postgres.GroupInvitationStore;
	ProjectStoreClass = postgres.ProjectStore;
	ProtectedResourceStoreClass = postgres.ProtectedResourceStore;
	McpClientPermissionStoreClass = postgres.McpClientPermissionStore;
	BucketStoreClass = postgres.UserBucketStore;
	AdminSessionStoreClass = postgres.AdminSessionStore;
	AdminAuditStoreClass = postgres.AdminAuditStore;
	ErrorStoreClass = postgres.ErrorStore;
	McpConfirmationStoreClass = postgres.McpConfirmationStore;
	SmtpSettingsStoreClass = postgres.SmtpSettingsStore;
	SecretStoreClass = postgres.SingletonSecretStore;
	SchemaMigrationStoreClass = postgres.SchemaMigrationStore;
	MigrationLeaseStoreClass = postgres.MigrationLeaseStore;

	/*
	 * Started here rather than left to a caller, because MongoDB gets the equivalent from its server
	 * for free. A PostgreSQL deployment whose sweeper was never started would reclaim nothing, ever,
	 * and the only symptom would be storage that grows — no error, no failing request. The timer is
	 * unreferenced, so it cannot hold a process open.
	 */
	postgres.startSweeper();
}

if (backend === 'mongodb') {
	const mongodb = await import('./mongodb/index.js');
	Adapter = mongodb.MongoAdapter;
	configStore = mongodb.configStore;
	UserStore = mongodb.UserStore;
	JWKSStoreClass = mongodb.JWKSStore;
	GroupStoreClass = mongodb.GroupStore;
	GroupInvitationStoreClass = mongodb.GroupInvitationStore;
	ProjectStoreClass = mongodb.ProjectStore;
	ProtectedResourceStoreClass = mongodb.ProtectedResourceStore;
	McpClientPermissionStoreClass = mongodb.McpClientPermissionStore;
	BucketStoreClass = mongodb.UserBucketStore;
	AdminSessionStoreClass = mongodb.AdminSessionStore;
	AdminAuditStoreClass = mongodb.AdminAuditStore;
	ErrorStoreClass = mongodb.ErrorStore;
	McpConfirmationStoreClass = mongodb.McpConfirmationStore;
	SmtpSettingsStoreClass = mongodb.SmtpSettingsStore;
	SecretStoreClass = mongodb.SingletonSecretStore;
	SchemaMigrationStoreClass = mongodb.SchemaMigrationStore;
	MigrationLeaseStoreClass = mongodb.MigrationLeaseStore;
}

if (process.env.NODE_ENV === 'test') {
	Adapter = (await import('../../test/models.js')).TestAdapter;
}

export const jwksStore: JWKSStoreInstance = new JWKSStoreClass();
export const adminSessionStore: AdminSessionStoreInstance =
	new AdminSessionStoreClass();
export const adminAuditStore: AdminAuditStoreInstance =
	new AdminAuditStoreClass();
export const mcpConfirmationStore: McpConfirmationStoreInstance =
	new McpConfirmationStoreClass();
/*
 * Which client identities may reach the administrative MCP plane. Eager like the stores above rather
 * than a lazy getter, because it is read on the request path of every administrative MCP call — that
 * live read is what makes a withdrawal take effect on the agent's next call instead of when its token
 * expires.
 */
export const mcpClientPermissionStore: McpClientPermissionStoreInstance =
	new McpClientPermissionStoreClass();
export const errorStore: ErrorStoreInstance = new ErrorStoreClass();
/* Eagerly constructed like the stores above, because both secrets are resolved at module scope —
 * configs/application.ts for the nonce secret, configs/pairwiseSalt.ts for the salt — before any
 * request, and a lazy getter would only defer that by one call.
 *
 * Two instances of one class, and the string is the whole distinction: it derives the document each
 * owns inside the shared serviceConfig area. Changing either string orphans that secret and silently
 * provisions a new one, which for the salt means reassigning every relying party's account key. */
export const dpopNonceSecretStore: SecretStoreInstance = new SecretStoreClass(
	'dpopNonceSecret'
);
export const pairwiseSaltStore: SecretStoreInstance = new SecretStoreClass(
	'pairwiseSalt'
);

/*
 * Keys the anonymized form of a caller's origin in the error store. A per-deployment secret, because
 * the requirement has two halves that pull against each other: the stored value must not be reversible
 * to the address, and two requests from one origin must still land on the same value. An unkeyed hash
 * of an address space that small is reversible by enumeration; a per-record salt would break the
 * second half.
 *
 * Shares the serviceConfig area's permanence for the reason the salt beside it does: a regenerated key
 * would silently stop correlating, and every record written before it would read as a different origin.
 */
export const errorOriginSaltStore: SecretStoreInstance = new SecretStoreClass(
	'errorOriginSalt'
);

export const cache = new Map();

/*
 * Whether the selected datastore answers.
 *
 * One function rather than a store method, because the question is about the backend and not about
 * any area — and because the in-memory case has to answer without there being anything to ask.
 *
 * Resolved lazily per call rather than captured at selection time: the probe is used by the startup
 * check and by the readiness endpoint, and binding it during module evaluation would mean importing
 * a driver on a path that has none.
 */
/*
 * How long a probe may take before it counts as a failure.
 *
 * A driver's own timeout bounds *establishing* a connection, not a query issued on one it already
 * holds — and the case that matters is the second: a database that is up, connected, and no longer
 * answering. Measured against a paused PostgreSQL container, an unbounded probe took 30 seconds to
 * come back, which is three orchestrator probe intervals spent holding a request open. Both drivers
 * behave that way, so the deadline lives here, at the seam both backends pass through, rather than
 * being written twice with two chances to be forgotten.
 *
 * Five seconds is long enough that a merely slow database is not called unreachable, and short
 * enough to answer inside a probe interval. The losing query is not cancellable — it finishes into
 * nothing — which is why `lib/actions/ready.ts` also refuses to start a second probe while one is
 * still in flight.
 */
const PING_TIMEOUT_MS = 5_000;

export async function storagePing(
	timeoutMs: number = PING_TIMEOUT_MS
): Promise<void> {
	await withDeadline(probe(), timeoutMs, 'storage');
}

async function probe(): Promise<void> {
	if (backend === 'postgres') {
		await (await import('./postgres/index.js')).ping();
		return;
	}
	if (backend === 'mongodb') {
		await (await import('./mongodb/db.js')).ping();
		return;
	}
	/* Nothing to reach. An in-memory deployment is reachable exactly as long as the process is, which
	 * is what the liveness endpoint already answers. */
}
export function adapter<TModelName extends string>(
	name: TModelName
): ModelAdapter<PayloadForModel<TModelName>> {
	if (!cache.has(name)) {
		cache.set(name, new Adapter(name));
	}
	return cache.get(name) as ModelAdapter<PayloadForModel<TModelName>>;
}

export type {
	KnownModelName,
	ModelPayloadByName,
	PayloadForModel
} from './modelTypes.js';

const userStores = new Map<string, UserStoreInstance>();
export function getUserStore(area = 'redfox'): UserStoreInstance {
	if (!userStores.has(area)) {
		userStores.set(area, new UserStore(area));
	}
	return userStores.get(area) as UserStoreInstance;
}

let groupStoreSingleton: GroupStoreInstance | null = null;
export function getGroupStore(): GroupStoreInstance {
	if (!groupStoreSingleton) {
		groupStoreSingleton = new GroupStoreClass();
	}
	return groupStoreSingleton;
}

let groupInvitationStoreSingleton: GroupInvitationStoreInstance | null = null;
export function getGroupInvitationStore(): GroupInvitationStoreInstance {
	if (!groupInvitationStoreSingleton) {
		groupInvitationStoreSingleton = new GroupInvitationStoreClass();
	}
	return groupInvitationStoreSingleton;
}

let projectStoreSingleton: ProjectStoreInstance | null = null;
export function getProjectStore(): ProjectStoreInstance {
	if (!projectStoreSingleton) {
		projectStoreSingleton = new ProjectStoreClass();
	}
	return projectStoreSingleton;
}

/*
 * Declared protected resources. There is deliberately no memo in front of this store: it is read on
 * every token request carrying a `resource`, and a deleted declaration has to stop issuance on the
 * very next request — which a cache would defer. Same reasoning as `tryFindClient` reading the
 * adapter every time.
 */
let protectedResourceStoreSingleton: ProtectedResourceStoreInstance | null =
	null;
export function getProtectedResourceStore(): ProtectedResourceStoreInstance {
	if (!protectedResourceStoreSingleton) {
		protectedResourceStoreSingleton = new ProtectedResourceStoreClass();
	}
	return protectedResourceStoreSingleton;
}

let bucketStoreSingleton: UserBucketStoreInstance | null = null;
export function getBucketStore(): UserBucketStoreInstance {
	if (!bucketStoreSingleton) {
		bucketStoreSingleton = new BucketStoreClass();
	}
	return bucketStoreSingleton;
}

/*
 * The record of applied schema migrations. Lazy, unlike the stores above it: it is read once by the
 * startup gate and once per migration run, never on a request path, so there is nothing to gain by
 * building it at import time and something to lose — this module is imported by the test suite, which
 * has no migrations to check.
 */
let schemaMigrationStoreSingleton: SchemaMigrationStoreInstance | null = null;
export function getSchemaMigrationStore(): SchemaMigrationStoreInstance {
	if (!schemaMigrationStoreSingleton) {
		schemaMigrationStoreSingleton = new SchemaMigrationStoreClass();
	}
	return schemaMigrationStoreSingleton;
}

/* Lazy for the same reason the record store beside it is: read once per migration run and once at
 * startup, never on a request path. */
let migrationLeaseStoreSingleton: MigrationLeaseStoreInstance | null = null;
export function getMigrationLeaseStore(): MigrationLeaseStoreInstance {
	if (!migrationLeaseStoreSingleton) {
		migrationLeaseStoreSingleton = new MigrationLeaseStoreClass();
	}
	return migrationLeaseStoreSingleton;
}

let smtpSettingsStoreSingleton: SmtpSettingsStoreInstance | null = null;
export function getSmtpSettingsStore(): SmtpSettingsStoreInstance {
	if (!smtpSettingsStoreSingleton) {
		smtpSettingsStoreSingleton = new SmtpSettingsStoreClass();
	}
	return smtpSettingsStoreSingleton;
}

// Test-only: drop the cached admin store singletons so a spec that requires a
// clean admin bucket/project (e.g. first-run setup, the UI shell) is not
// contaminated by users/projects another spec seeded earlier in the same
// process. The memory stores hold state in-instance; for the mongo stores this
// only drops stateless wrapper caches, so it is safe in any mode.
export function resetAdminMemoryStores(): void {
	userStores.clear();
	projectStoreSingleton = null;
	bucketStoreSingleton = null;
	groupStoreSingleton = null;
	groupInvitationStoreSingleton = null;
}
