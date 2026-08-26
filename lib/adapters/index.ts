import {
	MemoryAdapter,
	JWKSStore as MemoryJWKS,
	UserStore as MemoryUser,
	ProjectStore as MemoryProjectStore,
	UserBucketStore as MemoryUserBucketStore,
	AdminSessionStore as MemoryAdminSessionStore,
	AdminAuditStore as MemoryAdminAuditStore,
	ErrorStore as MemoryErrorStore,
	McpConfirmationStore as MemoryMcpConfirmationStore,
	SmtpSettingsStore as MemorySmtpSettingsStore,
	SingletonSecretStore as MemorySingletonSecretStore,
	configStore as memoryConfig
} from './memory/index.js';
import type {
	AdapterConfigStore,
	AdminAuditStoreConstructor,
	AdminAuditStoreInstance,
	ErrorStoreConstructor,
	ErrorStoreInstance,
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
	SecretStoreConstructor,
	SecretStoreInstance,
	SmtpSettingsStoreConstructor,
	SmtpSettingsStoreInstance,
	UserBucketStoreConstructor,
	UserBucketStoreInstance,
	UserStoreConstructor,
	UserStoreInstance
} from './types.js';

let Adapter: ModelAdapterConstructor = MemoryAdapter;
let UserStore: UserStoreConstructor = MemoryUser;
let JWKSStoreClass: JWKSStoreConstructor = MemoryJWKS;
let ProjectStoreClass: ProjectStoreConstructor = MemoryProjectStore;
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
export let configStore: AdapterConfigStore = memoryConfig;

if (process.env.MONGODB_URI) {
	const mongodb = await import('./mongodb/index.js');
	Adapter = mongodb.MongoAdapter;
	configStore = mongodb.configStore;
	UserStore = mongodb.UserStore;
	JWKSStoreClass = mongodb.JWKSStore;
	ProjectStoreClass = mongodb.ProjectStore;
	BucketStoreClass = mongodb.UserBucketStore;
	AdminSessionStoreClass = mongodb.AdminSessionStore;
	AdminAuditStoreClass = mongodb.AdminAuditStore;
	ErrorStoreClass = mongodb.ErrorStore;
	McpConfirmationStoreClass = mongodb.McpConfirmationStore;
	SmtpSettingsStoreClass = mongodb.SmtpSettingsStore;
	SecretStoreClass = mongodb.SingletonSecretStore;
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

let projectStoreSingleton: ProjectStoreInstance | null = null;
export function getProjectStore(): ProjectStoreInstance {
	if (!projectStoreSingleton) {
		projectStoreSingleton = new ProjectStoreClass();
	}
	return projectStoreSingleton;
}

let bucketStoreSingleton: UserBucketStoreInstance | null = null;
export function getBucketStore(): UserBucketStoreInstance {
	if (!bucketStoreSingleton) {
		bucketStoreSingleton = new BucketStoreClass();
	}
	return bucketStoreSingleton;
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
}
