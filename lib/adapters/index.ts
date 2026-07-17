import {
	MemoryAdapter,
	JWKSStore as MemoryJWKS,
	UserStore as MemoryUser,
	ProjectStore as MemoryProjectStore,
	UserBucketStore as MemoryUserBucketStore,
	AdminSessionStore as MemoryAdminSessionStore,
	configStore as memoryConfig
} from './memory/index.js';
import type {
	AdapterConfigStore,
	AdminSessionStoreConstructor,
	AdminSessionStoreInstance,
	JWKSStoreConstructor,
	JWKSStoreInstance,
	ModelAdapter,
	ModelAdapterConstructor,
	PayloadForModel,
	ProjectStoreConstructor,
	ProjectStoreInstance,
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
}

if (process.env.NODE_ENV === 'test') {
	Adapter = (await import('../../test/models.js')).TestAdapter;
}

export const jwksStore: JWKSStoreInstance = new JWKSStoreClass();
export const adminSessionStore: AdminSessionStoreInstance =
	new AdminSessionStoreClass();

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
