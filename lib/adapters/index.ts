import {
	MemoryAdapter,
	JWKSStore as MemoryJWKS,
	UserStore as MemoryUser,
	configStore as memoryConfig
} from './memory/index.js';
import type {
	AdapterConfigStore,
	JWKSStoreConstructor,
	JWKSStoreInstance,
	ModelAdapter,
	ModelAdapterConstructor,
	PayloadForModel,
	UserStoreConstructor,
	UserStoreInstance
} from './types.js';

let Adapter: ModelAdapterConstructor = MemoryAdapter;
let UserStore: UserStoreConstructor = MemoryUser;
let JWKSStoreClass: JWKSStoreConstructor = MemoryJWKS;
export let configStore: AdapterConfigStore = memoryConfig;

if (process.env.MONGODB_URI) {
	const mongodb = await import('./mongodb/index.js');
	Adapter = mongodb.MongoAdapter;
	configStore = mongodb.configStore;
	UserStore = mongodb.UserStore;
	JWKSStoreClass = mongodb.JWKSStore;
}

if (process.env.NODE_ENV === 'test') {
	Adapter = (await import('../../test/models.js')).TestAdapter;
}

export const jwksStore: JWKSStoreInstance = new JWKSStoreClass();

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
