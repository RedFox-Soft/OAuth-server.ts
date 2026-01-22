import {
	MemoryAdapter,
	UserStore as MemoryUser,
	configStore as memoryConfig
} from './memory.js';

let Adapter = MemoryAdapter;
let UserStore = MemoryUser;
export let configStore = memoryConfig;

if (process.env.MONGODB_URI) {
	const mongodb = await import('./mongodb.js');
	Adapter = mongodb.MongoAdapter;
	configStore = mongodb.configStore;
	UserStore = mongodb.UserStore;
}

if (process.env.NODE_ENV === 'test') {
	Adapter = (await import('../../test/models.js')).TestAdapter;
}

export const cache = new Map();
export function adapter(name: string) {
	if (!cache.has(name)) {
		cache.set(name, new Adapter(name));
	}
	return cache.get(name);
}

type UserStoreType = InstanceType<typeof UserStore>;
const userStores = new Map<string, UserStoreType>();
export function getUserStore(area = 'redfox'): UserStoreType {
	if (!userStores.has(area)) {
		userStores.set(area, new UserStore(area));
	}
	return userStores.get(area) as UserStoreType;
}
