import { MemoryAdapter, configStore as memoryConfig } from './memory.js';

let Adapter = MemoryAdapter;
export let configStore = memoryConfig;

if (process.env.MONGODB_URI) {
	const mongodb = await import('./mongodb.js');
	Adapter = mongodb.MongoAdapter;
	configStore = mongodb.configStore;
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
