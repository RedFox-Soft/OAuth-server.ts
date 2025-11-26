import { MemoryAdapter } from './memory.js';

let Adapter = MemoryAdapter;

if (process.env.MONGODB_URI) {
	Adapter = (await import('./mongodb.ts')).MongoAdapter;
}

if (process.env.NODE_ENV === 'test') {
	Adapter = (await import('../../test/models.ts')).TestAdapter;
}

const cache = new Map();
export function adapter(name: string) {
	if (!cache.has(name)) {
		cache.set(name, new Adapter(name));
	}
	return cache.get(name);
}
