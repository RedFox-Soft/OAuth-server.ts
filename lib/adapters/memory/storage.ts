import QuickLRU from 'quick-lru';

type StorageOptions = {
	maxAge?: number;
};

export interface MemoryStore<TValue = unknown> {
	get<TGet extends TValue = TValue>(key: string): TGet | undefined;
	set<TSet extends TValue = TValue>(
		key: string,
		value: TSet,
		options?: StorageOptions
	): unknown;
	delete(key: string): boolean;
	/*
	 * Required by MemoryAdapter.destroyByOwner: sweeping a principal's records means finding them, and
	 * a get/set/delete-only store cannot be searched. Satisfied without adaptation by both
	 * implementors — QuickLRU and the plain Map the test harness installs via setStorage.
	 */
	keys(): IterableIterator<string>;
}

let storage: MemoryStore<unknown> = new QuickLRU<string, unknown>({
	maxSize: 1000
}) as MemoryStore<unknown>;

export function getStorage<TValue = unknown>(): MemoryStore<TValue> {
	return storage as MemoryStore<TValue>;
}

export function setStorage<TValue = unknown>(store: MemoryStore<TValue>) {
	storage = store as MemoryStore<unknown>;
}
