import QuickLRU from 'quick-lru';

type StorageOptions = {
	maxAge?: number;
};

/*
 * Everything the memory backend keeps, each under its own key prefix (helpers.ts): a model's record
 * (`<Model>:<id>`), the id a session uid or a user code points at (`sessionUid:`, `userCode:`), and the
 * record keys issued under one grant (`grant:`). The one union a key can hold, so a reader narrows what
 * it finds instead of naming what it would like to find.
 */
export type StoredValue = Record<string, unknown> | string | string[];

export interface MemoryStore {
	get(key: string): StoredValue | undefined;
	set(key: string, value: StoredValue, options?: StorageOptions): unknown;
	delete(key: string): boolean;
	/*
	 * Required by MemoryAdapter.destroyByOwner: sweeping a principal's records means finding them, and
	 * a get/set/delete-only store cannot be searched. Satisfied without adaptation by both
	 * implementors — QuickLRU and the plain Map the test harness installs via setStorage.
	 */
	keys(): IterableIterator<string>;
}

let storage: MemoryStore = new QuickLRU<string, StoredValue>({
	maxSize: 1000
});

export function getStorage(): MemoryStore {
	return storage;
}

export function setStorage(store: MemoryStore) {
	storage = store;
}
