import QuickLRU from 'quick-lru';

let storage = new QuickLRU({ maxSize: 1000 });

export function getStorage() {
	return storage;
}

export function setStorage(store: any) {
	storage = store;
}
