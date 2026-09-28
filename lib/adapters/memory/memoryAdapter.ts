import epochTime from '../../helpers/epoch_time.js';
import { getStorage } from './storage.js';
import {
	modelKeyFor,
	grantKeyFor,
	sessionUidKeyFor,
	userCodeKeyFor,
	grantable,
	type ModelStorageKey
} from './helpers.js';
import type { ModelAdapter } from '../types.js';

type StoredRecord = Record<string, unknown>;

/*
 * The three readers of the one store, each narrowing to what its key prefix holds. A key read by the
 * wrong reader answers undefined rather than a value of another kind.
 */
function recordAt(key: string): StoredRecord | undefined {
	const value = getStorage().get(key);
	return typeof value === 'object' && !Array.isArray(value) ? value : undefined;
}

function idAt(key: string): string | undefined {
	const value = getStorage().get(key);
	return typeof value === 'string' ? value : undefined;
}

function keysAt(key: string): string[] | undefined {
	const value = getStorage().get(key);
	return Array.isArray(value) ? value : undefined;
}

function stringField(record: StoredRecord, field: string): string | undefined {
	const value = record[field];
	return typeof value === 'string' ? value : undefined;
}

/*
 * A record is stored as the object it was given and handed back as an object: which model's payload it
 * is, is the model's to check (BaseModel.fromStored), not a type this backend can vouch for.
 */
export class MemoryAdapter<
	TModelName extends string = string
> implements ModelAdapter<StoredRecord> {
	model: TModelName;

	constructor(model: TModelName) {
		this.model = model;
	}

	key(id: string): ModelStorageKey<TModelName> {
		return modelKeyFor(this.model, id);
	}

	async destroy(id: string) {
		getStorage().delete(this.key(id));
	}

	async consume(id: string) {
		const stored = recordAt(this.key(id));
		if (stored) {
			stored.consumed = epochTime();
		}
	}

	async find(id: string) {
		return recordAt(this.key(id));
	}

	async findByUid(uid: string) {
		const id = idAt(sessionUidKeyFor(uid));
		return id === undefined ? undefined : this.find(id);
	}

	async findByUserCode(userCode: string) {
		const id = idAt(userCodeKeyFor(userCode));
		return id === undefined ? undefined : this.find(id);
	}

	async upsert(id: string, payload: StoredRecord, expiresIn: number) {
		const key = this.key(id);
		const storage = getStorage();
		const uid = stringField(payload, 'uid');
		const grantId = stringField(payload, 'grantId');
		const userCode = stringField(payload, 'userCode');

		if (this.model === 'Session' && uid) {
			storage.set(sessionUidKeyFor(uid), id, {
				maxAge: expiresIn * 1000
			});
		}

		if (grantable.has(this.model) && grantId) {
			const grantKey = grantKeyFor(grantId);
			const grant = keysAt(grantKey);
			if (!grant) {
				storage.set(grantKey, [key]);
			} else {
				grant.push(key);
			}
		}

		if (userCode) {
			storage.set(userCodeKeyFor(userCode), id, {
				maxAge: expiresIn * 1000
			});
		}

		storage.set(key, payload, {
			maxAge: expiresIn * 1000
		});
	}

	/*
	 * Per-collection, matching MongoAdapter: deletes only the keys bearing this model's own prefix and
	 * leaves the rest of the index for the other models to claim. Before, this deleted every key under
	 * `grant:<id>` and dropped the index, so the first of revoke()'s five calls wiped all five areas and
	 * the other four no-op'd against a missing index — the same method meaning two different things per
	 * adapter. No migration is needed: the index has always stored full model-prefixed keys.
	 */
	async revokeByGrantId(grantId: string) {
		const grantKey = grantKeyFor(grantId);
		const storage = getStorage();
		const grant = keysAt(grantKey);
		if (!grant) {
			return;
		}

		const prefix = `${this.model}:`;
		const remaining: string[] = [];
		for (const key of grant) {
			if (key.startsWith(prefix)) {
				storage.delete(key);
			} else {
				remaining.push(key);
			}
		}

		if (remaining.length === 0) {
			storage.delete(grantKey);
		} else {
			storage.set(grantKey, remaining);
		}
	}

	async destroyByOwner(field: string, value: string) {
		const storage = getStorage();
		const prefix = `${this.model}:`;
		/*
		 * Snapshot before deleting: iterating a store while removing from it is undefined, and the Set
		 * also collapses the duplicate a QuickLRU can yield from its two internal caches.
		 */
		const keys = new Set(storage.keys());

		let destroyed = 0;
		for (const key of keys) {
			if (!key.startsWith(prefix)) {
				continue;
			}
			const stored = recordAt(key);
			/* Expired but not yet evicted — already gone as far as any reader is concerned. */
			if (!stored) {
				continue;
			}
			if (stringField(stored, field) === value) {
				storage.delete(key);
				destroyed += 1;
			}
		}
		return destroyed;
	}

	async destroyUnusedSince(
		markerField: string,
		usedField: string,
		ageField: string,
		before: number
	) {
		const storage = getStorage();
		const prefix = `${this.model}:`;
		/* Snapshot first, for the same reason `destroyByOwner` does. */
		const keys = new Set(storage.keys());

		let destroyed = 0;
		for (const key of keys) {
			if (!key.startsWith(prefix)) {
				continue;
			}
			const record = recordAt(key);
			if (!record) {
				continue;
			}
			const age = record[ageField];
			if (
				record[markerField] === true &&
				record[usedField] === undefined &&
				typeof age === 'number' &&
				age < before
			) {
				storage.delete(key);
				destroyed += 1;
			}
		}
		return destroyed;
	}
}
