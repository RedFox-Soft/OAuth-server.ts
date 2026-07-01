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
import type { PayloadForModel } from '../modelTypes.js';

type AdapterStoreValue<TModelName extends string> =
	PayloadForModel<TModelName> | string | string[];

function getStringField(payload: unknown, field: string): string | undefined {
	if (payload && typeof payload === 'object') {
		const value = Reflect.get(payload, field);
		if (typeof value === 'string') {
			return value;
		}
	}
}

export class MemoryAdapter<
	TModelName extends string = string
> implements ModelAdapter<PayloadForModel<TModelName>> {
	model: TModelName;

	constructor(model: TModelName) {
		this.model = model;
	}

	key(id: string): ModelStorageKey<TModelName> {
		return modelKeyFor(this.model, id);
	}

	async destroy(id: string) {
		const key = this.key(id);
		const storage = getStorage<AdapterStoreValue<TModelName>>();
		storage.delete(key);
	}

	async consume(id: string) {
		const storage = getStorage<AdapterStoreValue<TModelName>>();
		const stored = storage.get<PayloadForModel<TModelName>>(this.key(id));
		if (stored) {
			Reflect.set(stored, 'consumed', epochTime());
		}
	}

	async find(id: string) {
		const storage = getStorage<AdapterStoreValue<TModelName>>();
		return storage.get<PayloadForModel<TModelName>>(this.key(id));
	}

	async findByUid(uid: string) {
		const storage = getStorage<AdapterStoreValue<TModelName>>();
		const id = storage.get<string>(sessionUidKeyFor(uid));
		if (typeof id !== 'string') {
			return;
		}
		return this.find(id);
	}

	async findByUserCode(userCode: string) {
		const storage = getStorage<AdapterStoreValue<TModelName>>();
		const id = storage.get<string>(userCodeKeyFor(userCode));
		if (typeof id !== 'string') {
			return;
		}
		return this.find(id);
	}

	async upsert(
		id: string,
		payload: PayloadForModel<TModelName>,
		expiresIn: number
	) {
		const key = this.key(id);
		const storage = getStorage<AdapterStoreValue<TModelName>>();
		const uid = getStringField(payload, 'uid');
		const grantId = getStringField(payload, 'grantId');
		const userCode = getStringField(payload, 'userCode');

		if (this.model === 'Session' && uid) {
			storage.set<string>(sessionUidKeyFor(uid), id, {
				maxAge: expiresIn * 1000
			});
		}

		if (grantable.has(this.model) && grantId) {
			const grantKey = grantKeyFor(grantId);
			const grant = storage.get<string[]>(grantKey);
			if (!grant) {
				storage.set<string[]>(grantKey, [key]);
			} else {
				grant.push(key);
			}
		}

		if (userCode) {
			storage.set<string>(userCodeKeyFor(userCode), id, {
				maxAge: expiresIn * 1000
			});
		}

		storage.set<PayloadForModel<TModelName>>(key, payload, {
			maxAge: expiresIn * 1000
		});
	}

	async revokeByGrantId(grantId: string) {
		const grantKey = grantKeyFor(grantId);
		const storage = getStorage<AdapterStoreValue<TModelName>>();
		const grant = storage.get<string[]>(grantKey);
		if (grant) {
			grant.forEach((token: string) => storage.delete(token));
			storage.delete(grantKey);
		}
	}
}
