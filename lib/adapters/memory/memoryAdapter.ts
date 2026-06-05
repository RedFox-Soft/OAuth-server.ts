import epochTime from '../../helpers/epoch_time.js';
import { getStorage } from './storage.js';
import {
	grantKeyFor,
	sessionUidKeyFor,
	userCodeKeyFor,
	grantable
} from './helpers.js';

export class MemoryAdapter {
	model: string;

	constructor(model: string) {
		this.model = model;
	}

	key(id: string) {
		return `${this.model}:${id}`;
	}

	async destroy(id: string) {
		const key = this.key(id);
		getStorage().delete(key);
	}

	async consume(id: string) {
		getStorage().get(this.key(id)).consumed = epochTime();
	}

	async find(id: string) {
		return getStorage().get(this.key(id));
	}

	async findByUid(uid: string) {
		const id = getStorage().get(sessionUidKeyFor(uid));
		return this.find(id);
	}

	async findByUserCode(userCode: string) {
		const id = getStorage().get(userCodeKeyFor(userCode));
		return this.find(id);
	}

	async upsert(id: string, payload: any, expiresIn: number) {
		const key = this.key(id);
		const storage = getStorage();

		if (this.model === 'Session') {
			storage.set(sessionUidKeyFor(payload.uid), id, expiresIn * 1000);
		}

		const { grantId, userCode } = payload;
		if (grantable.has(this.model) && grantId) {
			const grantKey = grantKeyFor(grantId);
			const grant = storage.get(grantKey);
			if (!grant) {
				storage.set(grantKey, [key]);
			} else {
				grant.push(key);
			}
		}

		if (userCode) {
			storage.set(userCodeKeyFor(userCode), id, expiresIn * 1000);
		}

		storage.set(key, payload, expiresIn * 1000);
	}

	async revokeByGrantId(grantId: string) {
		const grantKey = grantKeyFor(grantId);
		const storage = getStorage();
		const grant = storage.get(grantKey);
		if (grant) {
			grant.forEach((token: string) => storage.delete(token));
			storage.delete(grantKey);
		}
	}
}
