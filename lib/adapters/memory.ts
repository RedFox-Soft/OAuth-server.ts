import QuickLRU from 'quick-lru';
import epochTime from '../helpers/epoch_time.js';
import { type User } from './types.js';

let storage = new QuickLRU({ maxSize: 1000 });

function grantKeyFor(id: string) {
	return `grant:${id}`;
}

function sessionUidKeyFor(id: string) {
	return `sessionUid:${id}`;
}

function userCodeKeyFor(userCode: string) {
	return `userCode:${userCode}`;
}

const grantable = new Set([
	'AccessToken',
	'AuthorizationCode',
	'RefreshToken',
	'DeviceCode',
	'BackchannelAuthenticationRequest'
]);

export class UserStore {
	private users = new Map<string, User>();
	name = 'redfox';

	constructor(name?: string) {
		if (name) {
			this.name = name;
		}
	}

	async findByEmail(email: string): Promise<User | null> {
		return this.users.get(email.toLowerCase()) || null;
	}

	async create(email: string, password: string): Promise<void> {
		if (this.users.has(email.toLowerCase())) {
			throw new Error('User with this email already exists');
		}

		this.users.set(email.toLowerCase(), {
			_id: crypto.randomUUID(),
			sub: crypto.randomUUID().replaceAll('-', ''),
			email,
			verified: false,
			password,
			active: true,
			createdAt: new Date(),
			updatedAt: new Date(),
			lastLoginAt: null
		});
	}
}

class ConfigStore {
	static instance = new ConfigStore();
	private config: Record<string, any> = {};

	async get(): Promise<Record<string, any> | null> {
		return this.config;
	}

	async set(config: Record<string, any>): Promise<void> {
		this.config = config;
	}
}

export const configStore = ConfigStore.instance;
export class MemoryAdapter {
	constructor(model) {
		this.model = model;
	}

	key(id) {
		return `${this.model}:${id}`;
	}

	async destroy(id) {
		const key = this.key(id);
		storage.delete(key);
	}

	async consume(id) {
		storage.get(this.key(id)).consumed = epochTime();
	}

	async find(id) {
		return storage.get(this.key(id));
	}

	async findByUid(uid) {
		const id = storage.get(sessionUidKeyFor(uid));
		return this.find(id);
	}

	async findByUserCode(userCode) {
		const id = storage.get(userCodeKeyFor(userCode));
		return this.find(id);
	}

	async upsert(id, payload, expiresIn) {
		const key = this.key(id);

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

	async revokeByGrantId(grantId) {
		const grantKey = grantKeyFor(grantId);
		const grant = storage.get(grantKey);
		if (grant) {
			grant.forEach((token) => storage.delete(token));
			storage.delete(grantKey);
		}
	}
}

export function setStorage(store) {
	storage = store;
}
