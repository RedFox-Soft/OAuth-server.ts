import { strict as assert } from 'node:assert';

import { expect } from 'bun:test';

import epochTime from '../lib/helpers/epoch_time.ts';
import { MemoryAdapter, setStorage } from '../lib/adapters/memory/index.js';

const map = new Map();

map.del = function (...args) {
	this.delete(...args);
};

setStorage(map);
const testStorage = new Map();

export class TestAdapter extends MemoryAdapter {
	constructor(name: string) {
		if (testStorage.has(name)) return testStorage.get(name);
		super(name);
		this.store = map;
		testStorage.set(name, this);
	}

	static for(name: string) {
		if (testStorage.has(name)) return testStorage.get(name);
		return new this(name);
	}

	get(key: string) {
		return this.constructor.for(key);
	}

	static clear() {
		map.clear();
	}

	clear() {
		map.clear();
	}

	syncFind(id: string) {
		return map.get(this.key(id)) || undefined;
	}

	syncUpdate(id: string, update: object) {
		const found = map.get(this.key(id));
		if (!found) return;
		Object.assign(found, update);
	}

	async upsert(id: string, payload, expiresIn: number) {
		if (
			this.model !== 'RegistrationAccessToken' &&
			this.model !== 'InitialAccessToken' &&
			this.model !== 'Client' &&
			this.model !== 'Grant'
		) {
			expect(payload).toHaveProperty('exp');
			expect(payload.exp).toBeTypeOf('number');
			expect(Number.isFinite(payload.exp)).toBe(true);
			expect(
				Math.abs(payload.exp - (expiresIn + epochTime()))
			).toBeLessThanOrEqual(1);
		}

		return super.upsert(id, payload, expiresIn);
	}
}

export class Account {
	accountId: string;

	constructor(id: string) {
		this.accountId = id;
		testStorage.set(`Account:${this.accountId}`, this);
	}

	static get storage() {
		return testStorage;
	}

	claims(use: string, scope: string, claims: object, rejected: string[]) {
		assert.equal(typeof use, 'string');
		assert.equal(typeof scope, 'string');
		assert.equal(typeof claims, 'object');
		assert.ok(Array.isArray(rejected));

		return {
			address: {
				country: '000',
				formatted: '000',
				locality: '000',
				postal_code: '000',
				region: '000',
				street_address: '000'
			},
			birthdate: '1987-10-16',
			email: 'johndoe@example.com',
			email_verified: false,
			family_name: 'Doe',
			gender: 'male',
			given_name: 'John',
			locale: 'en-US',
			middle_name: 'Middle',
			name: 'John Doe',
			nickname: 'Johny',
			phone_number: '+420 721 773500',
			phone_number_verified: false,
			picture: 'http://lorempixel.com/400/200/',
			preferred_username: 'johnny',
			profile: 'https://johnswebsite.com',
			sub: this.accountId,
			updated_at: 1454704946,
			website: 'http://example.com',
			zoneinfo: 'Europe/Berlin'
		};
	}

	static async findAccount(ctx: unknown, sub: string, token?: string) {
		if (sub === 'notfound') {
			return undefined;
		}
		assert.equal(typeof sub, 'string');
		let acc = testStorage.get(`Account:${sub}`);
		if (!acc) {
			acc = new Account(sub);
		}
		return acc;
	}
}
