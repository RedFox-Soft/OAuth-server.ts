import { expect } from 'bun:test';

import epochTime from '../lib/helpers/epoch_time.ts';
import { MemoryAdapter, setStorage } from '../lib/adapters/memory/index.js';

const map = new Map();

setStorage(map);
const testStorage = new Map<string, TestAdapter>();

export class TestAdapter extends MemoryAdapter {
	// The one storage map every model shares, exposed so a spec can inspect or seed records directly.
	declare store: typeof map;

	constructor(name: string) {
		const existing = testStorage.get(name);
		if (existing) return existing;
		super(name);
		this.store = map;
		testStorage.set(name, this);
	}

	static for(name: string) {
		return testStorage.get(name) ?? new TestAdapter(name);
	}

	get(key: string) {
		return TestAdapter.for(key);
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

	async upsert(
		id: string,
		payload: Parameters<MemoryAdapter['upsert']>[1],
		expiresIn: number
	) {
		if (
			this.model !== 'RegistrationAccessToken' &&
			this.model !== 'InitialAccessToken' &&
			this.model !== 'Client' &&
			this.model !== 'Grant'
		) {
			expect(payload).toHaveProperty('exp');
			if (typeof payload.exp !== 'number') {
				throw new TypeError('a stored payload must carry a numeric exp');
			}
			expect(Number.isFinite(payload.exp)).toBe(true);
			expect(
				Math.abs(payload.exp - (expiresIn + epochTime()))
			).toBeLessThanOrEqual(1);
		}

		return super.upsert(id, payload, expiresIn);
	}
}

// The full OIDC profile the ported conformance suite exercises masking against.
// Seeded onto a user's `claims` blob (via setSeedClaims) so the DB-backed
// findAccount returns it — the provider then masks by scope/claims parameter.
export const fullProfileClaims: Record<string, unknown> = {
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
	updated_at: 1454704946,
	website: 'http://example.com',
	zoneinfo: 'Europe/Berlin'
};
