import {
	describe,
	it,
	expect,
	beforeAll,
	beforeEach,
	afterEach,
	spyOn
} from 'bun:test';

import bootstrap, { seedClient } from '../test_helper.js';
import { testSigningKeys } from './fixtures.js';
import { writeRootKeys } from '../root_keys.js';
import { getBucketKeysStore } from 'lib/adapters/index.js';
import { ROOT_KEY_OWNER } from 'lib/consts/key_owner.js';
import {
	ensureRootKey,
	invalidateRootKeys,
	KEY_CACHE_SECONDS,
	KEY_PUBLICATION_SECONDS,
	RETIRED_KEY_LIFETIME_SECONDS,
	rootKeys
} from 'lib/keys/issuer_keys.js';
import * as lifecycle from 'lib/admin/key_lifecycle.js';
import { Client } from 'lib/models/client.js';
import { IdToken } from 'lib/models/id_token.js';
import { ISSUER } from 'lib/configs/env.js';
import { DEFAULT_REQUEST_BUCKET } from 'lib/configs/issuer.js';
import * as JWT from 'lib/helpers/jwt.js';

const [bootRsa] = testSigningKeys;

// The root owner as the admin service builds it, without the audit trail this spec does not examine.
const root: lifecycle.KeyOwner = {
	id: ROOT_KEY_OWNER,
	audit: async () => {},
	invalidate: async () => {
		invalidateRootKeys();
		await rootKeys();
	}
};

/* Moves the clock forward by `seconds` from the time it is called, cumulatively. */
function later(seconds: number) {
	const now = Date.now();
	spyOn(Date, 'now').mockReturnValue(now + seconds * 1000);
}

async function idToken() {
	const client = await Client.find('rp');
	const token = new IdToken(client, { sub: 'someone' });
	// The claims an ID Token carries are those its scope grants; `openid` grants `sub`.
	token.scope = 'openid';
	return token.issue('idtoken');
}

async function verifies(jwt: string) {
	const client = await Client.find('rp');
	try {
		await IdToken.validate(jwt, client, ISSUER, DEFAULT_REQUEST_BUCKET);
		return true;
	} catch {
		return false;
	}
}

const kidOf = (jwt: string) => JWT.header(jwt).kid;

async function promotedRsaKey() {
	const { kid } = await lifecycle.generateKey(root, 'RS256');
	later(KEY_PUBLICATION_SECONDS + 1);
	await lifecycle.promoteKey(root, kid);
	return kid;
}

/**
 * @proves The root issuer rotates its signing key with no restart: a promoted key signs the next token
 * on every instance within the cache bound, a token issued before keeps verifying, a retired key keeps
 * verifying until its lifetime ends and is then hidden while its record stays, and a root with no keys
 * is given exactly one.
 */
describe('the root signing key lifecycle', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'store' });
		seedClient({
			clientId: 'rp',
			clientSecret: 'secret',
			redirectUris: ['https://rp.example.test/cb']
		});
	});

	beforeEach(async () => {
		await writeRootKeys(testSigningKeys);
		invalidateRootKeys();
		await rootKeys();
	});

	afterEach(() => {
		(Date.now as unknown as { mockRestore?: () => void }).mockRestore?.();
	});

	it('signs the next ID Token with a key promoted in its algorithm, without a restart', async () => {
		expect(kidOf(await idToken())).toBe(bootRsa.kid);

		const kid = await promotedRsaKey();

		expect(kidOf(await idToken())).toBe(kid);
	});

	it('still verifies an ID Token issued before the promotion', async () => {
		const before = await idToken();

		await promotedRsaKey();

		expect(await verifies(before)).toBe(true);
	});

	/*
	 * Another instance's promotion reaches this one only through the store, so it is written there
	 * directly and this instance's cache is left alone — the case a second machine is in.
	 */
	it('signs with a key another instance promoted once the cache bound has passed', async () => {
		const { kid } = await lifecycle.generateKey(root, 'RS256');
		await rootKeys();
		const store = getBucketKeysStore();
		const at = new Date(Date.now());
		await store.setState(ROOT_KEY_OWNER, kid, 'signing', at);
		await store.setState(ROOT_KEY_OWNER, bootRsa.kid, 'published', at);

		later(KEY_CACHE_SECONDS + 1);

		expect(kidOf(await idToken())).toBe(kid);
	});

	it('keeps publishing and verifying a retired key until its lifetime ends', async () => {
		const before = await idToken();
		await promotedRsaKey();
		await lifecycle.retireKey(root, bootRsa.kid, bootRsa.kid);

		const published = (await rootKeys()).publicJWKS.keys.map((key) => key.kid);
		expect(published).toContain(bootRsa.kid);
		expect(await verifies(before)).toBe(true);
	});

	it('hides a retired key once its lifetime ends — not published, verifying nothing — while its record remains', async () => {
		const before = await idToken();
		await promotedRsaKey();
		await lifecycle.retireKey(root, bootRsa.kid, bootRsa.kid);

		later(RETIRED_KEY_LIFETIME_SECONDS + KEY_CACHE_SECONDS + 1);
		invalidateRootKeys();

		const published = (await rootKeys()).publicJWKS.keys.map((key) => key.kid);
		expect(published).not.toContain(bootRsa.kid);
		expect(await verifies(before)).toBe(false);
		expect(
			(await getBucketKeysStore().find(ROOT_KEY_OWNER, bootRsa.kid))?.state
		).toBe('retired');
	});

	it('gives a root with no keys exactly one signing key, however many ask at once', async () => {
		await getBucketKeysStore().destroyByBucket(ROOT_KEY_OWNER);

		await Promise.all([ensureRootKey(), ensureRootKey(), ensureRootKey()]);

		const records = await getBucketKeysStore().listByBucket(ROOT_KEY_OWNER);
		expect(records).toHaveLength(1);
		expect(records[0].state).toBe('signing');
	});
});
