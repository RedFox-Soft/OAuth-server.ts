import { beforeAll, beforeEach, describe, expect, it } from 'bun:test';

import bootstrap from '../test_helper.ts';
import { adminCookie } from '../end_user_lifecycle/fixtures.ts';
import { from, person, project, signIn } from '../person_activity/helpers.ts';
import {
	at,
	batchOf,
	daysAfter,
	empty,
	foxtrust,
	known,
	registerAt,
	seedFoxTrustKey,
	type FoxTrustFake
} from './helpers.ts';
import { configStore, resetStoresForTests } from 'lib/adapters/index.ts';
import { forgetLookupsForTests } from 'lib/address_lookup/lookups.ts';
import { flushPersonActivityNow } from 'lib/person_activity/flush.ts';

const DAY = '2026-12-10T10:00:00Z';
const LATER_THAT_DAY = '2026-12-10T18:00:00Z';
const NEXT_DAY = daysAfter(DAY, 1);

let fake: FoxTrustFake;
let bucketId: string;

beforeAll(async () => {
	await bootstrap(import.meta.url);
});

beforeEach(async () => {
	resetStoresForTests();
	forgetLookupsForTests();
	await configStore.set({});
	await adminCookie();
	bucketId = await project();
	fake = foxtrust();
	await seedFoxTrustKey();
});

/* A person signs in from `address`; nothing is written yet. */
async function signInFrom(address: string): Promise<void> {
	from(address);
	await signIn((await person(bucketId)).email);
}

/* The server writes what it holds, on `iso` as the lookups' clock reads it. */
function flushOn(iso: string): Promise<void> {
	return at(iso, () => flushPersonActivityNow());
}

/**
 * @proves Lookups stay within FoxTrust's daily allowance, never remember an answer FoxTrust gave because its own read
 * timed out, and ask about one address once a day (specs/136 US4, FR-007).
 */
describe('once FoxTrust says the allowance is used', () => {
	it('sends nothing more that UTC day after a quota entry', async () => {
		fake.batch = (ips) =>
			batchOf(
				ips.map((ip) => ({ ip, error: 'quota' })),
				0
			);
		await signInFrom('203.0.113.7');
		await flushOn(DAY);
		await signInFrom('203.0.113.8');
		await flushOn(LATER_THAT_DAY);

		expect(fake.ipsSent()).toEqual(['203.0.113.7']);
	});

	it('sends nothing more that UTC day after a 429 quota_exceeded', async () => {
		fake.batch = () => ({
			status: 429,
			body: { error: { code: 'quota_exceeded' } },
			headers: { 'retry-after': '3600' }
		});
		await signInFrom('203.0.113.7');
		await flushOn(DAY);
		await signInFrom('203.0.113.8');
		await flushOn(LATER_THAT_DAY);

		expect(fake.ipsSent()).toEqual(['203.0.113.7']);
	});

	it('looks addresses up again on the next UTC day', async () => {
		fake.batch = (ips) =>
			batchOf(
				ips.map((ip) => ({ ip, error: 'quota' })),
				0
			);
		await signInFrom('203.0.113.7');
		await flushOn(DAY);
		fake.batch = (ips) => batchOf(ips.map(known));
		await signInFrom('203.0.113.8');
		await flushOn(NEXT_DAY);

		expect(fake.ipsSent()).toEqual(['203.0.113.7', '203.0.113.8']);
	});
});

describe('what a process remembers for the day', () => {
	it('asks again at a later flush when every answer came back empty', async () => {
		fake.batch = (ips) => batchOf(ips.map(empty));
		await signInFrom('203.0.113.7');
		await flushOn(DAY);
		await signInFrom('203.0.113.7');
		await flushOn(LATER_THAT_DAY);

		expect(fake.ipsSent()).toEqual(['203.0.113.7', '203.0.113.7']);
	});

	it('does not ask again that day about an address FoxTrust knew nothing about beside known ones', async () => {
		fake.batch = (ips) =>
			batchOf(ips.map((ip) => (ip === '203.0.113.7' ? known(ip) : empty(ip))));
		await signInFrom('203.0.113.7');
		await signInFrom('198.51.100.4');
		await flushOn(DAY);
		await signInFrom('198.51.100.4');
		await flushOn(LATER_THAT_DAY);

		expect(fake.ipsSent().sort()).toEqual(['198.51.100.4', '203.0.113.7']);
	});

	it('does not ask again that day about an address FoxTrust called invalid', async () => {
		fake.batch = (ips) =>
			batchOf(ips.map((ip) => ({ ip, error: 'invalid_ip' })));
		await signInFrom('203.0.113.7');
		await flushOn(DAY);
		await signInFrom('203.0.113.7');
		await flushOn(LATER_THAT_DAY);

		expect(fake.ipsSent()).toEqual(['203.0.113.7']);
	});

	it('sends an address on many rows once a day', async () => {
		await signInFrom('203.0.113.7');
		await signInFrom('203.0.113.7');
		await flushOn(DAY);
		await signInFrom('203.0.113.7');
		await flushOn(LATER_THAT_DAY);

		expect(fake.ipsSent()).toEqual(['203.0.113.7']);
	});

	it('sends the same address again on the next UTC day', async () => {
		await signInFrom('203.0.113.7');
		await flushOn(DAY);
		await signInFrom('203.0.113.7');
		await flushOn(NEXT_DAY);

		expect(fake.ipsSent()).toEqual(['203.0.113.7', '203.0.113.7']);
	});
});

describe('a key FoxTrust no longer accepts', () => {
	beforeEach(async () => {
		fake.batch = () => ({
			status: 401,
			body: { error: { code: 'key_invalid' } }
		});
		await signInFrom('203.0.113.7');
		await flushOn(DAY);
	});

	it('is not used again', async () => {
		await signInFrom('203.0.113.8');
		await flushOn(LATER_THAT_DAY);

		expect(fake.batches()).toHaveLength(1);
	});

	it('is replaced by registering again the next day', async () => {
		await registerAt(daysAfter(DAY, 1.2));

		expect(fake.registrations()).toHaveLength(1);
	});
});
