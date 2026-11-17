import {
	afterEach,
	beforeAll,
	beforeEach,
	describe,
	expect,
	it
} from 'bun:test';

import bootstrap from '../test_helper.ts';
import { adminCookie } from '../end_user_lifecycle/fixtures.ts';
import { admin } from '../provisioning/helpers.ts';
import { from, person, project, signIn } from '../person_activity/helpers.ts';
import {
	daysAfter,
	deliverReport,
	foxtrust,
	lookupsOf,
	registerAt,
	seedFoxTrustKey,
	type FoxTrustFake
} from './helpers.ts';
import { configStore, resetStoresForTests } from 'lib/adapters/index.ts';
import { forgetLookupsForTests } from 'lib/address_lookup/lookups.ts';
import { ApplicationConfig } from 'lib/configs/application.ts';

let fake: FoxTrustFake;
let cookie: string;
let bucketId: string;

beforeAll(async () => {
	await bootstrap(import.meta.url);
});

beforeEach(async () => {
	resetStoresForTests();
	forgetLookupsForTests();
	// No setting saved by an earlier case: it would read as already in force, and a save of it would change nothing.
	await configStore.set({});
	cookie = await adminCookie();
	bucketId = await project();
	fake = foxtrust();
	from('203.0.113.7');
});

afterEach(() => {
	ApplicationConfig['addressLookup.enabled'] = true;
	ApplicationConfig['telemetry.enabled'] = true;
});

async function save(setting: string, value: boolean): Promise<void> {
	const reply = await admin('PUT', '/admin/api/settings', cookie, {
		[setting]: value
	});
	expect(reply.status).toBe(200);
}

async function signInAndFlush(): Promise<void> {
	const anna = await person(bucketId);
	await signIn(anna.email);
	await lookupsOf(cookie, bucketId, anna.accountId);
}

/**
 * @proves A super administrator turns lookups and registration off with one setting, without a restart, and a key
 * already received is kept for when it is turned on again (specs/136 US3, FR-010).
 */
describe('turning address lookup off', () => {
	it('sends no address while the setting is off', async () => {
		await seedFoxTrustKey();
		await save('addressLookup.enabled', false);
		await signInAndFlush();

		expect(fake.batches()).toHaveLength(0);
	});

	it('sends no registration while the setting is off', async () => {
		await deliverReport('2026-12-01T12:00:00Z');
		await save('addressLookup.enabled', false);
		await registerAt(daysAfter('2026-12-01T13:00:00Z', 7));

		expect(fake.registrations()).toHaveLength(0);
	});

	it('keeps a held key', async () => {
		await seedFoxTrustKey();
		await save('addressLookup.enabled', false);

		const reply = await admin(
			'GET',
			'/admin/api/settings/address-lookup',
			cookie
		);
		expect(reply.body).toMatchObject({
			state: 'off',
			key: { dailyQuota: 1000 }
		});
	});

	it('looks addresses up again at the next flush once turned on, without a restart', async () => {
		await seedFoxTrustKey();
		await save('addressLookup.enabled', false);
		await signInAndFlush();
		await save('addressLookup.enabled', true);
		from('203.0.113.8');
		await signInAndFlush();

		expect(fake.ipsSent()).toEqual(['203.0.113.8']);
	});

	it('goes on looking up with a held key after usage reporting is turned off', async () => {
		await seedFoxTrustKey();
		await save('telemetry.enabled', false);
		await signInAndFlush();

		expect(fake.ipsSent()).toEqual(['203.0.113.7']);
	});
});
