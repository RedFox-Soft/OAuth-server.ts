import {
	afterEach,
	beforeAll,
	beforeEach,
	describe,
	expect,
	it
} from 'bun:test';

import bootstrap from '../test_helper.ts';
import { admin } from '../provisioning/helpers.ts';
import { agentFor, editor, tool } from '../behind_proxy/helpers.ts';
import { sessionFor } from '../admin_session.ts';
import { ADMIN_SESSION_COOKIE } from 'lib/admin/consts.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { createAdministrator } from '../administrators.ts';
import { from, person, project, signIn } from '../person_activity/helpers.ts';
import {
	batchOf,
	daysAfter,
	deliverReport,
	foxtrust,
	known,
	lookupsOf,
	registerAt,
	seedFoxTrustKey,
	type FoxTrustFake
} from './helpers.ts';
import type { User } from 'lib/adapters/types.ts';
import { resetStoresForTests } from 'lib/adapters/index.ts';
import { forgetLookupsForTests } from 'lib/address_lookup/lookups.ts';
import { ApplicationConfig } from 'lib/configs/application.ts';
import nanoid from 'lib/helpers/nanoid.ts';

const STATUS = '/admin/api/settings/address-lookup';

let fake: FoxTrustFake;
let superAdmin: User;
let cookie: string;

beforeAll(async () => {
	await bootstrap(import.meta.url);
});

beforeEach(async () => {
	resetStoresForTests();
	forgetLookupsForTests();
	fake = foxtrust();
	await ensureAdminSeed();
	superAdmin = await createAdministrator('super', `sa-${nanoid()}@x.io`);
	cookie = `${ADMIN_SESSION_COOKIE}=${(await sessionFor(superAdmin))._id}`;
});

afterEach(() => {
	ApplicationConfig['telemetry.enabled'] = true;
});

async function status() {
	const reply = await admin('GET', STATUS, cookie);
	expect(reply.status).toBe(200);
	return reply.body;
}

/**
 * @proves A super administrator can tell from the status alone whether lookups work today and, if not, why and what to
 * do; an agent reads the same; nobody else reads it (specs/136 US3, FR-012, SC-005).
 */
describe('the address lookup status', () => {
	it("shows today's lookups used of the allowance", async () => {
		await seedFoxTrustKey();
		fake.batch = (ips) => batchOf(ips.map(known), 999);
		const bucketId = await project();
		from('203.0.113.7');
		const anna = await person(bucketId);
		await signIn(anna.email);
		await lookupsOf(cookie, bucketId, anna.accountId);

		expect(await status()).toMatchObject({
			state: 'on',
			today: { limit: 1000, remaining: 999, usedUp: false }
		});
	});

	it('says why FoxTrust stopped issuing a key', async () => {
		fake.registration = { status: 403, body: { error: 'muted' } };
		await deliverReport('2026-12-01T12:00:00Z');
		await registerAt(daysAfter('2026-12-01T13:00:00Z', 7));

		expect(await status()).toMatchObject({
			state: 'stopped',
			stopped: 'muted'
		});
	});

	it('says no key can come while usage reporting is off', async () => {
		ApplicationConfig['telemetry.enabled'] = false;

		expect(await status()).toMatchObject({ state: 'reporting-off', key: null });
	});

	it('says when this server will first ask for a key', async () => {
		await deliverReport('2026-12-01T12:00:00Z');

		expect(await status()).toMatchObject({
			state: 'waiting',
			registration: { nextTryAfter: '2026-12-08T00:00:00.000Z' }
		});
	});

	it('is the same for an agent', async () => {
		await seedFoxTrustKey();
		const answer = await tool(
			await agentFor(superAdmin),
			'address_lookup_status_get',
			{}
		);

		expect(answer.result?.structuredContent?.result).toEqual(await status());
	});

	it('is refused to an administrator who is not a super administrator', async () => {
		const plain = await editor();

		expect((await admin('GET', STATUS, plain.cookie)).status).toBe(403);
	});
});
