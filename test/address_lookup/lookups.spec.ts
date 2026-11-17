import { beforeAll, beforeEach, describe, expect, it } from 'bun:test';

import bootstrap from '../test_helper.ts';
import { adminCookie } from '../end_user_lifecycle/fixtures.ts';
import { admin } from '../provisioning/helpers.ts';
import {
	behindProxyPath,
	checkApp,
	createApp,
	expectStatus,
	signInThrough,
	world,
	type World
} from '../behind_proxy/helpers.ts';
import {
	fromProxy,
	issueProxyKey
} from '../behind_proxy/conditions_helpers.ts';
import { from, person, project, signIn } from '../person_activity/helpers.ts';
import { forgetLookupsForTests } from 'lib/address_lookup/lookups.ts';
import {
	KEY,
	batchOf,
	foxtrust,
	lookupsOf,
	seedFoxTrustKey,
	type FoxTrustFake
} from './helpers.ts';

const MUNICH = {
	asn: 64500,
	asName: 'Example Net',
	regionCode: 'BY',
	region: 'Bavaria',
	city: 'Munich'
};

let fake: FoxTrustFake;

/**
 * @proves An administrator reads, beside a recorded address, its network owner (AS number and name) and its region
 * and city, looked up at FoxTrust's API with the key this server holds (specs/136 US1).
 */
describe('owner and location of a sign-in address', () => {
	let cookie: string;
	let bucketId: string;

	beforeAll(async () => {
		await bootstrap(import.meta.url);
		cookie = await adminCookie();
	});

	/* A process of its own per case: what an earlier case looked up is not remembered. */
	beforeEach(async () => {
		forgetLookupsForTests();
		bucketId = await project();
		fake = foxtrust();
		await seedFoxTrustKey();
		from('203.0.113.7');
	});

	it('shows the network owner, region and city once a key is held', async () => {
		const anna = await person(bucketId);
		await signIn(anna.email);

		const { rows } = await lookupsOf(cookie, bucketId, anna.accountId, {
			kind: 'signIn'
		});
		expect(rows.map((row) => [row.address, row.lookup])).toEqual([
			['203.0.113.7', MUNICH]
		]);
	});

	it("asks FoxTrust about the address with this server's key", async () => {
		const anna = await person(bucketId);
		await signIn(anna.email);
		await lookupsOf(cookie, bucketId, anna.accountId);

		const [sent] = fake.batches();
		expect(sent.headers.authorization).toBe(`Bearer ${KEY}`);
		expect(JSON.parse(sent.body)).toEqual({ ips: ['203.0.113.7'] });
	});

	it('shows only the owner of an address FoxTrust knows only the owner of', async () => {
		fake.batch = (ips) =>
			batchOf(
				ips.map((ip) => ({
					ip,
					network: { asn: 64500, org: 'Example Net', asCountry: null },
					subdivisions: [],
					city: null
				}))
			);
		const anna = await person(bucketId);
		await signIn(anna.email);

		const { rows } = await lookupsOf(cookie, bucketId, anna.accountId, {
			kind: 'signIn'
		});
		expect(rows.map((row) => row.lookup)).toEqual([
			{
				asn: 64500,
				asName: 'Example Net',
				regionCode: null,
				region: null,
				city: null
			}
		]);
	});
});

/**
 * @proves A refusal at an app behind the proxy whose proxy proved the person's address carries the same owner and
 * location as a sign-in (specs/136 US1 scenario 3).
 */
describe('owner and location at an app behind the proxy', () => {
	let w: World;

	beforeAll(async () => {
		await bootstrap(import.meta.url);
		w = await world();
		from('203.0.113.9');
	});

	beforeEach(async () => {
		forgetLookupsForTests();
		fake = foxtrust();
		await seedFoxTrustKey();
	});

	it('shows them on a refusal whose address the proxy proved', async () => {
		const app = await createApp(w.cookie, w.acme.id, {
			rootGroups: [w.acme.staff],
			name: 'Wiki'
		});
		expectStatus(
			await admin('PATCH', behindProxyPath(w.acme.id, app.id), w.cookie, {
				rules: [
					{ path: '/', who: { kind: 'groups', groups: [w.acme.staff] } },
					{ path: '/admin', who: { kind: 'groups', groups: [w.acme.admins] } }
				]
			}),
			200,
			'setting the wiki rules'
		);
		const key = await issueProxyKey(w.cookie, w.acme.id);
		const headers = fromProxy(key.key, '198.51.100.20');
		const target = { slug: w.acme.slug, app };
		const signed = await signInThrough(target, w.acme.staffMember, { headers });
		await checkApp(target, { uri: '/admin', cookie: signed.cookie, headers });

		const { rows } = await lookupsOf(
			w.cookie,
			w.acme.id,
			w.acme.staffMember.accountId,
			{ kind: 'app', outcome: 'refused' }
		);
		expect(rows.map((row) => [row.address, row.lookup])).toEqual([
			['198.51.100.20', MUNICH]
		]);
	});
});
