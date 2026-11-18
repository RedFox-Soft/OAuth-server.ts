import {
	afterEach,
	beforeAll,
	beforeEach,
	describe,
	expect,
	it,
	spyOn,
	type Mock
} from 'bun:test';

import bootstrap from '../test_helper.ts';
import { adminCookie } from '../end_user_lifecycle/fixtures.ts';
import { admin } from '../provisioning/helpers.ts';
import {
	behindProxyPath,
	checkApp,
	createApp,
	expectStatus,
	signInThrough,
	world
} from '../behind_proxy/helpers.ts';
import {
	fromProxy,
	issueProxyKey
} from '../behind_proxy/conditions_helpers.ts';
import {
	PASSWORD,
	PersonBrowser,
	WRONG,
	from,
	person,
	project,
	signIn,
	typePassword
} from '../person_activity/helpers.ts';
import {
	KEY,
	batchOf,
	daysAfter,
	deliverReport,
	foxtrust,
	known,
	lookupsOf,
	registerAt,
	type FoxTrustFake
} from './helpers.ts';
import {
	configStore,
	errorStore,
	getPersonActivityStore,
	getSealingStore,
	getUserStore,
	instanceSigningKeyStore,
	resetStoresForTests
} from 'lib/adapters/index.ts';
import { ADMIN_BUCKET_ID } from 'lib/admin/consts.ts';
import { forgetLookupsForTests } from 'lib/address_lookup/lookups.ts';
import { ApplicationConfig } from 'lib/configs/application.ts';
import { flushPersonActivityNow } from 'lib/person_activity/flush.ts';
import { SEALED_PREFIX } from 'lib/sealing/seal.ts';

let fake: FoxTrustFake;
let cookie: string;
let bucketId: string;

beforeAll(async () => {
	await bootstrap(import.meta.url);
});

beforeEach(async () => {
	resetStoresForTests();
	forgetLookupsForTests();
	await configStore.set({});
	cookie = await adminCookie();
	bucketId = await project();
	fake = foxtrust();
	from('203.0.113.7');
});

afterEach(() => {
	ApplicationConfig['addressLookup.enabled'] = true;
});

/*
 * A server that went the whole way: a report with its instance key, a week later a registration answered with a key,
 * then a sign-in looked up. Every place a secret could leak has had its chance.
 */
async function wholeWay(logs: Mock<(...args: unknown[]) => void>[]) {
	fake.registration = {
		status: 201,
		body: { key: KEY, dailyQuota: 1000, burst: 5 }
	};
	await deliverReport('2026-12-01T12:00:00Z');
	await registerAt(daysAfter('2026-12-01T13:00:00Z', 7));
	await deliverReport('2026-12-09T12:00:00Z');
	const anna = await person(bucketId);
	await signIn(anna.email);
	await lookupsOf(cookie, bucketId, anna.accountId);

	const answers = await Promise.all(
		[
			'/admin/api/settings/address-lookup',
			'/admin/api/settings/telemetry',
			'/admin/api/keyring'
		].map(async (path) => {
			const reply = await admin('GET', path, cookie);
			expect(reply.status).toBe(200);
			return JSON.stringify(reply.body);
		})
	);
	return [
		...fake.requests.map(
			(sent) => `${JSON.stringify(sent.headers)} ${sent.body}`
		),
		...logs.flatMap((log) =>
			log.mock.calls.map((call) => JSON.stringify(call))
		),
		...answers,
		JSON.stringify((await errorStore.list()).groups)
	];
}

function spies(): Mock<(...args: unknown[]) => void>[] {
	return [
		spyOn(console, 'log'),
		spyOn(console, 'info'),
		spyOn(console, 'warn'),
		spyOn(console, 'error')
	];
}

/**
 * @proves SI-1: the private half of the instance key never leaves the server: not in a report, a request, a log line,
 * an administrator's or agent's answer or an error record.
 */
describe('the private half of the instance key', () => {
	it('appears in nothing the server sends, logs or answers', async () => {
		const texts = await wholeWay(spies());
		const stored = await instanceSigningKeyStore.read();
		if (!(stored instanceof Uint8Array)) throw new Error('no instance key');
		const der = Buffer.from(stored);
		const seed = der.subarray(der.length - 32);
		const forms = [der, seed].flatMap((bytes) => [
			bytes.toString('hex'),
			bytes.toString('base64'),
			bytes.toString('base64url')
		]);

		for (const text of texts) {
			for (const form of forms) expect(text.includes(form)).toBe(false);
		}
	});
});

/**
 * @proves SI-7: the FoxTrust key is sealed at rest and leaves the server only in the authorization header of a lookup.
 */
describe('the FoxTrust key', () => {
	it('is stored sealed', async () => {
		await wholeWay(spies());
		const [leaf] = await getSealingStore().scan('foxtrustKey');
		const raw =
			typeof leaf.value === 'string'
				? leaf.value
				: Buffer.from(leaf.value).toString('utf8');

		expect(raw.startsWith(SEALED_PREFIX)).toBe(true);
	});

	it('appears nowhere but the authorization header of a lookup', async () => {
		const texts = await wholeWay(spies());
		const elsewhere = texts.filter(
			(text) =>
				text.includes(KEY) && !text.includes(`"authorization":"Bearer ${KEY}"`)
		);
		const batches = fake.batches();

		expect(elsewhere).toEqual([]);
		expect(batches.length).toBeGreaterThan(0);
		for (const sent of batches) expect(sent.body.includes(KEY)).toBe(false);
	});
});

/**
 * @proves SI-2: only public addresses on the rows being written leave the server, an administrator's sign-in like a
 * person's (specs/137), never anything else about the person.
 */
describe('what is sent for a lookup', () => {
	beforeEach(async () => {
		const { seedFoxTrustKey } = await import('./helpers.ts');
		await seedFoxTrustKey();
	});

	it('is never a private address', async () => {
		from('10.0.0.5');
		await signIn((await person(bucketId)).email);
		from('203.0.113.7');
		await signIn((await person(bucketId)).email);
		await flushPersonActivityNow();

		expect(fake.ipsSent()).toEqual(['203.0.113.7']);
	});

	it('is never a private address a proxy proved', async () => {
		const w = await world();
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
			'setting the rules'
		);
		const key = await issueProxyKey(w.cookie, w.acme.id);
		const headers = fromProxy(key.key, '192.168.1.4');
		const target = { slug: w.acme.slug, app };
		from('203.0.113.9');
		const signed = await signInThrough(target, w.acme.staffMember, { headers });
		await checkApp(target, { uri: '/admin', cookie: signed.cookie, headers });
		await flushPersonActivityNow();

		expect(fake.ipsSent()).not.toContain('192.168.1.4');
	});

	it("is an administrator's sign-in address like a person's", async () => {
		const administrator = await getUserStore(ADMIN_BUCKET_ID).create(
			`admin-${Math.random().toString(36).slice(2)}@acme.test`,
			await Bun.password.hash(PASSWORD),
			true
		);
		from('203.0.113.50');
		await typePassword(
			new PersonBrowser(),
			administrator.email,
			PASSWORD,
			'admin-panel'
		);
		await flushPersonActivityNow();

		const { rows } = await getPersonActivityStore().listForPerson(
			ADMIN_BUCKET_ID,
			administrator._id,
			{ limit: 10, now: new Date() }
		);
		expect([fake.ipsSent(), rows.map((row) => row.lookup?.city)]).toEqual([
			['203.0.113.50'],
			['Munich']
		]);
	});

	it('carries nothing about the person', async () => {
		const anna = await person(bucketId);
		await signIn(anna.email);
		await flushPersonActivityNow();

		const [sent] = fake.batches();
		expect(JSON.parse(sent.body)).toEqual({ ips: ['203.0.113.7'] });
		for (const secret of [
			anna.email,
			anna.accountId,
			bucketId,
			'activity-app'
		]) {
			expect(sent.body.includes(secret)).toBe(false);
		}
	});

	it('is an IPv4 address in its IPv4 form when it reached the server as IPv4-mapped IPv6', async () => {
		from('::ffff:203.0.113.8');
		await signIn((await person(bucketId)).email);
		await flushPersonActivityNow();

		expect(fake.ipsSent()).toEqual(['203.0.113.8']);
	});
});

/**
 * @proves SI-3: a row keeps only the AS number and name, the region and the city from FoxTrust's answer, whatever else
 * the answer holds.
 */
describe('what a row keeps of an answer', () => {
	it('is only the owner and location', async () => {
		const { seedFoxTrustKey } = await import('./helpers.ts');
		await seedFoxTrustKey();
		fake.batch = (ips) =>
			batchOf(
				ips.map((ip) => ({
					...known(ip),
					risk: 97,
					level: 'high',
					reasons: ['tor'],
					categories: ['tor'],
					country: 'DE',
					subdivisions: [
						{ isoCode: 'BY', names: { en: 'Bavaria', de: 'Bayern' } },
						{ isoCode: 'XX', names: { en: 'Elsewhere' } }
					]
				}))
			);
		const anna = await person(bucketId);
		await signIn(anna.email);
		await flushPersonActivityNow();

		const { rows } = await getPersonActivityStore().listForPerson(
			bucketId,
			anna.accountId,
			{ limit: 10, now: new Date() }
		);
		const [row] = rows.filter((one) => one.lookup !== undefined);
		expect(row.lookup).toEqual({
			asn: 64500,
			asName: 'Example Net',
			regionCode: 'BY',
			region: 'Bavaria',
			city: 'Munich'
		});
		expect(row.facts?.categories ?? []).not.toContain('tor');
	});
});

/** @proves SI-4: no request a person makes waits on FoxTrust. */
describe('a sign-in while FoxTrust never answers', () => {
	it('completes before anything is sent to FoxTrust', async () => {
		const { seedFoxTrustKey } = await import('./helpers.ts');
		await seedFoxTrustKey();
		fake.batch = () => 'hang';
		const started = Date.now();
		await signIn((await person(bucketId)).email);

		expect(Date.now() - started).toBeLessThan(2000);
		expect(fake.batches()).toEqual([]);
	});
});

/** @proves An owner and location never sit beside an address they were not found for. */
describe('a row whose address changes', () => {
	it('drops the owner and location of the address it had', async () => {
		const { seedFoxTrustKey } = await import('./helpers.ts');
		await seedFoxTrustKey();
		// Failed sign-ins of one day are one row, which keeps the latest address.
		const anna = await person(bucketId);
		await typePassword(new PersonBrowser(), anna.email, WRONG);
		await flushPersonActivityNow();
		ApplicationConfig['addressLookup.enabled'] = false;
		from('198.51.100.4');
		await typePassword(new PersonBrowser(), anna.email, WRONG);
		await flushPersonActivityNow();

		const { rows } = await getPersonActivityStore().listForPerson(
			bucketId,
			anna.accountId,
			{ kind: 'signIn', limit: 10, now: new Date() }
		);
		expect(rows.map((row) => [row.address, row.lookup])).toEqual([
			['198.51.100.4', undefined]
		]);
	});
});
