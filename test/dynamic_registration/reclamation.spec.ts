import {
	describe,
	beforeAll,
	afterEach,
	it,
	expect,
	setSystemTime
} from 'bun:test';

import bootstrap, { agent } from '../test_helper.js';
import { adapter } from 'lib/adapters/index.ts';
import { UNUSED_REGISTRATION_TTL_SECONDS } from 'lib/models/client/dynamic_registration.ts';

/*
 * Bounding what dynamic registration can accumulate.
 *
 * The rule is proved as behaviour with time travel against the in-memory adapter. ⚠ What that cannot
 * prove is the datastore side — that the index declared for this sweep exists and is used — because no
 * in-memory double has an index. That gap is recorded in the feature's quickstart rather than papered
 * over; it needs the storage-fidelity suite the constitution allows, which this repository does not
 * have yet.
 */

const json = { 'content-type': 'application/json' };
const HOUR = 60 * 60;

async function register() {
	const res = await agent.reg.post(
		{ redirect_uris: ['https://client.example.com/cb'] },
		{ headers: json }
	);
	expect(res.status).toBe(201);
	return res.data?.client_id as string;
}

function exists(clientId: string) {
	return adapter('Client')
		.find(clientId)
		.then((found) => Boolean(found));
}

/**
 * @proves An abandoned self-registration is reclaimed after its window, and one that ever
 * completed an authorization - or that an operator created - never is.
 */
describe('reclaiming registrations nobody took up', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'dynamic_registration' });
	});

	afterEach(() => {
		setSystemTime();
	});

	it('removes one that never completed an authorization, once the window passes', async () => {
		const abandoned = await register();
		expect(await exists(abandoned)).toBe(true);

		setSystemTime(
			new Date(Date.now() + (UNUSED_REGISTRATION_TTL_SECONDS + HOUR) * 1000)
		);
		/* The sweep runs opportunistically at registration time, so a later registration triggers it. */
		await register();

		expect(await exists(abandoned)).toBe(false);
	});

	it('leaves one alone while it is still inside the window', async () => {
		const recent = await register();

		setSystemTime(new Date(Date.now() + HOUR * 1000));
		await register();

		expect(await exists(recent)).toBe(true);
	});

	/*
	 * The distinction the whole mechanism turns on. A registration that completed an authorization is
	 * a client somebody is using, and age says nothing about it.
	 */
	it('never removes one that completed an authorization, however old', async () => {
		const used = await register();
		const stored = (await adapter('Client').find(used)) as Record<
			string,
			unknown
		>;
		await adapter('Client').upsert(used, {
			...stored,
			registrationUsedAt: Math.floor(Date.now() / 1000)
		});

		setSystemTime(
			new Date(Date.now() + (UNUSED_REGISTRATION_TTL_SECONDS + HOUR) * 1000)
		);
		await register();

		expect(await exists(used)).toBe(true);
	});

	/*
	 * An administrator-created client carries no marker at all, so it is outside the sweep by
	 * construction rather than by an age check. Asserted because getting this wrong deletes real
	 * clients, and the sweep would not distinguish them from abandoned ones if the marker were absent.
	 */
	it('never touches a client an administrator created', async () => {
		expect(await exists('client')).toBe(true);

		setSystemTime(
			new Date(Date.now() + (UNUSED_REGISTRATION_TTL_SECONDS + HOUR) * 1000)
		);
		await register();

		expect(await exists('client')).toBe(true);
	});

	it('marks a registration used when its authorization code is redeemed', async () => {
		/*
		 * Asserted through the model rather than through a full code exchange: the exchange is covered
		 * by the authorization-code suite, and what matters here is that the marker survives the round
		 * trip through storage so the sweep can read it.
		 */
		const clientId = await register();
		const { markRegistrationUsed } =
			await import('lib/models/client/dynamic_registration.ts');

		await markRegistrationUsed({ clientId, registeredDynamically: true });

		const stored = (await adapter('Client').find(clientId)) as {
			registrationUsedAt?: number;
		};
		expect(typeof stored.registrationUsedAt).toBe('number');
	});
});
