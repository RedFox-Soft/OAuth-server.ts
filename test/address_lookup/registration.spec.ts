import {
	afterEach,
	beforeAll,
	beforeEach,
	describe,
	expect,
	it,
	spyOn
} from 'bun:test';
import crypto from 'node:crypto';

import bootstrap from '../test_helper.ts';
import {
	KEY,
	daysAfter,
	deliverReport,
	foxtrust,
	registerAt,
	type FoxTrustFake
} from './helpers.ts';
import {
	errorStore,
	getTelemetryStateStore,
	resetStoresForTests
} from 'lib/adapters/index.ts';
import { heldKey } from 'lib/address_lookup/foxtrust_key.ts';
import { registrationPass } from 'lib/address_lookup/register.ts';
import { ApplicationConfig } from 'lib/configs/application.ts';

/* The first usage report carrying the instance key is delivered at noon on this day. */
const FIRST_REPORT = '2026-12-01T12:00:00Z';
/* A week later, past the instance's report slot. */
const WEEK_LATER = '2026-12-08T13:00:00Z';

let fake: FoxTrustFake;

beforeAll(async () => {
	await bootstrap(import.meta.url);
});

/* Each case is a server freshly upgraded: no key, no registration, one first report delivered. */
beforeEach(async () => {
	resetStoresForTests();
	fake = foxtrust();
	await deliverReport(FIRST_REPORT);
});

afterEach(() => {
	ApplicationConfig['telemetry.enabled'] = true;
	ApplicationConfig['addressLookup.enabled'] = true;
});

/* One registration pass a day from `from`, for `days` days, at 13:00 UTC. */
async function registerDaily(from: string, days: number): Promise<void> {
	for (let day = 0; day < days; day += 1) {
		await registerAt(daysAfter(from, day));
	}
}

/**
 * @proves A server gets a FoxTrust key by itself, a week after its usage reports start carrying its instance key, and
 * handles every answer FoxTrust's contract names, quietly (specs/136 US2, FR-003, FR-004).
 */
describe('registration before standing could exist', () => {
	it('sends no registration in the six days after the first report with the key', async () => {
		await registerDaily('2026-12-02T13:00:00Z', 6);

		expect(fake.registrations()).toHaveLength(0);
	});

	it('sends one signed registration a week after the first report with the key', async () => {
		await registerAt(WEEK_LATER);

		const [sent] = fake.registrations();
		const body = JSON.parse(sent.body) as Record<string, string>;
		expect(Object.keys(body).sort()).toEqual(
			[
				'format',
				'instanceId',
				'instanceKey',
				'issuedAt',
				'nonce',
				'signature'
			].sort()
		);
		const signed = Buffer.from(
			[
				'foxtrust-instance-key-v1',
				body.instanceId,
				body.instanceKey,
				body.issuedAt,
				body.nonce
			].join('\n'),
			'utf8'
		);
		const publicKey = crypto.createPublicKey({
			key: { kty: 'OKP', crv: 'Ed25519', x: body.instanceKey },
			format: 'jwk'
		});
		expect(
			crypto.verify(
				null,
				signed,
				publicKey,
				Buffer.from(body.signature, 'base64url')
			)
		).toBe(true);
		expect(body.nonce).toMatch(/^[A-Za-z0-9_-]{22}$/);
		expect(body.issuedAt).toBe('2026-12-08T13:00:00.000Z');
	});
});

describe('a key FoxTrust issues', () => {
	beforeEach(() => {
		fake.registration = {
			status: 201,
			body: { key: KEY, dailyQuota: 1000, burst: 5 }
		};
	});

	it('is kept for lookups', async () => {
		await registerAt(WEEK_LATER);

		const state = await getTelemetryStateStore().read();
		expect(await heldKey(state)).toBe(KEY);
		expect(state?.lookupKey?.dailyQuota).toBe(1000);
	});

	it('ends the requests for a key', async () => {
		await registerDaily(WEEK_LATER, 3);

		expect(fake.registrations()).toHaveLength(1);
	});
});

describe('after FoxTrust answers not yet', () => {
	it('waits the days FoxTrust names', async () => {
		fake.registration = {
			status: 403,
			body: { error: 'not_yet', retryAfterDays: 4 }
		};
		await registerDaily(WEEK_LATER, 4);
		expect(fake.registrations()).toHaveLength(1);

		await registerAt(daysAfter(WEEK_LATER, 4));
		expect(fake.registrations()).toHaveLength(2);
	});

	it('waits at least one day when FoxTrust names none', async () => {
		fake.registration = {
			status: 403,
			body: { error: 'not_yet', retryAfterDays: 0 }
		};
		await registerAt(WEEK_LATER);
		await registerAt(daysAfter(WEEK_LATER, 0.25));
		expect(fake.registrations()).toHaveLength(1);

		await registerAt(daysAfter(WEEK_LATER, 1));
		expect(fake.registrations()).toHaveLength(2);
	});
});

for (const [answer, status] of [
	['muted', 403],
	['key_mismatch', 409]
] as const) {
	describe(`after FoxTrust answers ${answer}`, () => {
		beforeEach(async () => {
			fake.registration = { status, body: { error: answer } };
			await registerAt(WEEK_LATER);
		});

		it('sends nothing for six days', async () => {
			await registerDaily(daysAfter(WEEK_LATER, 1), 6);

			expect(fake.registrations()).toHaveLength(1);
		});

		it('asks again a week later', async () => {
			await registerAt(daysAfter(WEEK_LATER, 7));

			expect(fake.registrations()).toHaveLength(2);
		});
	});
}

describe('after a registration that failed', () => {
	it('tries an invalid request again the next day', async () => {
		fake.registration = {
			status: 400,
			body: { error: 'invalid', field: 'issuedAt' }
		};
		await registerAt(WEEK_LATER);
		await registerAt(daysAfter(WEEK_LATER, 1));

		expect(fake.registrations()).toHaveLength(2);
	});

	it('tries a busy FoxTrust again after its Retry-After', async () => {
		fake.registration = {
			status: 503,
			body: { error: 'unavailable' },
			headers: { 'retry-after': '172800' }
		};
		await registerAt(WEEK_LATER);
		await registerAt(daysAfter(WEEK_LATER, 1));
		expect(fake.registrations()).toHaveLength(1);

		await registerAt(daysAfter(WEEK_LATER, 2));
		expect(fake.registrations()).toHaveLength(2);
	});

	it('tries an unreachable FoxTrust again the next day', async () => {
		fake.registration = 'unreachable';
		await registerAt(WEEK_LATER);
		await registerAt(daysAfter(WEEK_LATER, 1));

		expect(fake.registrations()).toHaveLength(2);
	});

	it('leaves no log line and no error record', async () => {
		const logged = [
			spyOn(console, 'error'),
			spyOn(console, 'warn'),
			spyOn(console, 'log')
		];
		fake.registration = 'unreachable';
		await registerAt(WEEK_LATER);

		for (const spy of logged) expect(spy).not.toHaveBeenCalled();
		expect((await errorStore.list()).groups).toHaveLength(0);
	});
});

describe('registration limits', () => {
	it('sends nothing while usage reporting is off, as no key can come', async () => {
		ApplicationConfig['telemetry.enabled'] = false;
		await registerAt(WEEK_LATER);

		expect(fake.registrations()).toHaveLength(0);
	});

	it('sends at most one registration a UTC day across processes', async () => {
		// Straight to the pass: overlapping clock changes would not unwind to where they started.
		await Promise.all(
			['13:00', '14:00', '20:00'].map((time) =>
				registrationPass(new Date(`2026-12-08T${time}:00Z`), {
					ignoreSlot: true
				})
			)
		);

		expect(fake.registrations()).toHaveLength(1);
	});
});
