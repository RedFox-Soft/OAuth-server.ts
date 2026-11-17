import {
	afterEach,
	beforeAll,
	beforeEach,
	describe,
	expect,
	it
} from 'bun:test';

import bootstrap from '../test_helper.ts';
import { OTHER_KEYRING, TEST_KEYRING } from '../sealing/fixtures.ts';
import {
	daysAfter,
	deliverReport,
	foxtrust,
	registerAt,
	type FoxTrustFake
} from './helpers.ts';
import {
	getTelemetryStateStore,
	resetStoresForTests
} from 'lib/adapters/index.ts';
import { instancePublicKey } from 'lib/address_lookup/instance_key.ts';
import { resetKeyringForTests } from 'lib/sealing/keyring.ts';

const FIRST_REPORT = '2026-12-01T12:00:00Z';
const WEEK_LATER = '2026-12-08T13:00:00Z';

let fake: FoxTrustFake;

beforeAll(async () => {
	await bootstrap(import.meta.url);
});

beforeEach(() => {
	resetKeyringForTests(TEST_KEYRING);
	resetStoresForTests();
	fake = foxtrust();
});

afterEach(() => {
	resetKeyringForTests(TEST_KEYRING);
});

/**
 * @proves SI-6: an instance has one key pair for life. It is created once, also when processes race on its first use,
 * and never replaced, also when it cannot be read: FoxTrust binds the instance to its first pair for good.
 */
describe('the instance key pair', () => {
	it('is one pair when processes race on its first use', async () => {
		const keys = await Promise.all(
			Array.from({ length: 5 }, () => instancePublicKey())
		);

		expect(new Set(keys).size).toBe(1);
		expect(keys[0]).toMatch(/^[A-Za-z0-9_-]{43}$/);
	});

	describe('while the keyring that sealed it is not loaded', () => {
		let original: string | null;

		beforeEach(async () => {
			await deliverReport(FIRST_REPORT);
			original = await instancePublicKey();
			resetKeyringForTests(OTHER_KEYRING);
		});

		it('is left out of the usage report', async () => {
			await deliverReport(daysAfter(FIRST_REPORT, 1));

			const last = fake.reports().at(-1);
			expect(JSON.parse(last?.body ?? '{}')).not.toHaveProperty('instanceKey');
		});

		it('sends no registration', async () => {
			await registerAt(WEEK_LATER);

			expect(fake.registrations()).toHaveLength(0);
		});

		it('is the same pair once that keyring is loaded again', async () => {
			await instancePublicKey();
			await registerAt(WEEK_LATER);
			resetKeyringForTests(TEST_KEYRING);

			expect(await instancePublicKey()).toBe(original);
		});
	});
});

/**
 * @proves SI-5: a registration is never a replay. Its signing time is later than the last one sent, and its nonce is
 * new.
 */
describe('a registration', () => {
	beforeEach(async () => {
		await deliverReport(FIRST_REPORT);
		fake.registration = 'unreachable';
	});

	it('is not sent when the clock was set back before the last one', async () => {
		await registerAt(daysAfter(WEEK_LATER, 2));
		// As if FoxTrust had allowed an immediate retry: only the signing time stands in the way.
		await getTelemetryStateStore().updateRegistration({}, ['notBefore']);
		await registerAt(daysAfter(WEEK_LATER, 1));

		expect(fake.registrations()).toHaveLength(1);
	});

	it('carries a nonce no earlier registration carried', async () => {
		await registerAt(WEEK_LATER);
		await registerAt(daysAfter(WEEK_LATER, 1));

		const nonces = fake
			.registrations()
			.map((sent) => (JSON.parse(sent.body) as { nonce: string }).nonce);
		expect(nonces).toHaveLength(2);
		expect(new Set(nonces).size).toBe(2);
	});
});
