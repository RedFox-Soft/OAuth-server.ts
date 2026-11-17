import { beforeAll, describe, expect, it } from 'bun:test';
import crypto from 'node:crypto';

import bootstrap from '../test_helper.ts';
import { deliverReport, foxtrust } from './helpers.ts';

function instanceKeyOf(body: string): unknown {
	return (JSON.parse(body) as { instanceKey?: unknown }).instanceKey;
}

/**
 * @proves The daily usage report carries this server's public instance key, the same every day, so FoxTrust can count
 * the server's standing toward a key (specs/136 US2, FR-002).
 */
describe('the instance key in the usage report', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	it('is the same on every day the server reports', async () => {
		const fake = foxtrust();
		await deliverReport('2026-12-01T12:00:00Z');
		await deliverReport('2026-12-02T12:00:00Z');

		const [first, second] = fake
			.reports()
			.map((sent) => instanceKeyOf(sent.body));
		expect(first).toMatch(/^[A-Za-z0-9_-]{43}$/);
		expect(second).toBe(first);
	});

	it('is an Ed25519 public key', async () => {
		const fake = foxtrust();
		await deliverReport('2026-12-03T12:00:00Z');

		const x = String(instanceKeyOf(fake.reports()[0].body));
		const key = crypto.createPublicKey({
			key: { kty: 'OKP', crv: 'Ed25519', x },
			format: 'jwk'
		});
		expect(key.asymmetricKeyType).toBe('ed25519');
	});
});
