import { describe, it, expect, beforeEach } from 'bun:test';

import { captureOrigin, resetOriginSalt } from 'lib/error_store/redact.ts';

/*
 * The three origin capture levels (FR-003a).
 *
 * The anonymized level has two halves that pull against each other, and a test of either alone would
 * pass while the feature was useless: the stored value must not be reversible to the address, and two
 * requests from one origin must still land on the same value. An implementation that stored nothing
 * satisfies the first; one that stored the address satisfies the second.
 */
const headersFor = (address: string) =>
	new Headers(address ? { 'x-forwarded-for': address } : {});

describe('origin capture levels', () => {
	beforeEach(() => {
		resetOriginSalt();
	});

	it('stores nothing and says so at the omitted level', async () => {
		const origin = await captureOrigin(headersFor('203.0.113.7'), 'omitted');

		/*
		 * The marker, not null. A reader must be able to tell "the operator chose not to look" from
		 * "there was nothing to see" without knowing what the configuration was when this was written.
		 */
		expect(origin).toBe('not-captured');
	});

	it('stores the address at the full level', async () => {
		expect(await captureOrigin(headersFor('203.0.113.7'), 'full')).toBe(
			'203.0.113.7'
		);
	});

	describe('anonymized', () => {
		it('does not store the address', async () => {
			const origin = await captureOrigin(
				headersFor('203.0.113.7'),
				'anonymized'
			);

			expect(origin).not.toBeNull();
			expect(origin).not.toContain('203.0.113');
			expect(origin).not.toContain('.');
		});

		// The half a privacy-only implementation would fail: correlation must survive anonymisation.
		it('gives one origin one value', async () => {
			const first = await captureOrigin(
				headersFor('203.0.113.7'),
				'anonymized'
			);
			const second = await captureOrigin(
				headersFor('203.0.113.7'),
				'anonymized'
			);

			expect(first).toBe(second);
		});

		it('gives different origins different values', async () => {
			const one = await captureOrigin(headersFor('203.0.113.7'), 'anonymized');
			const two = await captureOrigin(headersFor('198.51.100.4'), 'anonymized');

			expect(one).not.toBe(two);
		});

		/*
		 * Stable across the process forgetting its cached key, because the key is stored rather than
		 * generated per process: a restart that changed it would silently stop correlating, and every
		 * record written before it would read as a different origin.
		 */
		it('stays stable when the key is re-resolved', async () => {
			const before = await captureOrigin(
				headersFor('203.0.113.7'),
				'anonymized'
			);
			resetOriginSalt();
			const after = await captureOrigin(
				headersFor('203.0.113.7'),
				'anonymized'
			);

			expect(after).toBe(before);
		});
	});

	it('reads the first hop of a forwarded chain', async () => {
		const headers = new Headers({
			'x-forwarded-for': '203.0.113.7, 70.41.3.18, 150.172.238.178'
		});
		expect(await captureOrigin(headers, 'full')).toBe('203.0.113.7');
	});

	it('falls back to x-real-ip', async () => {
		const headers = new Headers({ 'x-real-ip': '203.0.113.9' });
		expect(await captureOrigin(headers, 'full')).toBe('203.0.113.9');
	});

	// No header at all is genuinely unknown, which is not the same as not-captured.
	it('reports null when there is nothing to capture', async () => {
		expect(await captureOrigin(headersFor(''), 'anonymized')).toBeNull();
		expect(await captureOrigin(headersFor(''), 'full')).toBeNull();
	});
});
