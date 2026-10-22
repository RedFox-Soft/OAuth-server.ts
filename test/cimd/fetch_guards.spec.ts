import { describe, it, expect, afterEach, spyOn } from 'bun:test';

import {
	fetchClientDocument,
	MAX_DOCUMENT_BYTES,
	resolver
} from 'lib/client_metadata_document/fetch.ts';
import { mock, assertNoPendingInterceptors } from '../fetch_mock.js';

/*
 * The SSRF boundary.
 *
 * The governing draft says this outright: an authorization server supporting client description
 * documents "takes a URL as input from an unknown client and fetches that URL", and a malicious client
 * can use that to reach "private administration endpoints the authorization server has access to". The
 * MCP security best practices repeat it with a named list of ranges. So the mitigations below are
 * requirements, not hardening, and each case here is one of them.
 *
 * Address checks are exercised through the injected resolver rather than by real DNS: what is being
 * tested is what this server does with an answer, and a spec that depended on how the network
 * resolves `localhost` today would be testing the network.
 */

const OK = { identifier: 'https://app.example.com/c.json' };

function resolveTo(address: string) {
	return spyOn(resolver, 'lookup').mockResolvedValue([address]);
}

afterEach(() => {
	mock.restore();
	resolver.lookup = resolver.realLookup;
});

/**
 * @proves The outbound fetch for a client document cannot be pointed at an internal address,
 * redirected, or used to read an unbounded body.
 */
describe('refusing a destination this server should not reach', () => {
	it('refuses every private and reserved range, by name', async () => {
		/* The list the MCP security best practices names, plus the loopback forms. */
		for (const address of [
			'10.0.0.1',
			'172.16.0.1',
			'192.168.1.1',
			'127.0.0.1',
			'169.254.169.254',
			'::1',
			'fc00::1',
			'fe80::1',
			'0.0.0.0'
		]) {
			resolveTo(address);
			const result = await fetchClientDocument(OK.identifier);

			expect(result.ok, address).toBe(false);
			if (!result.ok) expect(result.reason, address).toBe('blocked_address');
		}
	});

	it('does not issue the request at all when the address is refused', async () => {
		resolveTo('169.254.169.254');
		/*
		 * No interceptor is registered. If the implementation reached the network the mock would throw
		 * for want of one, so a clean `blocked_address` is proof the request was never made — which is
		 * the property that matters: a refusal after the fact still hits the internal service.
		 */
		const result = await fetchClientDocument(OK.identifier);

		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.reason).toBe('blocked_address');
	});

	it('allows an ordinary public address', async () => {
		resolveTo('93.184.216.34');
		mock('https://app.example.com')
			.intercept({ path: '/c.json' })
			.reply(200, '{"client_id":"x"}', {
				headers: { 'content-type': 'application/json' }
			});

		const result = await fetchClientDocument(OK.identifier);

		expect(result.ok).toBe(true);
		assertNoPendingInterceptors();
	});
});

/*
 * Draft -02 §5: "The authorization server MUST NOT automatically follow HTTP redirects." A document lives at its
 * identifier or nowhere, so the destination is never asked for — the interceptor registered there is left
 * waiting, which is the proof.
 */
describe('answering with a redirect', () => {
	it.each([301, 302, 307, 308])(
		'refuses a document host that answers %d, and never requests the destination',
		async (status) => {
			resolveTo('93.184.216.34');
			mock('https://app.example.com')
				.intercept({ path: '/c.json' })
				.reply(status, '', {
					headers: { location: 'https://app.example.com/moved.json' }
				});
			mock('https://app.example.com')
				.intercept({ path: '/moved.json' })
				.reply(200, '{}', { headers: { 'content-type': 'application/json' } });

			const result = await fetchClientDocument(OK.identifier);

			expect(result).toEqual({ ok: false, reason: 'status' });
			expect(() => assertNoPendingInterceptors()).toThrow(
				'https://app.example.com/moved.json'
			);
		}
	);
});

describe('bounding what is accepted', () => {
	it('refuses a body over the size the draft recommends', async () => {
		resolveTo('93.184.216.34');
		mock('https://app.example.com')
			.intercept({ path: '/c.json' })
			.reply(200, 'x'.repeat(MAX_DOCUMENT_BYTES + 1), {
				headers: { 'content-type': 'application/json' }
			});

		const result = await fetchClientDocument(OK.identifier);

		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.reason).toBe('too_large');
	});

	it('refuses a declared content length over the bound without reading the body', async () => {
		resolveTo('93.184.216.34');
		mock('https://app.example.com')
			.intercept({ path: '/c.json' })
			.reply(200, '{}', {
				headers: {
					'content-type': 'application/json',
					'content-length': String(MAX_DOCUMENT_BYTES + 1)
				}
			});

		const result = await fetchClientDocument(OK.identifier);

		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.reason).toBe('too_large');
	});

	it('refuses a non-success status', async () => {
		resolveTo('93.184.216.34');
		mock('https://app.example.com')
			.intercept({ path: '/c.json' })
			.reply(404, 'nope');

		const result = await fetchClientDocument(OK.identifier);

		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.reason).toBe('status');
	});

	/* Draft -02 §5: the document "MUST be served with a 200 OK", and every other status is an error. */
	it('refuses a success status other than 200', async () => {
		resolveTo('93.184.216.34');
		mock('https://app.example.com')
			.intercept({ path: '/c.json' })
			.reply(203, '{}', { headers: { 'content-type': 'application/json' } });

		const result = await fetchClientDocument(OK.identifier);

		expect(result).toEqual({ ok: false, reason: 'status' });
	});

	it('reports a transport failure as unreachable rather than throwing', async () => {
		resolveTo('93.184.216.34');
		/* A mocked origin with no matching interceptor throws, which is what a dead host looks like. */
		mock('https://app.example.com');

		const result = await fetchClientDocument(OK.identifier);

		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.reason).toBe('unreachable');
	});

	it('refuses an identifier whose host cannot be resolved', async () => {
		spyOn(resolver, 'lookup').mockResolvedValue([]);

		const result = await fetchClientDocument(OK.identifier);

		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.reason).toBe('unresolvable');
	});
});
