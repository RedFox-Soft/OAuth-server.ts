import { describe, it, expect } from 'bun:test';

import {
	InvalidOriginError,
	canonicalOrigin,
	isOriginAllowed,
	isValidOrigin,
	normalizeOrigins,
	originRejectionMessage
} from 'lib/helpers/cors_origin.js';

/*
 * The shared origin rule. Contract: specs/011-cors-support/contracts/admin-projects-api.md.
 *
 * Unit-level rather than HTTP-level by exception: the same helper backs the admin schema and the
 * per-request comparison, so pinning it once here keeps the route specs to what they are actually
 * about. The admin routes still get their own integration coverage.
 */
describe('CORS origin validation', () => {
	it('accepts a bare http(s) origin', () => {
		expect(isValidOrigin('https://app.example.com')).toBe(true);
		expect(isValidOrigin('http://localhost:3000')).toBe(true);
		expect(isValidOrigin('https://app.example.com:8443')).toBe(true);
	});

	it('accepts a mixed-case host and canonicalizes it to lower case', () => {
		expect(isValidOrigin('https://APP.Example.COM')).toBe(true);
		expect(normalizeOrigins(['https://APP.Example.COM'])).toEqual([
			'https://app.example.com'
		]);
	});

	it.each([
		['trailing slash', 'https://app.example.com/'],
		['a path', 'https://app.example.com/callback'],
		['a query', 'https://app.example.com?a=1'],
		['a fragment', 'https://app.example.com#x'],
		['embedded credentials', 'https://user:pass@app.example.com'],
		['a written default port', 'https://app.example.com:443'],
		['a written default http port', 'http://app.example.com:80'],
		['a non-web scheme', 'ftp://app.example.com'],
		['a file scheme', 'file:///etc/passwd'],
		['the any-origin wildcard', '*'],
		['a wildcard subdomain', 'https://*.example.com'],
		['the null origin', 'null'],
		['a bare hostname', 'app.example.com'],
		['the empty string', '']
	])('rejects %s', (_label, value) => {
		expect(isValidOrigin(value)).toBe(false);
	});

	it('names the canonical form when the value is merely non-canonical', () => {
		expect(originRejectionMessage('https://app.example.com/')).toBe(
			'invalid origin "https://app.example.com/": expected "https://app.example.com"'
		);
		expect(originRejectionMessage('https://app.example.com:443')).toBe(
			'invalid origin "https://app.example.com:443": expected "https://app.example.com"'
		);
	});

	it('explains what was expected when the value is not an origin at all', () => {
		expect(originRejectionMessage('app.example.com')).toContain(
			'expected a bare http(s) origin'
		);
		expect(originRejectionMessage('*')).toContain(
			'expected a bare http(s) origin'
		);
	});

	it('collapses duplicates while preserving order', () => {
		expect(
			normalizeOrigins([
				'https://b.example.com',
				'https://a.example.com',
				'https://B.example.com'
			])
		).toEqual(['https://b.example.com', 'https://a.example.com']);
	});

	it('throws on the first invalid entry so a list is never half-applied', () => {
		expect(() =>
			normalizeOrigins(['https://a.example.com', 'https://b.example.com/'])
		).toThrow(InvalidOriginError);
	});

	it('canonicalizes without asserting canonical input', () => {
		expect(canonicalOrigin('https://app.example.com/cb')).toBe(
			'https://app.example.com'
		);
		expect(canonicalOrigin('not a url')).toBeUndefined();
	});

	describe('request-time matching', () => {
		const allowed = ['https://app.example.com'];

		it('matches exactly', () => {
			expect(isOriginAllowed('https://app.example.com', allowed)).toBe(true);
			expect(isOriginAllowed('https://APP.example.com', allowed)).toBe(true);
		});

		it('never matches a subdomain, a parent, or a different scheme or port', () => {
			expect(isOriginAllowed('https://evil.app.example.com', allowed)).toBe(
				false
			);
			expect(isOriginAllowed('https://example.com', allowed)).toBe(false);
			expect(isOriginAllowed('http://app.example.com', allowed)).toBe(false);
			expect(isOriginAllowed('https://app.example.com:8443', allowed)).toBe(
				false
			);
		});

		it('grants nothing for an empty or absent list', () => {
			expect(isOriginAllowed('https://app.example.com', [])).toBe(false);
			expect(isOriginAllowed('https://app.example.com', undefined)).toBe(false);
		});
	});
});
