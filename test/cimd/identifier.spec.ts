import { describe, it, expect } from 'bun:test';

import { parseClientIdentifierUrl } from 'lib/client_metadata_document/identifier.ts';

/*
 * The form rules from `draft-ietf-oauth-client-id-metadata-document-00` §3, every one of them a MUST.
 *
 * These run before any network call, and that ordering is the point rather than an optimisation: a
 * malformed identifier that reached the fetch layer would be an attacker's free probe of whatever the
 * authorization server can reach. Refusing on shape alone costs nothing and closes that.
 */

/**
 * @proves Only an https URL with a path is a document identifier, traversal and credentials and
 * fragments are refused on the raw input, and an ordinary client id falls through untouched.
 */
describe('a client identifier that is a URL', () => {
	it('accepts an https URL carrying a path component', () => {
		const result = parseClientIdentifierUrl(
			'https://app.example.com/oauth/client-metadata.json'
		);

		expect(result.ok).toBe(true);
		if (result.ok) {
			expect(result.url.href).toBe(
				'https://app.example.com/oauth/client-metadata.json'
			);
		}
	});

	it('accepts a port and a query string', () => {
		expect(
			parseClientIdentifierUrl('https://app.example.com:8443/c.json?v=2').ok
		).toBe(true);
	});

	/*
	 * Not an error — simply not a URL identifier. Everything that is not one has to fall through to the
	 * ordinary client lookup, or every existing client id would start being refused.
	 */
	it('declines a plain client id without calling it malformed', () => {
		for (const id of [
			'admin-panel',
			'client',
			'urn:example:client',
			/* Not an attempt at a document identifier either — only http(s) is a candidate. */
			'ftp://app.example.com/c.json',
			''
		]) {
			const result = parseClientIdentifierUrl(id);
			expect(result.ok).toBe(false);
			if (!result.ok) expect(result.reason).toBe('not_a_url');
		}
	});

	/*
	 * `http` is refused rather than declined: it *is* an attempt at a document identifier, and the
	 * draft forbids the scheme outright. Distinguishing the two is what lets an ordinary client id fall
	 * through to the normal lookup while a plaintext document URL is named as the mistake it is.
	 */
	it('refuses an http document identifier', () => {
		const result = parseClientIdentifierUrl('http://app.example.com/c.json');
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.reason).toBe('not_https');
	});

	/*
	 * A bare origin is refused because URL parsing gives it the path `/`, which the draft does not
	 * accept as a path component — and because a client id that is just a hostname would let anyone
	 * controlling a domain speak for every application on it.
	 */
	it('refuses a URL with no path component', () => {
		for (const id of ['https://app.example.com', 'https://app.example.com/']) {
			const result = parseClientIdentifierUrl(id);
			expect(result.ok).toBe(false);
			if (!result.ok) expect(result.reason).toBe('no_path');
		}
	});

	it('refuses dot and double-dot path segments', () => {
		for (const id of [
			'https://app.example.com/./c.json',
			'https://app.example.com/a/../c.json',
			'https://app.example.com/a/..',
			'https://app.example.com/.'
		]) {
			const result = parseClientIdentifierUrl(id);
			expect(result.ok).toBe(false);
			if (!result.ok) expect(result.reason).toBe('dot_segment');
		}
	});

	it('refuses a fragment', () => {
		const result = parseClientIdentifierUrl('https://app.example.com/c.json#x');
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.reason).toBe('fragment');
	});

	it('refuses embedded credentials', () => {
		for (const id of [
			'https://user@app.example.com/c.json',
			'https://user:pass@app.example.com/c.json'
		]) {
			const result = parseClientIdentifierUrl(id);
			expect(result.ok).toBe(false);
			if (!result.ok) expect(result.reason).toBe('credentials');
		}
	});

	/*
	 * URL parsing normalises `%2e` to `.` only sometimes, so the dot-segment rule is applied to the
	 * parsed pathname rather than to the raw input — otherwise an encoded traversal would slip past a
	 * check that looked only at what the caller typed.
	 */
	it('refuses a percent-encoded dot segment', () => {
		const result = parseClientIdentifierUrl(
			'https://app.example.com/a/%2e%2e/c.json'
		);
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.reason).toBe('dot_segment');
	});
});
