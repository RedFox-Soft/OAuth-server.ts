import { describe, it, expect } from 'bun:test';

import { validateClientDocument } from 'lib/client_metadata_document/validate.ts';
import { documentFor } from './document_host.js';

/*
 * What has to be true of a retrieved document before it may speak for a client.
 *
 * Four of these are `MUST`s in the governing draft and the MCP client-registration page: valid JSON,
 * the required properties present, the declared `client_id` exactly equal to the URL it came from, and
 * no symmetric-secret authentication method. The identifier-equality rule is the load-bearing one —
 * without it, anybody could host a document claiming to be somebody else's client.
 */

const IDENTIFIER = 'https://app.example.com/oauth/client-metadata.json';

function validate(body: unknown, identifier = IDENTIFIER) {
	return validateClientDocument(
		typeof body === 'string' ? body : JSON.stringify(body),
		identifier
	);
}

describe('validating a client description document', () => {
	it('accepts a well-formed document and hands back canonical metadata', () => {
		const result = validate(documentFor(IDENTIFIER));

		expect(result.ok).toBe(true);
		if (result.ok) {
			/*
			 * Two conventions, and the split is the model's rather than this module's. The base
			 * registration attributes are translated to canonical names here, because they are not in
			 * RECOGNIZED_METADATA and the schema engine will not read them from snake input. Everything
			 * that *is* recognised metadata — `client_name`, `logo_uri`, `client_uri` — stays snake_case
			 * on purpose: the schema engine reads and camelCases it, and translating it early would hide
			 * it from the engine entirely.
			 */
			expect(result.metadata.clientId).toBe(IDENTIFIER);
			expect(result.metadata.redirectUris).toEqual([
				'https://app.example.com/callback'
			]);
			expect(result.metadata.client_name).toBe('Example MCP Client');
			expect(result.metadata.client_id).toBeUndefined();
		}
	});

	it('refuses a body that is not JSON', () => {
		for (const body of ['', 'not json', '<html></html>']) {
			const result = validate(body);
			expect(result.ok).toBe(false);
			if (!result.ok) expect(result.reason).toBe('not_json');
		}
	});

	it('refuses JSON that is not an object', () => {
		for (const body of ['[]', '"x"', '3', 'null']) {
			const result = validate(body);
			expect(result.ok).toBe(false);
			if (!result.ok) expect(result.reason).toBe('not_an_object');
		}
	});

	it('refuses a document missing a required property', () => {
		for (const missing of ['client_id', 'client_name', 'redirect_uris']) {
			const document = Object.fromEntries(
				Object.entries(documentFor(IDENTIFIER)).filter(
					([key]) => key !== missing
				)
			);

			const result = validate(document);
			expect(result.ok, missing).toBe(false);
			if (!result.ok) {
				expect(result.reason, missing).toBe('missing_property');
				expect(result.detail, missing).toBe(missing);
			}
		}
	});

	/*
	 * The rule that makes a document identifier trustworthy at all. Without it, hosting a document that
	 * names somebody else's identifier would let an attacker present a well-known client's name and
	 * their own redirect target.
	 */
	it('refuses a document whose client_id is not the URL it came from', () => {
		const result = validate(
			documentFor('https://evil.example.com/c.json'),
			IDENTIFIER
		);

		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.reason).toBe('identifier_mismatch');
	});

	it('requires exact equality, not a near match', () => {
		for (const claimed of [
			`${IDENTIFIER}/`,
			IDENTIFIER.replace('https', 'HTTPS'),
			IDENTIFIER.replace('app.example.com', 'APP.EXAMPLE.COM'),
			`${IDENTIFIER}?v=2`
		]) {
			const result = validate(documentFor(claimed), IDENTIFIER);
			expect(result.ok, claimed).toBe(false);
			if (!result.ok)
				expect(result.reason, claimed).toBe('identifier_mismatch');
		}
	});

	it('refuses an empty or malformed redirect list', () => {
		for (const redirect_uris of [[], 'https://x/cb', [1], ['']]) {
			const result = validate(documentFor(IDENTIFIER, { redirect_uris }));
			expect(result.ok).toBe(false);
			if (!result.ok) expect(result.reason).toBe('bad_redirect_uris');
		}
	});

	/*
	 * §4.1, a MUST NOT. A client identified by a self-hosted document has no way to have been issued a
	 * shared secret, so a document claiming one is either confused or an attempt to have this server
	 * accept an authentication method nobody can satisfy.
	 */
	it('refuses any authentication method based on a shared symmetric secret', () => {
		for (const method of [
			'client_secret_basic',
			'client_secret_post',
			'client_secret_jwt'
		]) {
			const result = validate(
				documentFor(IDENTIFIER, { token_endpoint_auth_method: method })
			);
			expect(result.ok, method).toBe(false);
			if (!result.ok) expect(result.reason, method).toBe('symmetric_secret');
		}
	});

	it('accepts a public client and one proving possession of a published key', () => {
		expect(
			validate(documentFor(IDENTIFIER, { token_endpoint_auth_method: 'none' }))
				.ok
		).toBe(true);

		expect(
			validate(
				documentFor(IDENTIFIER, {
					token_endpoint_auth_method: 'private_key_jwt',
					jwks_uri: 'https://app.example.com/jwks.json'
				})
			).ok
		).toBe(true);
	});

	/*
	 * A key-proving method with nowhere to find the key would be accepted and then fail at the token
	 * endpoint, which is a refusal an operator cannot diagnose from the document.
	 */
	it('refuses private_key_jwt with no published key location', () => {
		const result = validate(
			documentFor(IDENTIFIER, { token_endpoint_auth_method: 'private_key_jwt' })
		);

		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.reason).toBe('missing_jwks');
	});

	/*
	 * A secret in a self-hosted, world-readable document is not a secret. Stripped rather than
	 * refused, because the harm is in honouring it, and a document that carries one by mistake should
	 * still be able to identify a public client.
	 */
	it('never carries a client secret out of a document', () => {
		const result = validate(
			documentFor(IDENTIFIER, { client_secret: 'not-a-secret-anymore' })
		);

		expect(result.ok).toBe(true);
		if (result.ok) expect(result.metadata.clientSecret).toBeUndefined();
	});
});
