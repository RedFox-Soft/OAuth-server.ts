import { describe, it, beforeAll, expect } from 'bun:test';
import bootstrap, { agent } from '../test_helper.js';

/**
 * @proves UserInfo refuses an absent or malformed credential with a bearer challenge rather than
 * parsing it optimistically.
 */
describe('providing Bearer token', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	describe('invalid requests', () => {
		it('UserInfo without a credential is refused with a bearer challenge', async function () {
			// @ts-expect-error intentionally calling with no args to test the missing-token path
			const { error } = await agent.userinfo.get();
			if (!error) {
				throw new Error('Have to be exception');
			}
			expect(error.status).toBe(422);
			expect(error.value).toEqual({
				error: 'invalid_request',
				error_description: 'no access token provided'
			});
		});

		it('refuses an Authorization header with only one part', async function () {
			const { error } = await agent.userinfo.get({
				headers: {
					authorization: 'Bearer'
				}
			});
			if (!error) {
				throw new Error('Have to be exception');
			}
			expect(error.status).toBe(401);
			expect(error.value).toEqual({
				error: 'invalid_header_authorization',
				error_description: 'invalid authorization header value format'
			});
		});

		it('refuses an Authorization scheme other than Bearer', async function () {
			const { error } = await agent.userinfo.get({
				headers: {
					authorization: 'Basic some'
				}
			});
			if (!error) {
				throw new Error('Have to be exception');
			}
			expect(error.status).toBe(401);
			expect(error.value).toEqual({
				error: 'invalid_header_authorization',
				error_description: 'authorization header scheme must be `Bearer`'
			});
		});
	});
});
