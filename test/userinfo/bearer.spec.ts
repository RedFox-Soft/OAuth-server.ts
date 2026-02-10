import { describe, it, beforeAll, expect } from 'bun:test';
import bootstrap, { agent } from '../test_helper.js';

describe('providing Bearer token', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url)();
	});

	describe('invalid requests', () => {
		it('nothing provided', async function () {
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

		it('bad Authorization header format (one part)', async function () {
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

		it('bad Authorization header format (not bearer)', async function () {
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
