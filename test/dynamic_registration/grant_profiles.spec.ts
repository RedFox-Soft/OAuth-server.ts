import { describe, beforeAll, it, expect } from 'bun:test';
import { Type } from '@sinclair/typebox';

import bootstrap, { agent } from '../test_helper.js';
import { shaped } from 'test/shape.js';

const json = { 'content-type': 'application/json' };
const REDIRECT = 'https://client.example.com/cb';
const ID_JAG = 'urn:ietf:params:oauth:grant-profile:id-jag';
const EXCHANGE = 'urn:ietf:params:oauth:grant-type:token-exchange';
const BEARER = 'urn:ietf:params:oauth:grant-type:jwt-bearer';

const Body = Type.Record(Type.String(), Type.Unknown());

function register(metadata: Record<string, unknown>) {
	return agent.reg.post(
		{ redirect_uris: [REDIRECT], ...metadata },
		{ headers: json }
	);
}

/**
 * @proves A client cannot declare that it implements the ID-JAG grant profile without both grants the
 * profile is made of (ID-JAG §8), and one that has them is registered with the profile echoed.
 */
describe('registering a client that declares the ID-JAG grant profile', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'dynamic_registration' });
	});

	it('refuses the profile with invalid_client_metadata when the token-exchange grant is missing', async () => {
		const { status, error } = await register({
			grant_types: ['authorization_code', BEARER],
			authorization_grant_profiles_supported: [ID_JAG]
		});

		expect(status).toBe(400);
		expect(shaped(Body, error?.value)).toHaveProperty(
			'error',
			'invalid_client_metadata'
		);
	});

	it('registers the client and echoes the profile when both grants are present', async () => {
		const { status, data } = await register({
			grant_types: ['authorization_code', EXCHANGE, BEARER],
			authorization_grant_profiles_supported: [ID_JAG]
		});

		expect(status).toBe(201);
		expect(shaped(Body, data)).toHaveProperty(
			'authorization_grant_profiles_supported',
			[ID_JAG]
		);
	});
});
