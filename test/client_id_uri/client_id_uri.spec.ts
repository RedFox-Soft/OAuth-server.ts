import { describe, it, beforeAll, expect } from 'bun:test';

import bootstrap, { agent } from '../test_helper.js';

const json = { 'content-type': 'application/json' };
const bearer = (token) => ({ authorization: `Bearer ${token}` });

// The client_id here is a full URI (the config's idFactory returns one), so it is percent-encoded
// into the /reg/:clientId path segment. registration_client_uri must therefore carry the encoded
// client_id in its path and no query string.
function expectUri(registration_client_uri, client_id) {
	const parsed = new URL(registration_client_uri);
	expect(parsed.search).toHaveLength(0);
	const i = parsed.pathname.indexOf('/reg/');
	expect(parsed.pathname.slice(i + 5)).toBe(encodeURIComponent(client_id));
}

describe('registration management with client_id as URI', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	it('returns client_id as a URI string', async () => {
		let res = await agent.reg.post(
			{ redirect_uris: ['https://client.example.com/cb'] },
			{ headers: json }
		);
		expect(res.status).toBe(201);
		if (!res.data) throw new Error('expected response data');

		const { client_id } = res.data;
		let { registration_access_token, registration_client_uri } = res.data;
		expectUri(registration_client_uri, client_id);

		// eden treaty does not encode dynamic path segments, and the client_id is a URI, so the
		// value handed to the path param must itself be percent-encoded (Elysia decodes it back).
		const clientId = encodeURIComponent(client_id);

		res = await agent
			.reg({ clientId })
			.get({ headers: bearer(registration_access_token) });
		expect(res.status).toBe(200);
		if (!res.data) throw new Error('expected response data');
		({ registration_access_token, registration_client_uri } = res.data);
		expectUri(registration_client_uri, client_id);

		res = await agent.reg({ clientId }).put(
			{
				client_id,
				redirect_uris: ['https://client.example.com/cb2']
			},
			{ headers: { ...json, ...bearer(registration_access_token) } }
		);
		expect(res.status).toBe(200);
		if (!res.data) throw new Error('expected response data');
		({ registration_access_token, registration_client_uri } = res.data);
		expectUri(registration_client_uri, client_id);

		res = await agent
			.reg({ clientId })
			.delete(undefined, { headers: bearer(registration_access_token) });
		expect(res.status).toBe(204);
	});
});
