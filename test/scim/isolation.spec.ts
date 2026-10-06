import { describe, it, beforeAll, expect } from 'bun:test';

import { elysia } from 'lib/index.js';
import bootstrap from '../test_helper.js';
import { basic, token } from '../provisioning/helpers.ts';
import {
	connect,
	provider,
	scim,
	scimBucket,
	scimUser,
	type Connected
} from './helpers.ts';
import { issueCredential } from 'lib/provisioning/service.js';

const noAudit = async () => undefined;

async function oauthToken(
	c: Connected
): Promise<{ secret: string; access: string }> {
	const { secret } = await issueCredential(
		c.bucket,
		c.connection._id,
		{ kind: 'secret' },
		noAudit
	);
	const granted = await token(
		`/${c.bucket.slug}/token`,
		{ grant_type: 'client_credentials' },
		basic(`scim-${c.connection._id}`, secret as string)
	);
	expect(granted.status).toBe(200);
	return {
		secret: secret as string,
		access: granted.json.access_token as string
	};
}

/**
 * @proves A connection sees and changes only the users it provisioned, in its own bucket, with a credential
 * good for nothing else — whichever endpoint, bucket, scope or resource it is tried at (spec 070, User
 * Story 5, scenarios 1–4; FR-011, FR-012, FR-022, FR-023; SC-004).
 */
describe('a provisioning connection is fenced in', () => {
	let a: Connected;
	let b: Connected;
	let other: Connected;
	let bUser: string;

	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'scim' });
		const shared = await scimBucket([provider('one'), provider('two')]);
		a = await connect(shared, { providerId: 'one' });
		b = await connect(shared, { providerId: 'two' });
		other = await connect(await scimBucket([provider('three')]));
		await scim('POST', `${a.base}/Users`, {
			token: a.token,
			body: scimUser('a1@contoso.com')
		});
		bUser = (
			await scim('POST', `${b.base}/Users`, {
				token: b.token,
				body: scimUser('b1@contoso.com')
			})
		).json.id as string;
	});

	it('lists only its own users', async () => {
		const res = await scim('GET', `${a.base}/Users`, { token: a.token });

		expect(res.json).toMatchObject({ totalResults: 1 });
		expect((res.json.Resources as { userName: string }[])[0].userName).toBe(
			'a1@contoso.com'
		);
	});

	it('answers 404 for another connection’s user, whatever it tries', async () => {
		const path = `${a.base}/Users/${bUser}`;

		const results = [
			await scim('GET', path, { token: a.token }),
			await scim('PUT', path, {
				token: a.token,
				body: scimUser('b1@contoso.com', { displayName: 'x' })
			}),
			await scim('PATCH', path, {
				token: a.token,
				body: {
					schemas: ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
					Operations: [{ op: 'replace', path: 'active', value: false }]
				}
			}),
			await scim('DELETE', path, { token: a.token })
		];

		for (const res of results) expect(res.status).toBe(404);
		const still = await scim('GET', `${b.base}/Users/${bUser}`, {
			token: b.token
		});
		expect(still.json).toMatchObject({ active: true });
	});

	it('refuses its token at another bucket’s SCIM endpoint, at userinfo, at MCP and at the admin API', async () => {
		const { access } = await oauthToken(a);
		const bearer = { authorization: `Bearer ${access}` };
		const call = (path: string, method = 'GET') =>
			elysia.handle(
				new Request(`http://e.ly${path}`, { method, headers: bearer })
			);

		expect(
			(await scim('GET', `${other.base}/Users`, { token: access })).status
		).toBe(401);
		expect(
			(await scim('GET', `${other.base}/Users`, { token: a.token })).status
		).toBe(401);
		expect(
			(await call(`/${a.bucket.slug}/userinfo`)).status
		).toBeGreaterThanOrEqual(400);
		expect((await call('/mcp', 'POST')).status).toBeGreaterThanOrEqual(400);
		expect(
			(await call(`/admin/api/buckets/${a.bucket._id}/users`)).status
		).toBeGreaterThanOrEqual(400);
	});

	it('gets no token at another bucket, for another scope or for another resource', async () => {
		const { secret } = await oauthToken(a);
		const auth = basic(`scim-${a.connection._id}`, secret);

		const atOtherBucket = await token(
			`/${other.bucket.slug}/token`,
			{ grant_type: 'client_credentials' },
			auth
		);
		const otherScope = await token(
			`/${a.bucket.slug}/token`,
			{ grant_type: 'client_credentials', scope: 'scim openid' },
			auth
		);
		const otherResource = await token(
			`/${a.bucket.slug}/token`,
			{ grant_type: 'client_credentials', resource: 'http://e.ly/mcp' },
			auth
		);

		expect(atOtherBucket.json.error).toBe('invalid_target');
		expect(otherScope.json.error).toBe('invalid_scope');
		expect(otherResource.json.error).toBe('invalid_target');
	});

	it('gives no other client a token for a bucket’s SCIM resource', async () => {
		const res = await token(
			`/${a.bucket.slug}/token`,
			{
				grant_type: 'client_credentials',
				resource: `http://e.ly/${a.bucket.slug}/scim/v2`
			},
			basic('client', 'secret')
		);

		expect(res.json.error).toBe('invalid_target');
	});
});
