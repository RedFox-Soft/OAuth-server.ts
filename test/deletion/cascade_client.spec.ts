import { describe, it, expect, beforeAll, beforeEach } from 'bun:test';

import bootstrap, { agent, type Setup } from '../test_helper.js';
import { AuthorizationRequest } from 'test/AuthorizationRequest.js';
import { AccessToken } from 'lib/models/access_token.js';
import { RefreshToken } from 'lib/models/refresh_token.js';
import { AuthorizationCode } from 'lib/models/authorization_code.js';
import { ClientCredentials } from 'lib/models/client_credentials.js';
import { DeviceCode } from 'lib/models/device_code.js';
import { BackchannelAuthenticationRequest } from 'lib/models/backchannel_authentication_request.js';
import { RegistrationAccessToken } from 'lib/models/registration_access_token.js';
import { Grant } from 'lib/models/grant.js';
import { Client } from 'lib/models/client.js';
import {
	adapter,
	adminSessionStore,
	getProjectStore,
	getUserStore
} from 'lib/adapters/index.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import {
	ADMIN_BUCKET_ID,
	ADMIN_SESSION_COOKIE,
	UNASSIGNED_GROUP_ID
} from 'lib/admin/consts.ts';
import { updateClient } from 'lib/admin/clients/service.ts';
import { sessionFor } from '../admin_session.ts';

// User Story 1 — deleting a client destroys everything it issued.
//
// Assertions go through the endpoint that *consumes* the credential wherever one exists: the claim is
// "this no longer works", and only the real surface can prove that. The two areas worth the trouble are
// ClientCredentials, which carries no grantId so no grant walk reaches it, and RegistrationAccessToken,
// which may be issued with no expiry so its residue is not even bounded by a TTL.
//
// Every test seeds its own client. Sharing one would make each test depend on the previous test not
// having deleted it — which is exactly what this suite does to its subject.

describe('deletion cascade: client', () => {
	let setup: Setup;
	let counter = 0;

	beforeAll(async () => {
		setup = await bootstrap(import.meta.url);
	});

	beforeEach(async () => {
		await ensureAdminSeed();
	});

	/* Upserted rather than seedClient()'d: this runs many times per file, and seedClient refuses a
	 * duplicate id by design. */
	async function freshClient() {
		counter += 1;
		const clientId = `doomed-${counter}`;
		await adapter('Client').upsert(clientId, {
			clientId,
			clientSecret: 'secret',
			grantTypes: [
				'authorization_code',
				'refresh_token',
				'client_credentials',
				'urn:ietf:params:oauth:grant-type:device_code'
			],
			responseTypes: ['code'],
			redirectUris: [`https://${clientId}.example.com/cb`]
		});
		const client = await Client.tryFind(clientId);
		if (!client) throw new Error(`client ${clientId} did not resolve`);
		return client;
	}

	async function consentFor(clientId: string, accountId: string) {
		const grant = new Grant({ clientId, accountId });
		grant.addOIDCScope('openid offline_access');
		return grant.save();
	}

	async function superAdminCookie(): Promise<string> {
		const user = await getUserStore(ADMIN_BUCKET_ID).create(
			`sa-${Math.random()}@x.io`,
			'hash',
			['super_admin']
		);
		const session = await sessionFor(user);
		return `${ADMIN_SESSION_COOKIE}=${session._id}`;
	}

	async function deleteClient(clientId: string) {
		const cookie = await superAdminCookie();
		const project = await getProjectStore().create({
			ownerGroupId: UNASSIGNED_GROUP_ID,
			name: 'P',
			slug: `p-${Math.random()}`,
			clientIds: [clientId]
		});
		return agent.admin.api
			.projects({ id: project._id })
			.clients({ clientId })
			.delete(undefined, { headers: { cookie } });
	}

	it('refuses its access token at userinfo and reports it inactive (scenario 1)', async () => {
		await setup.login({ scope: 'openid' });
		const accountId = setup.getAccountId();
		const client = await freshClient();
		const grantId = await consentFor(client.clientId, accountId);

		const at = new AccessToken({
			client,
			accountId,
			grantId,
			scope: 'openid'
		});
		const bearer = await at.save();

		const before = await agent.userinfo.get({
			headers: { authorization: `Bearer ${bearer}` }
		});
		expect(before.status).toBe(200);

		const deleted = await deleteClient(client.clientId);
		expect(deleted.status).toBe(200);

		const after = await agent.userinfo.get({
			headers: { authorization: `Bearer ${bearer}` }
		});
		expect(after.status).toBe(401);

		expect(await introspect(bearer)).toHaveProperty('active', false);
	});

	it('refuses its refresh token as an invalid grant (scenario 2)', async () => {
		await setup.login({ scope: 'openid offline_access' });
		const accountId = setup.getAccountId();
		const client = await freshClient();
		const grantId = await consentFor(client.clientId, accountId);

		const rt = new RefreshToken({
			client,
			accountId,
			grantId,
			scope: 'openid offline_access',
			gty: 'authorization_code'
		});
		const token = await rt.save();
		expect(await introspect(token)).toHaveProperty('active', true);

		await deleteClient(client.clientId);

		// Inactive to a third party, and unusable at the token endpoint. Both matter: the first proves the
		// record is gone, the second that no path accepts it.
		expect(await introspect(token)).toHaveProperty('active', false);
		const exchange = await agent.token.post(
			{ grant_type: 'refresh_token', refresh_token: token },
			{ headers: basicAuth(client.clientId, 'secret') }
		);
		expect(errorOf(exchange)).toMatch(/invalid_grant|invalid_client/);
	});

	it('reports its client-credentials token inactive (scenario 3)', async () => {
		const client = await freshClient();
		const cc = new ClientCredentials({ client, scope: '' });
		const token = await cc.save();
		expect(await introspect(token)).toHaveProperty('active', true);

		await deleteClient(client.clientId);

		// No grantId on this payload at all, so only an owner sweep reaches it.
		expect(await introspect(token)).toHaveProperty('active', false);
	});

	it('refuses its own registration access token (scenario 4)', async () => {
		const client = await freshClient();
		const rat = new RegistrationAccessToken({ clientId: client.clientId });
		const token = await rat.save();

		// Recorded from a probe: a registration access token is persisted with no `exp` at all, which is
		// why this area is the one swept first — its residue is not bounded by any TTL.
		expect(
			await adapter('RegistrationAccessToken').find(rat.jti)
		).toBeDefined();

		await deleteClient(client.clientId);

		// Asserted before the PUT, deliberately. Registration management rotates the token it
		// authenticates with, so a PUT would destroy the record itself and make this assertion pass for
		// the wrong reason.
		expect(
			await adapter('RegistrationAccessToken').find(rat.jti)
		).toBeUndefined();

		const res = await agent.reg({ clientId: client.clientId }).put(
			{
				clientId: client.clientId,
				redirectUris: ['https://x.example.com/cb']
			},
			{ headers: { authorization: `Bearer ${token}` } }
		);
		expect(res.status).not.toBe(200);
	});

	it('destroys outstanding codes, device codes and backchannel requests (scenario 5)', async () => {
		await setup.login({ scope: 'openid' });
		const accountId = setup.getAccountId();
		const client = await freshClient();
		const grantId = await consentFor(client.clientId, accountId);

		const code = new AuthorizationCode({
			client,
			accountId,
			grantId,
			scope: 'openid',
			redirectUri: `https://${client.clientId}.example.com/cb`
		});
		await code.save();
		const device = new DeviceCode({
			client,
			accountId,
			grantId,
			scope: 'openid',
			userCode: `AAAA-${counter}`
		});
		await device.save();
		const backchannel = new BackchannelAuthenticationRequest({
			client,
			accountId,
			grantId,
			scope: 'openid'
		});
		await backchannel.save();

		await deleteClient(client.clientId);

		expect(await adapter('AuthorizationCode').find(code.jti)).toBeUndefined();
		expect(await adapter('DeviceCode').find(device.jti)).toBeUndefined();
		expect(
			await adapter('BackchannelAuthenticationRequest').find(backchannel.jti)
		).toBeUndefined();
	});

	it('destroys the consent records naming it, and only those (scenario 6)', async () => {
		await setup.login({ scope: 'openid' });
		const accountId = setup.getAccountId();
		const doomed = await freshClient();
		const survivor = await freshClient();
		const doomedGrant = await consentFor(doomed.clientId, accountId);
		const survivorGrant = await consentFor(survivor.clientId, accountId);

		await deleteClient(doomed.clientId);

		expect(await adapter('Grant').find(doomedGrant)).toBeUndefined();
		expect(await adapter('Grant').find(survivorGrant)).toBeDefined();
	});

	// The Mongo-only hole this closes: revocation used to ask the client whether it still allowed a grant
	// type before sweeping that area, so narrowing the types after issuance shielded live tokens.
	it('sweeps tokens even after its grant types were narrowed (scenario 7)', async () => {
		await setup.login({ scope: 'openid offline_access' });
		const accountId = setup.getAccountId();
		const client = await freshClient();
		const grantId = await consentFor(client.clientId, accountId);

		const rt = new RefreshToken({
			client,
			accountId,
			grantId,
			scope: 'openid offline_access',
			gty: 'authorization_code'
		});
		await rt.save();

		await updateClient(client.clientId, {
			grantTypes: ['authorization_code']
		});
		await deleteClient(client.clientId);

		expect(await adapter('RefreshToken').find(rt.jti)).toBeUndefined();
	});

	it('deletes a client that issued nothing (scenario 8)', async () => {
		const client = await freshClient();

		const res = await deleteClient(client.clientId);

		expect(res.status).toBe(200);
		expect(await adapter('Client').find(client.clientId)).toBeUndefined();
	});
});

/* The suite's own encoding (base64url, percent-encoded parts) and no content-type override, which eden
 * needs to serialize the body itself. */
function basicAuth(clientId: string, secret: string) {
	return AuthorizationRequest.basicAuthHeader(clientId, secret);
}

/* Introspected by a *surviving* client, so the answer is about the token and not about the caller. */
async function introspect(token: string): Promise<unknown> {
	const res = await agent.token.introspect.post(
		{ token },
		{ headers: basicAuth('bystander', 'secret') }
	);
	return res.data;
}

/* Eden's response type varies per route, so this narrows from `unknown` rather than naming a shape that
 * only fits one of them. */
function errorOf(response: unknown): string {
	return bodyOf<{ error?: string }>(response)?.error ?? '';
}

/* The body of a response, whether the route answered with it as data or as an error. */
function bodyOf<T>(response: unknown): T | undefined {
	if (typeof response !== 'object' || response === null) return undefined;
	const { data, error } = response as {
		data?: unknown;
		error?: { value?: unknown } | null;
	};
	return (data ?? error?.value) as T | undefined;
}
