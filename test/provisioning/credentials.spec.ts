import { describe, it, beforeAll, afterEach, expect } from 'bun:test';
import { exportJWK, generateKeyPair, SignJWT } from 'jose';

import { ApplicationConfig } from 'lib/configs/application.js';
import bootstrap from '../test_helper.js';
import { adminCookie } from '../end_user_lifecycle/fixtures.ts';
import {
	connect,
	scim,
	scimBucket,
	type Connected,
	slugOf
} from '../scim/helpers.ts';
import { admin, basic, token } from './helpers.ts';

function connectionPath(c: Connected): string {
	return `/admin/api/buckets/${c.bucket._id}/provisioning-connections/${c.connection._id}`;
}

function tokenPath(c: Connected): string {
	return `/${slugOf(c.bucket)}/token`;
}

async function issueSecret(c: Connected, cookie: string): Promise<string> {
	const issued = await admin(
		'POST',
		`${connectionPath(c)}/credentials`,
		cookie,
		{
			kind: 'secret'
		}
	);
	expect(issued.status).toBe(201);
	return issued.json.secret as string;
}

/**
 * @proves A provisioning connection's credentials obtain a token good for its own bucket's SCIM endpoint,
 * are shown exactly once, and stop working — with every token they obtained — the moment they are rotated,
 * revoked or switched off (spec 070, User Story 2, scenarios 2–4, 10; FR-009, FR-010, FR-013).
 */
describe('provisioning connection credentials', () => {
	let cookie: string;

	beforeAll(async () => {
		await bootstrap(import.meta.url);
		cookie = await adminCookie();
	});

	afterEach(() => {
		ApplicationConfig['scim.secretCredentials'] = true;
		ApplicationConfig['scim.staticTokens'] = true;
	});

	it('obtains a scim token with a signed client assertion that works on the bucket’s SCIM endpoints', async () => {
		const c = await connect(await scimBucket());
		const { publicKey, privateKey } = await generateKeyPair('ES256');
		const jwk = {
			...(await exportJWK(publicKey)),
			kid: 'k1',
			use: 'sig',
			alg: 'ES256'
		};
		const issued = await admin(
			'POST',
			`${connectionPath(c)}/credentials`,
			cookie,
			{
				kind: 'key',
				jwks: { keys: [jwk] }
			}
		);
		expect(issued.status).toBe(201);
		const clientId = `scim-${c.connection._id}`;
		const assertion = await new SignJWT({})
			.setProtectedHeader({ alg: 'ES256', kid: 'k1' })
			.setIssuer(clientId)
			.setSubject(clientId)
			.setAudience(`http://e.ly${tokenPath(c)}`)
			.setJti(crypto.randomUUID())
			.setIssuedAt()
			.setExpirationTime('2m')
			.sign(privateKey);

		const granted = await token(tokenPath(c), {
			grant_type: 'client_credentials',
			client_id: clientId,
			client_assertion_type:
				'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
			client_assertion: assertion
		});
		const used = await scim('GET', `${c.base}/Users`, {
			token: granted.json.access_token as string
		});

		expect(granted.status).toBe(200);
		expect(granted.json).toMatchObject({ token_type: 'Bearer', scope: 'scim' });
		expect(used.status).toBe(200);
	});

	it('accepts a secret in the Authorization header and in the body alike', async () => {
		const c = await connect(await scimBucket());
		const secret = await issueSecret(c, cookie);
		const clientId = `scim-${c.connection._id}`;

		const viaHeader = await token(
			tokenPath(c),
			{ grant_type: 'client_credentials' },
			basic(clientId, secret)
		);
		const viaBody = await token(tokenPath(c), {
			grant_type: 'client_credentials',
			client_id: clientId,
			client_secret: secret
		});

		expect(viaHeader.status).toBe(200);
		expect(viaBody.status).toBe(200);
	});

	it('never returns an issued secret or static token in a later read', async () => {
		const c = await connect(await scimBucket());
		const secret = await issueSecret(c, cookie);

		const one = await admin('GET', connectionPath(c), cookie);
		const all = await admin(
			'GET',
			`/admin/api/buckets/${c.bucket._id}/provisioning-connections`,
			cookie
		);

		for (const read of [one, all]) {
			expect(read.status).toBe(200);
			const serialised = JSON.stringify(read.json);
			expect(serialised).not.toContain(secret);
			expect(serialised).not.toContain(c.token);
		}
	});

	it('stops the old secret, the old static token and every token they obtained once each is re-issued', async () => {
		const c = await connect(await scimBucket());
		const clientId = `scim-${c.connection._id}`;
		const oldSecret = await issueSecret(c, cookie);
		const oldAccess = (
			await token(
				tokenPath(c),
				{ grant_type: 'client_credentials' },
				basic(clientId, oldSecret)
			)
		).json.access_token as string;

		await issueSecret(c, cookie);
		const reissuedToken = await admin(
			'POST',
			`${connectionPath(c)}/credentials`,
			cookie,
			{
				kind: 'static_token'
			}
		);

		expect(reissuedToken.status).toBe(201);
		expect(
			(
				await token(
					tokenPath(c),
					{ grant_type: 'client_credentials' },
					basic(clientId, oldSecret)
				)
			).json.error
		).toBe('invalid_client');
		expect(
			(await scim('GET', `${c.base}/Users`, { token: oldAccess })).status
		).toBe(401);
		expect(
			(await scim('GET', `${c.base}/Users`, { token: c.token })).status
		).toBe(401);
	});

	it('revokes every token a connection obtained when the connection is deleted', async () => {
		const c = await connect(await scimBucket());
		const clientId = `scim-${c.connection._id}`;
		const secret = await issueSecret(c, cookie);
		const access = (
			await token(
				tokenPath(c),
				{ grant_type: 'client_credentials' },
				basic(clientId, secret)
			)
		).json.access_token as string;

		const deleted = await admin('DELETE', connectionPath(c), cookie);

		expect(deleted.status).toBe(200);
		expect(
			(await scim('GET', `${c.base}/Users`, { token: access })).status
		).toBe(401);
	});

	it('refuses a secret and a static token once their kind is switched off', async () => {
		const c = await connect(await scimBucket());
		const clientId = `scim-${c.connection._id}`;
		const secret = await issueSecret(c, cookie);
		const access = (
			await token(
				tokenPath(c),
				{ grant_type: 'client_credentials' },
				basic(clientId, secret)
			)
		).json.access_token as string;

		ApplicationConfig['scim.secretCredentials'] = false;
		ApplicationConfig['scim.staticTokens'] = false;

		expect(
			(
				await token(
					tokenPath(c),
					{ grant_type: 'client_credentials' },
					basic(clientId, secret)
				)
			).json.error
		).toBe('invalid_client');
		expect(
			(await scim('GET', `${c.base}/Users`, { token: access })).status
		).toBe(401);
		expect(
			(await scim('GET', `${c.base}/Users`, { token: c.token })).status
		).toBe(401);
	});
});
