import { describe, it, expect, beforeAll } from 'bun:test';
import { Type } from '@sinclair/typebox';

import bootstrap from '../test_helper.js';
import { AccessToken } from 'lib/models/access_token.js';
import { Client } from 'lib/models/client.js';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { ADMIN_MCP_CLIENT_ID, MCP_RESOURCE } from 'lib/mcp/consts.ts';
import { adminCookie } from '../end_user_lifecycle/fixtures.ts';
import { createAdministrator } from '../administrators.ts';
import { shaped } from '../shape.ts';
import { call, rpc } from '../mcp/rpc.ts';
import {
	connect,
	provider,
	scimBucket,
	type Connected
} from '../scim/helpers.ts';
import { admin } from './helpers.ts';

const Guidance = Type.Object({
	directories: Type.Array(
		Type.Object({
			id: Type.String(),
			displayName: Type.String(),
			recommendedCredential: Type.String(),
			fallbackCredential: Type.Optional(Type.String()),
			labels: Type.Object({
				scimBaseUrl: Type.String(),
				clientSecret: Type.Optional(Type.String())
			}),
			steps: Type.Array(Type.String()),
			pitfalls: Type.Array(Type.String()),
			values: Type.Object({
				scimBaseUrl: Type.Union([Type.String(), Type.Null()]),
				tokenEndpoint: Type.Union([Type.String(), Type.Null()])
			})
		})
	)
});
const ConnectionRead = Type.Object({
	directory: Type.String(),
	scimBaseUrl: Type.Union([Type.String(), Type.Null()]),
	tokenEndpoint: Type.String()
});

const MICROSOFT =
	'https://login.microsoftonline.com/11112222-bbbb-3333-cccc-4444dddd5555/v2.0';

function directoriesPath(bucketId: string): string {
	return `/admin/api/projects/${bucketId}/provisioning-connections/directories`;
}

function connectionPath(c: Connected): string {
	return `/admin/api/projects/${c.bucket._id}/provisioning-connections/${c.connection._id}`;
}

async function agentToken(): Promise<string> {
	const user = await createAdministrator('super');
	const at = new AccessToken({
		client: await Client.find(ADMIN_MCP_CLIENT_ID),
		accountId: user._id,
		scope: 'openid'
	});
	at.setAudience(MCP_RESOURCE);
	const token = await at.save();
	await rpc(
		{
			jsonrpc: '2.0',
			id: 1,
			method: 'initialize',
			params: {
				protocolVersion: '2026-07-28',
				capabilities: {},
				clientInfo: { name: 'test-agent', version: '1.0.0' }
			}
		},
		token
	);
	return token;
}

/**
 * @proves An administrator and an agent read the same guidance for connecting Microsoft Entra ID, Okta or
 * another directory — in each directory's own words and with this bucket's addresses — and a connection
 * remembers which directory it is for, inferred for one that never said (spec 088, User Story 6).
 */
describe('directory guidance for SCIM provisioning', () => {
	let cookie: string;

	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'directories' });
		await ensureAdminSeed();
		cookie = await adminCookie();
	});

	it('names Entra, Okta and another directory, each with this bucket’s SCIM address and token endpoint', async () => {
		const c = await connect(await scimBucket());
		const view = shaped(
			ConnectionRead,
			(await admin('GET', connectionPath(c), cookie)).body
		);

		const reply = await admin('GET', directoriesPath(c.bucket._id), cookie);

		expect(reply.status).toBe(200);
		const { directories } = shaped(Guidance, reply.body);
		expect(directories.map((d) => d.id)).toEqual(['entra', 'okta', 'generic']);
		for (const directory of directories) {
			expect(directory.values).toEqual({
				scimBaseUrl: view.scimBaseUrl,
				tokenEndpoint: view.tokenEndpoint
			});
		}
	});

	it('uses Entra’s own field names and recommends it a client secret', async () => {
		const c = await connect(await scimBucket());

		const { directories } = shaped(
			Guidance,
			(await admin('GET', directoriesPath(c.bucket._id), cookie)).body
		);
		const entra = directories.find((d) => d.id === 'entra');

		expect(entra?.labels.scimBaseUrl).toBe('Tenant URL');
		expect(entra?.labels.clientSecret).toBe('Client Secret');
		expect(entra?.recommendedCredential).toBe('secret');
		expect(entra?.pitfalls.join(' ')).toContain('never Both');
	});

	it('recommends Okta a client secret with the static token as its fallback', async () => {
		const c = await connect(await scimBucket());

		const { directories } = shaped(
			Guidance,
			(await admin('GET', directoriesPath(c.bucket._id), cookie)).body
		);
		const okta = directories.find((d) => d.id === 'okta');

		expect(okta?.recommendedCredential).toBe('secret');
		expect(okta?.fallbackCredential).toBe('static_token');
		expect(okta?.labels.scimBaseUrl).toBe('SCIM connector base URL');
	});

	it('infers Entra for a connection bound to a Microsoft provider that never said', async () => {
		const c = await connect(
			await scimBucket([provider('ms', { issuer: MICROSOFT })])
		);

		const view = shaped(
			ConnectionRead,
			(await admin('GET', connectionPath(c), cookie)).body
		);

		expect(view.directory).toBe('entra');
	});

	it('infers another directory for a connection bound to any other provider', async () => {
		const c = await connect(await scimBucket());

		const view = shaped(
			ConnectionRead,
			(await admin('GET', connectionPath(c), cookie)).body
		);

		expect(view.directory).toBe('generic');
	});

	it('reads back the directory an administrator chose', async () => {
		const c = await connect(await scimBucket());

		const changed = await admin('PATCH', connectionPath(c), cookie, {
			directory: 'okta'
		});

		expect(changed.status).toBe(200);
		expect(
			shaped(
				ConnectionRead,
				(await admin('GET', connectionPath(c), cookie)).body
			).directory
		).toBe('okta');
	});

	it('creates a connection for the directory named at creation', async () => {
		const bucket = await scimBucket();

		const created = await admin(
			'POST',
			`/admin/api/projects/${bucket._id}/provisioning-connections`,
			cookie,
			{ displayName: 'Okta', providerId: 'corp', directory: 'okta' }
		);

		expect(created.status).toBe(201);
		expect(shaped(ConnectionRead, created.body).directory).toBe('okta');
	});

	it('refuses a directory it does not know', async () => {
		const c = await connect(await scimBucket());

		const changed = await admin('PATCH', connectionPath(c), cookie, {
			directory: 'ldap'
		});

		expect(changed.status).toBe(422);
	});

	it('gives an agent the same guidance the console reads', async () => {
		const c = await connect(await scimBucket());
		const token = await agentToken();

		const fromConsole = shaped(
			Guidance,
			(await admin('GET', directoriesPath(c.bucket._id), cookie)).body
		);
		const agent = await rpc(
			call('provisioning_directory_list', { id: c.bucket._id }),
			token
		);

		expect(agent.result?.isError).not.toBe(true);
		expect(shaped(Guidance, agent.result?.structuredContent?.result)).toEqual(
			fromConsole
		);
	});
});
