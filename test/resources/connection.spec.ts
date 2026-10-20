import { describe, it, expect, beforeAll } from 'bun:test';
import { decodeJwt } from 'jose';
import bootstrap, { bindClientToBucket } from '../test_helper.js';
import { AuthorizationRequest } from 'test/AuthorizationRequest.js';
import { elysia } from 'lib/index.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { getBucketStore } from 'lib/adapters/index.ts';
import { ADMIN_SESSION_COOKIE, UNASSIGNED_GROUP_ID } from 'lib/admin/consts.ts';
import { ISSUER } from 'lib/configs/env.js';
import nanoid from 'lib/helpers/nanoid.ts';
import { createAdministrator } from '../administrators.ts';
import { sessionFor } from '../admin_session.ts';
import { present } from 'test/shape.js';

const IDENTIFIER = 'https://mcp.connection.example/mcp';

interface Connection {
	issuer: string;
	audience: string;
	metadata: { resource: string; authorization_servers: string[] };
	metadataUrl: string | null;
	challenge: string | null;
}

let cookie: string;
let projectId: string;

async function admin(method: string, path: string, body?: unknown) {
	const response = await elysia.handle(
		new Request(`${ISSUER}${path}`, {
			method,
			headers: { cookie, 'content-type': 'application/json' },
			...(body === undefined ? {} : { body: JSON.stringify(body) })
		})
	);
	return { status: response.status, data: (await response.json()) as unknown };
}

async function declaredConnection(): Promise<Connection> {
	const listed = await admin(
		'GET',
		`/admin/api/projects/${projectId}/resources`
	);
	const { resources } = listed.data as {
		resources: { connection: Connection }[];
	};
	return present(resources.at(0), 'the declared API').connection;
}

/**
 * @proves A developer protecting a declared API is told the issuer and the exact audience its tokens carry, and the
 * metadata to serve names the project as authorization server — the same values a token issued for it carries.
 */
describe("a declared API's connection details", () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'connection' });
		await ensureAdminSeed();
		const user = await createAdministrator('super', `rc-${nanoid()}@x.io`);
		cookie = `${ADMIN_SESSION_COOKIE}=${(await sessionFor(user))._id}`;
		const id = nanoid()
			.toLowerCase()
			.replace(/[^a-z0-9]/g, '');
		projectId = (
			await getBucketStore().create({
				name: `connection ${id}`,
				slug: `rc-${id}`,
				ownerGroupId: UNASSIGNED_GROUP_ID
			})
		)._id;
		await bindClientToBucket('conn-service', projectId);
		const declared = await admin(
			'POST',
			`/admin/api/projects/${projectId}/resources`,
			{
				identifier: IDENTIFIER,
				name: 'Connection API',
				scopes: ['mcp:tools'],
				tokenFormat: 'jwt',
				accessTokenTTL: 600
			}
		);
		expect(declared.status).toBe(201);
	});

	it('name its exact audience and the issuer that mints its tokens, which a token issued for it carries', async () => {
		const connection = await declaredConnection();

		// At the project's own token endpoint: the API is declared in the project, under its issuer.
		const response = await elysia.handle(
			new Request(`${connection.issuer}/token`, {
				method: 'POST',
				headers: {
					...AuthorizationRequest.basicAuthHeader(
						'conn-service',
						'conn-service-secret'
					),
					'content-type': 'application/x-www-form-urlencoded'
				},
				body: new URLSearchParams({
					grant_type: 'client_credentials',
					scope: 'mcp:tools',
					resource: IDENTIFIER
				}).toString()
			})
		);
		expect(response.status).toBe(200);
		const claims = decodeJwt(
			((await response.json()) as { access_token: string }).access_token
		);
		expect(connection.audience).toBe(IDENTIFIER);
		expect(claims.aud).toBe(connection.audience);
		expect(claims.iss).toBe(connection.issuer);
	});

	it('give metadata that names the project as its authorization server, and the challenge pointing at it', async () => {
		const connection = await declaredConnection();

		expect(connection.metadata.resource).toBe(IDENTIFIER);
		expect(connection.metadata.authorization_servers).toEqual([
			connection.issuer
		]);
		expect(connection.metadataUrl).toBe(
			'https://mcp.connection.example/.well-known/oauth-protected-resource/mcp'
		);
		expect(connection.challenge).toBe(
			`Bearer resource_metadata="${String(connection.metadataUrl)}"`
		);
	});
});
