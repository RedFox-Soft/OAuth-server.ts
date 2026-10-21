import { describe, beforeAll, it, expect } from 'bun:test';
import { Type } from '@sinclair/typebox';

import bootstrap from '../test_helper.js';
import { getBucketGroupStore } from 'lib/adapters/index.js';
import { DEFAULT_BUCKET_ID } from 'lib/admin/consts.ts';
import { ISSUER } from 'lib/configs/env.js';
import { MCP_RESOURCE } from 'lib/mcp/consts.js';
import { shaped } from 'test/shape.js';
import { adminCookie, defaultBucket } from '../end_user_lifecycle/fixtures.ts';
import { admin } from '../provisioning/helpers.ts';

const BASE = `/admin/api/projects/${DEFAULT_BUCKET_ID}/outside-authorization-servers`;

const Connection = Type.Object({
	id: Type.String(),
	issuer: Type.String(),
	displayName: Type.String(),
	applications: Type.Array(
		Type.Object({
			clientId: Type.String(),
			externalClientId: Type.Optional(Type.String())
		})
	),
	rules: Type.Array(
		Type.Object({
			appliesTo: Type.Union([
				Type.Literal('everyone'),
				Type.Object({
					groups: Type.Array(
						Type.Object({
							id: Type.String(),
							name: Type.Union([Type.String(), Type.Null()])
						})
					)
				})
			]),
			apis: Type.Array(
				Type.Object({
					identifier: Type.String(),
					scopes: Type.Array(Type.String())
				})
			)
		})
	),
	includeEmail: Type.Boolean(),
	lastUsedAt: Type.Union([Type.Number(), Type.Null()])
});

function body(overrides: Record<string, unknown> = {}) {
	return {
		issuer: 'https://as.tickets.example',
		displayName: 'Tickets',
		applications: [{ clientId: 'globex-agent', externalClientId: 'f53f191f' }],
		rules: [
			{
				appliesTo: 'everyone',
				apis: [{ identifier: 'https://mcp.tickets.example/', scopes: ['read'] }]
			}
		],
		...overrides
	};
}

/**
 * @proves An administrator can connect a project only to an outside authorization server that is safe to vouch
 * to, naming only the project's confidential applications that may exchange and how each is known there, and
 * can read, change and remove what they connected.
 */
describe('connecting an outside authorization server to a project', () => {
	let cookie: string;

	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'id_jag_issuing' });
		await defaultBucket();
		cookie = await adminCookie();
		await getBucketGroupStore().create(
			{
				_id: 'grp-eng',
				bucketId: DEFAULT_BUCKET_ID,
				displayName: 'Engineering'
			},
			[]
		);
	});

	it('creates a connection and reads it back, then changes and removes it', async () => {
		const created = await admin('POST', BASE, cookie, body());
		expect(created.status).toBe(201);
		const connection = shaped(Connection, created.body);
		expect(connection).toMatchObject({
			issuer: 'https://as.tickets.example',
			includeEmail: true,
			lastUsedAt: null
		});

		const listed = await admin('GET', BASE, cookie);
		expect(
			shaped(Type.Array(Connection), listed.body).map((c) => c.id)
		).toEqual([connection.id]);

		const changed = await admin('PATCH', `${BASE}/${connection.id}`, cookie, {
			displayName: 'Tickets SaaS',
			includeEmail: false
		});
		expect(shaped(Connection, changed.body)).toMatchObject({
			displayName: 'Tickets SaaS',
			includeEmail: false
		});

		const removed = await admin('DELETE', `${BASE}/${connection.id}`, cookie);
		expect(removed.status).toBe(200);
		expect(
			(await admin('GET', `${BASE}/${connection.id}`, cookie)).status
		).toBe(404);
	});

	for (const [what, issuer] of [
		["the project's own issuer", ISSUER],
		["the instance's administrative MCP endpoint", MCP_RESOURCE],
		['an address that is not https', 'http://as.plain.example'],
		['an address with a fragment', 'https://as.tickets.example/#x']
	] as const) {
		it(`refuses ${what} as the outside server`, async () => {
			const res = await admin('POST', BASE, cookie, body({ issuer }));

			expect(res.status).toBe(422);
		});
	}

	it('refuses a second connection to the same outside server', async () => {
		const issuer = 'https://as.twice.example';
		await admin('POST', BASE, cookie, body({ issuer }));

		const res = await admin('POST', BASE, cookie, body({ issuer }));

		expect(res.status).toBe(409);
	});

	it('refuses an application whose client id is not a URL without its identifier there', async () => {
		const res = await admin(
			'POST',
			BASE,
			cookie,
			body({
				issuer: 'https://as.noid.example',
				applications: [{ clientId: 'globex-agent' }]
			})
		);

		expect(res.status).toBe(422);
	});

	it('accepts an application whose client id is a URL without an identifier there', async () => {
		const res = await admin(
			'POST',
			BASE,
			cookie,
			body({
				issuer: 'https://as.url.example',
				applications: [{ clientId: 'https://agent.globex.example/client.json' }]
			})
		);

		expect(res.status).toBe(201);
	});

	for (const [what, applications] of [
		[
			'an application that does not authenticate',
			[{ clientId: 'spa', externalClientId: 'x' }]
		],
		[
			'an application without the token exchange grant',
			[{ clientId: 'tickets-sso', externalClientId: 'x' }]
		],
		[
			'an application the project does not have',
			[{ clientId: 'nobody', externalClientId: 'x' }]
		]
	] as const) {
		it(`refuses ${what}`, async () => {
			const res = await admin(
				'POST',
				BASE,
				cookie,
				body({ issuer: `https://as.${what.length}.example`, applications })
			);

			expect(res.status).toBe(422);
		});
	}

	it('refuses a rule naming a group the project does not have', async () => {
		const res = await admin(
			'POST',
			BASE,
			cookie,
			body({
				issuer: 'https://as.nogroup.example',
				rules: [
					{
						appliesTo: { groups: ['grp-missing'] },
						apis: [{ identifier: 'https://mcp.x.example/', scopes: [] }]
					}
				]
			})
		);

		expect(res.status).toBe(422);
	});

	it('refuses a rule that allows no MCP server', async () => {
		const res = await admin(
			'POST',
			BASE,
			cookie,
			body({
				issuer: 'https://as.noapi.example',
				rules: [{ appliesTo: 'everyone', apis: [] }]
			})
		);

		expect(res.status).toBe(422);
	});

	it('does not let an update change which outside server is connected', async () => {
		const created = shaped(
			Connection,
			(
				await admin(
					'POST',
					BASE,
					cookie,
					body({ issuer: 'https://as.fixed.example' })
				)
			).body
		);

		const res = await admin('PATCH', `${BASE}/${created.id}`, cookie, {
			issuer: 'https://as.moved.example'
		});

		expect(res.status).toBe(422);
	});

	it('shows a group deleted since the rule was written as a group without a name', async () => {
		await getBucketGroupStore().create(
			{
				_id: 'grp-temp',
				bucketId: DEFAULT_BUCKET_ID,
				displayName: 'Temporary'
			},
			[]
		);
		const created = shaped(
			Connection,
			(
				await admin(
					'POST',
					BASE,
					cookie,
					body({
						issuer: 'https://as.deleted-group.example',
						rules: [
							{
								appliesTo: { groups: ['grp-temp'] },
								apis: [{ identifier: 'https://mcp.x.example/', scopes: [] }]
							}
						]
					})
				)
			).body
		);
		await getBucketGroupStore().destroy('grp-temp');

		const read = shaped(
			Connection,
			(await admin('GET', `${BASE}/${created.id}`, cookie)).body
		);

		expect(read.rules[0]?.appliesTo).toEqual({
			groups: [{ id: 'grp-temp', name: null }]
		});
	});
});
