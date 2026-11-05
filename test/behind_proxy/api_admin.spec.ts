import { beforeAll, describe, expect, it } from 'bun:test';

import bootstrap from '../test_helper.js';
import { adminAuditStore, getBucketStore } from 'lib/adapters/index.ts';
import { UNASSIGNED_GROUP_ID } from 'lib/admin/consts.ts';
import { forgetBucketAddresses } from 'lib/admin/auth/bucketAddress.ts';
import nanoid from 'lib/helpers/nanoid.ts';
import { ADMIN_MCP_CLIENT_ID } from 'lib/mcp/consts.ts';
import { admin } from '../provisioning/helpers.ts';
import { shaped } from '../shape.ts';
import {
	agentFor,
	confirm,
	editor,
	tool,
	world,
	type World
} from './helpers.ts';
import {
	ApiView,
	apiCheck,
	apiCheckUrl,
	bearer,
	changeApi,
	declareApi,
	jwtFor,
	resourcesPath
} from './api_helpers.ts';
import { TABLE } from './api_decision_table.ts';

async function readApi(cookie: string, bucketId: string, identifier: string) {
	return shaped(
		ApiView,
		(await admin('GET', resourcesPath(bucketId, identifier), cookie)).body
	);
}

/**
 * @proves An API's tools table and who checks its tokens are set through the same route an administrator uses,
 * and an agent changing either is held until it confirms, with the change recorded under both.
 */
describe('setting who checks an API’s tokens, and its tools', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	describe('an agent acting for an editor of the project', () => {
		it.each([
			['the tools table', { tools: TABLE }],
			['who checks its tokens', { checkedBy: 'proxy' }]
		])(
			'a change of %s through MCP is held until confirmed, and the audit names both',
			async (_what, change) => {
				const { user, cookie, project } = await editor();
				const api = await declareApi(cookie, project.id);
				const token = await agentFor(user);
				const args = {
					id: project.id,
					resourceId: api.identifier,
					...change
				};

				const described = await tool(token, 'resource_update', args);

				expect(described.result?.structuredContent?.status).toBe(
					'confirmation_required'
				);
				const held = await readApi(cookie, project.id, api.identifier);
				expect(held.checkedBy).toBe('server');
				expect('tools' in held).toBe(false);

				const applied = await confirm(
					token,
					'resource_update',
					args,
					described
				);

				expect(applied.result?.isError).not.toBe(true);
				const after = await readApi(cookie, project.id, api.identifier);
				expect(after).toMatchObject(change);
				const { entries } = await adminAuditStore.list({
					actor: user._id,
					action: 'resource.update'
				});
				expect(entries.map((entry) => entry.viaClientId)).toContain(
					ADMIN_MCP_CLIENT_ID
				);
			}
		);
	});

	describe('the update route', () => {
		let w: World;

		beforeAll(async () => {
			w = await world();
		});

		const row = (name: string, scopes: string[]) => ({ name, scopes });

		it.each([
			['a scope the API does not have', [row('search_files', ['mail:read'])]],
			[
				'two rows with one name',
				[
					row('search_files', ['files:read']),
					row('search_files', ['files:write'])
				]
			],
			['a row with no scope', [row('search_files', [])]],
			[
				'a scope twice in one row',
				[row('search_files', ['files:read', 'files:read'])]
			],
			[
				'more than 200 rows',
				Array.from({ length: 201 }, (_, i) =>
					row(`tool_${String(i)}`, ['files:read'])
				)
			],
			['an empty name', [row('', ['files:read'])]],
			[
				'a name longer than 128 characters',
				[row('t'.repeat(129), ['files:read'])]
			],
			[
				'a name with a control character',
				[row('search\u0007files', ['files:read'])]
			],
			[
				'a name with surrounding whitespace',
				[row(' search_files', ['files:read'])]
			]
		])('a table with %s is not saved', async (_what, rows) => {
			const api = await declareApi(w.cookie, w.acme.id, { checkedBy: 'proxy' });

			const res = await admin(
				'PATCH',
				resourcesPath(w.acme.id, api.identifier),
				w.cookie,
				{ tools: { rows, otherTools: 'refuse', withoutMethod: 'refuse' } }
			);

			expect([400, 422]).toContain(res.status);
			expect(
				'tools' in (await readApi(w.cookie, w.acme.id, api.identifier))
			).toBe(false);
		});

		it('removing a scope a tool needs is refused, naming the tool', async () => {
			const api = await declareApi(w.cookie, w.acme.id, {
				checkedBy: 'proxy',
				tools: TABLE
			});

			const res = await admin(
				'PATCH',
				resourcesPath(w.acme.id, api.identifier),
				w.cookie,
				{ scopes: ['files:read', 'files:write'] }
			);

			expect(res.status).toBe(400);
			expect(JSON.stringify(res.body)).toContain('delete_file');
			expect(
				(await readApi(w.cookie, w.acme.id, api.identifier)).scopes
			).toContain('files:delete');
		});

		it('a token issued while its server checked it is allowed after the switch to the proxy, and refused as unknown after switching back', async () => {
			const api = await declareApi(w.cookie, w.acme.id);
			const token = await jwtFor(api);
			const send = () =>
				apiCheck({
					slug: w.acme.slug,
					identifier: api.identifier,
					authorization: bearer(token),
					mcpMethod: 'tools/list'
				});

			await changeApi(w.cookie, w.acme.id, api.identifier, {
				checkedBy: 'proxy'
			});
			const allowed = await send();
			await changeApi(w.cookie, w.acme.id, api.identifier, {
				checkedBy: 'server'
			});
			const unknown = await send();

			expect(allowed.status).toBe(200);
			expect(unknown.status).toBe(403);
			expect(unknown.headers.get('x-auth-reason')).toBe('not_found');
		});

		it('the view of an API its proxy checks names the check and the metadata the project serves', async () => {
			const api = await declareApi(w.cookie, w.acme.id, { checkedBy: 'proxy' });
			const check = apiCheckUrl(w.acme.slug, api.identifier);

			expect(api.connection.check).toEqual({
				verifyUrl: check,
				metadataUrl: `${check}/metadata`
			});
			expect(api.connection.metadataUrl).toBe(`${check}/metadata`);
			expect(api.connection.challenge).toBe(
				`Bearer resource_metadata="${check}/metadata"`
			);
		});

		it.each([
			[
				'an identifier that is not an https address',
				'urn:example:files',
				false
			],
			['a project with no address of its own', undefined, true]
		])(
			'handing the checks to the proxy is refused for %s',
			async (_what, identifier, legacy) => {
				const bucketId = legacy ? await legacyProject() : w.acme.id;
				const api = await declareApi(w.cookie, bucketId, {
					...(identifier ? { identifier } : {})
				});

				const res = await admin(
					'PATCH',
					resourcesPath(bucketId, api.identifier),
					w.cookie,
					{ checkedBy: 'proxy' }
				);

				expect(res.status).toBe(400);
				expect(
					(await readApi(w.cookie, bucketId, api.identifier)).checkedBy
				).toBe('server');
			}
		);
	});
});

/* A project recorded before every project had an address: served at the root, with no check address of its own. */
async function legacyProject(): Promise<string> {
	const id = `legacy-${nanoid()
		.toLowerCase()
		.replace(/[^a-z0-9]/g, '')}`;
	await getBucketStore().create({
		_id: id,
		name: 'Legacy people',
		ownerGroupId: UNASSIGNED_GROUP_ID
	});
	forgetBucketAddresses();
	return id;
}
