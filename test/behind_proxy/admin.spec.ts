import { beforeAll, describe, expect, it } from 'bun:test';
import { Type } from '@sinclair/typebox';

import bootstrap from '../test_helper.js';
import { elysia } from 'lib/index.ts';
import { ISSUER } from 'lib/configs/env.js';
import { adminAuditStore } from 'lib/adapters/index.ts';
import { ADMIN_BUCKET_ID } from 'lib/admin/consts.ts';
import { ADMIN_MCP_CLIENT_ID } from 'lib/mcp/consts.ts';
import { createAdministrator } from '../administrators.ts';
import { admin } from '../provisioning/helpers.ts';
import { shaped } from '../shape.ts';
import {
	AppView,
	agentFor,
	behindProxyPath,
	confirm,
	createApp,
	editor,
	freshAddress,
	readApp,
	tool,
	world,
	type World
} from './helpers.ts';

const AppList = Type.Object({ apps: Type.Array(AppView) });

/**
 * @proves An app behind a proxy is declared only with a group for its root and never in the administrators'
 * project, and an agent declares and changes one as an administrator does in the console — recorded under both,
 * and a change of who may open it held until the agent confirms it.
 */
describe('declaring an app behind a proxy', () => {
	let w: World;

	beforeAll(async () => {
		await bootstrap(import.meta.url);
		w = await world();
	});

	describe('the create route', () => {
		it('an app with no group for its root is not created', async () => {
			const address = freshAddress();

			const res = await admin('POST', behindProxyPath(w.acme.id), w.cookie, {
				name: 'Dashboards',
				address,
				proxyKind: 'caddy',
				rootGroups: []
			});

			expect(res.status).toBe(422);
			const listed = await admin('GET', behindProxyPath(w.acme.id), w.cookie);
			expect(
				shaped(AppList, listed.body).apps.map((app) => app.address)
			).not.toContain(address);
		});
	});

	describe("the administrators' project", () => {
		it('creating an app there is refused, and its implicit client does not exist', async () => {
			const res = await admin(
				'POST',
				behindProxyPath(ADMIN_BUCKET_ID),
				w.cookie,
				{
					name: 'Console tools',
					address: freshAddress(),
					proxyKind: 'caddy',
					rootGroups: ['any-group']
				}
			);

			expect(res.status).toBe(403);
			const authorize = await elysia.handle(
				new Request(
					`${ISSUER}/auth?${new URLSearchParams({
						client_id: `proxy.${ADMIN_BUCKET_ID}`,
						response_type: 'code',
						scope: 'openid email',
						redirect_uri: 'https://tools.example.com/_foxauth/callback',
						state: 's',
						code_challenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
						code_challenge_method: 'S256'
					}).toString()}`,
					{ redirect: 'manual' }
				)
			);
			expect(authorize.status).toBe(400);
			expect(await authorize.json()).toMatchObject({ error: 'invalid_client' });
		});
	});

	describe('an agent acting for an editor of the project', () => {
		it('creating an app through MCP succeeds and the audit names both', async () => {
			const { user, project } = await editor();
			const token = await agentFor(user);
			const args = {
				id: project.id,
				name: 'Metrics',
				address: freshAddress(),
				proxyKind: 'traefik',
				rootGroups: [project.staff]
			};

			const described = await tool(token, 'behind_proxy_app_create', args);
			const applied = await confirm(
				token,
				'behind_proxy_app_create',
				args,
				described
			);

			expect(applied.result?.isError).not.toBe(true);
			const { entries } = await adminAuditStore.list({
				actor: user._id,
				action: 'behindproxy.create'
			});
			expect(entries.map((entry) => entry.viaClientId)).toContain(
				ADMIN_MCP_CLIENT_ID
			);
		});
	});

	describe('an agent', () => {
		it('a rules change through MCP is held until confirmed in a second call', async () => {
			const app = await createApp(w.cookie, w.acme.id, {
				rootGroups: [w.acme.staff]
			});
			const token = await agentFor(await createAdministrator('super'));
			const args = {
				id: w.acme.id,
				appId: app.id,
				rules: [
					{ path: '/', who: { kind: 'groups', groups: [w.acme.staff] } },
					{ path: '/health', who: { kind: 'public', subtree: false } }
				]
			};

			const described = await tool(token, 'behind_proxy_app_update', args);

			expect(described.result?.structuredContent?.status).toBe(
				'confirmation_required'
			);
			expect(
				(await readApp(w.cookie, w.acme.id, app.id)).rules.map((r) => r.path)
			).toEqual(['/']);
			await confirm(token, 'behind_proxy_app_update', args, described);
			expect(
				(await readApp(w.cookie, w.acme.id, app.id)).rules.map((r) => r.path)
			).toEqual(['/', '/health']);
		});
	});
});
