import { beforeAll, describe, expect, it } from 'bun:test';
import { createHash } from 'node:crypto';

import bootstrap from '../test_helper.js';
import { adminAuditStore } from 'lib/adapters/index.ts';
import { ADMIN_MCP_CLIENT_ID } from 'lib/mcp/consts.ts';
import { declareApi } from './api_helpers.ts';
import { excludedConsoleOperations, mcpCatalogue } from 'lib/mcp/catalogue.ts';
import { admin } from '../provisioning/helpers.ts';
import {
	agentFor,
	confirm,
	createApp,
	editor,
	tool,
	world,
	type World
} from './helpers.ts';
import {
	addressesOf,
	issueProxyKey,
	keyedCheck,
	proxyKeysPath
} from './conditions_helpers.ts';

function digest(key: string): string {
	return createHash('sha256').update(key).digest('base64url');
}

let w: World;

/**
 * @proves A project's proxy key is shown once to the administrator who issues it, never again to anyone — nor to an
 * agent, which may list and withdraw keys but not issue one — and the check accepts exactly the active keys.
 */
describe('the proxy key of a project', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
		w = await world();
	});

	describe('issued by an administrator', () => {
		it('is shown once, and a third key while two are active is refused', async () => {
			const { cookie, project } = await editor();

			const first = await admin('POST', proxyKeysPath(project.id), cookie, {});
			const second = await admin('POST', proxyKeysPath(project.id), cookie, {});
			const third = await admin('POST', proxyKeysPath(project.id), cookie, {});

			expect(first.status).toBe(201);
			expect((first.body as { key: string }).key).toMatch(
				/^fpk_[A-Za-z0-9_-]{43}$/
			);
			expect(second.status).toBe(201);
			expect(third.status).toBe(409);
			expect((third.body as { code: string }).code).toBe('proxy_key_limit');
			const listed = await admin('GET', proxyKeysPath(project.id), cookie);
			expect(listed.status).toBe(200);
			expect((listed.body as { keys: unknown[] }).keys).toHaveLength(2);
		});

		it('is returned by no view of the project, nor its digest', async () => {
			const { cookie, project } = await editor();
			const { key } = await issueProxyKey(cookie, project.id);

			const reads = await Promise.all([
				admin('GET', proxyKeysPath(project.id), cookie),
				admin('GET', `/admin/api/projects/${project.id}`, cookie),
				admin('GET', '/admin/api/projects', cookie)
			]);

			for (const reply of reads) {
				const text = JSON.stringify(reply.body);
				expect(text).not.toContain(key);
				expect(text).not.toContain(digest(key));
			}
		});
	});

	describe('presented by the proxy', () => {
		it('is accepted while active, both keys during a rotation, and not after it is withdrawn', async () => {
			const app = await createApp(w.cookie, w.acme.id, {
				rootGroups: [w.acme.staff]
			});
			const target = { slug: w.acme.slug, app };
			const old = await issueProxyKey(w.cookie, w.acme.id);
			const next = await issueProxyKey(w.cookie, w.acme.id);

			await keyedCheck(target, old.key, '203.0.113.9');
			const withOld = (await addressesOf(w.cookie, w.acme.id, app.id)).last;
			await keyedCheck(target, next.key, '203.0.113.9');
			const withNext = (await addressesOf(w.cookie, w.acme.id, app.id)).last;
			const withdrawn = await admin(
				'DELETE',
				proxyKeysPath(w.acme.id, old.id),
				w.cookie
			);
			await keyedCheck(target, old.key, '203.0.113.9');
			const afterWithdrawal = (await addressesOf(w.cookie, w.acme.id, app.id))
				.last;

			expect(withOld?.keyValid).toBe(true);
			expect(withNext?.keyValid).toBe(true);
			expect(withdrawn.status).toBe(204);
			expect(afterWithdrawal?.keyPresent).toBe(true);
			expect(afterWithdrawal?.keyValid).toBe(false);
		});
	});

	describe('to an agent', () => {
		it('issuing a key is not published, and listing and withdrawing are', () => {
			const issue = {
				method: 'POST',
				path: '/admin/api/projects/:id/proxy-keys'
			};
			const published = mcpCatalogue.filter((entry) =>
				entry.path.startsWith(issue.path)
			);

			expect(published.some((entry) => entry.method === issue.method)).toBe(
				false
			);
			expect(
				excludedConsoleOperations.some(
					(entry) =>
						entry.method === issue.method &&
						entry.path === issue.path &&
						entry.absence === 'withheld'
				)
			).toBe(true);
			expect(published.map((entry) => entry.method).sort()).toEqual([
				'DELETE',
				'GET'
			]);
		});

		it('a withdrawal through MCP is held until confirmed, and the key stays meanwhile', async () => {
			const { user, cookie, project } = await editor();
			const issued = await issueProxyKey(cookie, project.id);
			const token = await agentFor(user);

			const described = await tool(token, 'project_proxy_key_withdraw', {
				id: project.id,
				keyId: issued.id
			});

			expect(described.result?.structuredContent?.status).toBe(
				'confirmation_required'
			);
			const listed = await admin('GET', proxyKeysPath(project.id), cookie);
			expect((listed.body as { keys: unknown[] }).keys).toHaveLength(1);
			expect(JSON.stringify(described)).not.toContain(issued.key);
		});
	});
});

/**
 * @proves An agent changing the conditions of an app or an API, or the time zone they read the clock in, is held until
 * it confirms, and the change is recorded under both the agent and the person it acts for.
 */
describe('an agent setting conditions', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	it.each([
		[
			'an app’s conditions',
			'behind_proxy_app_update',
			'behindproxy.update',
			(project: { id: string; staff: string }, target: string) => ({
				id: project.id,
				appId: target,
				rules: [
					{
						path: '/',
						who: { kind: 'groups', groups: [project.staff] },
						conditions: [{ kind: 'fresh', maxAgeMinutes: 15 }]
					}
				]
			})
		],
		[
			'an app’s time zone',
			'behind_proxy_app_update',
			'behindproxy.update',
			(project: { id: string }, target: string) => ({
				id: project.id,
				appId: target,
				timeZone: 'Europe/Moscow'
			})
		],
		[
			'an API’s access',
			'resource_update',
			'resource.update',
			(project: { id: string; staff: string }, target: string) => ({
				id: project.id,
				resourceId: target,
				tools: {
					rows: [],
					otherTools: 'refuse',
					withoutMethod: 'refuse',
					access: { conditions: [{ kind: 'group', groups: [project.staff] }] }
				}
			})
		]
	] as const)(
		'a change of %s is held until confirmed, and the audit names both',
		async (_what, name, action, argsOf) => {
			const { user, cookie, project } = await editor();
			const target =
				name === 'resource_update'
					? (await declareApi(cookie, project.id, { checkedBy: 'proxy' }))
							.identifier
					: (
							await createApp(cookie, project.id, {
								rootGroups: [project.staff]
							})
						).id;
			const token = await agentFor(user);
			const args = argsOf(project, target);

			const described = await tool(token, name, args);
			const applied = await confirm(token, name, args, described);

			expect(described.result?.structuredContent?.status).toBe(
				'confirmation_required'
			);
			expect(applied.result?.isError).not.toBe(true);
			const { entries } = await adminAuditStore.list({
				actor: user._id,
				action
			});
			expect(entries.map((entry) => entry.viaClientId)).toContain(
				ADMIN_MCP_CLIENT_ID
			);
		}
	);
});
