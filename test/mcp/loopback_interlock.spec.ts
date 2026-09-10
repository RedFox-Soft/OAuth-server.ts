import {
	describe,
	it,
	expect,
	beforeAll,
	beforeEach,
	afterEach
} from 'bun:test';
import { Elysia } from 'elysia';
import { treaty } from '@elysiajs/eden';

import bootstrap from '../test_helper.js';
import { resolveAdmin } from 'lib/admin/auth/rbac.ts';
import {
	mcpClientRoutes,
	LOOPBACK_ACKNOWLEDGEMENT
} from 'lib/admin/mcp-clients/routes.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import {
	adminAuditStore,
	getUserStore,
	mcpClientPermissionStore
} from 'lib/adapters/index.ts';
import { ADMIN_BUCKET_ID, ADMIN_SESSION_COOKIE } from 'lib/admin/consts.ts';
import { clearDocumentCache } from 'lib/client_metadata_document/cache.ts';
import { resolver } from 'lib/client_metadata_document/fetch.ts';
import { serveDocument, mock } from '../cimd/document_host.js';
import { sessionFor } from '../admin_session.ts';
import { clearPermissions } from './permissions.ts';

/*
 * Granting a client identity administrative authority, and the one thing an operator has to be told
 * before they can.
 *
 * A document offering only loopback redirect targets proves control of a domain but cannot prove which
 * local process will receive the authorization code — the specification says so and calls the warning
 * a SHOULD. On this surface the consequence is administrative authority over the whole instance, so
 * the warning is an interlock rather than a notice: the route refuses until the administrator says
 * they were told, and the acknowledgement is audited with the grant.
 */

const app = new Elysia({ normalize: false })
	.use(resolveAdmin)
	.use(mcpClientRoutes);
const api = treaty(app);

const publicAddress = '93.184.216.34';

async function superAdmin() {
	const user = await getUserStore(ADMIN_BUCKET_ID).create(
		`super-${Math.random()}@x.io`,
		'hash',
		['super_admin']
	);
	const session = await sessionFor(user);
	return {
		cookie: `${ADMIN_SESSION_COOKIE}=${session._id}`,
		userId: user._id
	};
}

async function projectAdmin() {
	const user = await getUserStore(ADMIN_BUCKET_ID).create(
		`proj-${Math.random()}@x.io`,
		'hash',
		['project_admin']
	);
	const session = await sessionFor(user);
	return { cookie: `${ADMIN_SESSION_COOKIE}=${session._id}` };
}

/**
 * @proves Permitting a client identity to administer the instance is a super-admin act, is
 * refused for an unreachable or malformed document, and requires an acknowledgement for a
 * loopback-only or host-wide entry.
 */
describe('permitting a client identity through the admin API', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'mcp' });
	});

	beforeEach(async () => {
		await ensureAdminSeed();
		await clearPermissions();
		clearDocumentCache();
		resolver.lookup = async () => [publicAddress];
	});

	afterEach(() => {
		mock.restore();
		resolver.lookup = resolver.realLookup;
	});

	it('refuses anyone who is not a super administrator', async () => {
		const { cookie } = await projectAdmin();

		const res = await api.admin.api.mcp.clients.get({ headers: { cookie } });

		expect(res.status).toBe(403);
	});

	it('permits an identity whose document offers a real redirect target', async () => {
		const { cookie } = await superAdmin();
		const { identifier } = serveDocument({
			overrides: { redirect_uris: ['https://app.example.com/callback'] }
		});

		const res = await api.admin.api.mcp.clients.post(
			{ kind: 'identifier', value: identifier },
			{ headers: { cookie } }
		);

		expect(res.status).toBe(201);
		expect(
			(res.data as { loopbackAcknowledged?: boolean }).loopbackAcknowledged
		).toBe(false);
	});

	/*
	 * The interlock. The refusal carries the same words the console shows as the acknowledgement, so
	 * what the administrator agreed to and what the route enforced cannot be two different statements.
	 */
	it('refuses a loopback-only identity until the risk is acknowledged', async () => {
		const { cookie } = await superAdmin();
		const { identifier } = serveDocument({
			overrides: { redirect_uris: ['http://127.0.0.1:33418/callback'] }
		});

		const res = await api.admin.api.mcp.clients.post(
			{ kind: 'identifier', value: identifier },
			{ headers: { cookie } }
		);

		expect(res.status).toBe(409);
		expect((res.error?.value as { message?: string })?.message).toBe(
			LOOPBACK_ACKNOWLEDGEMENT
		);
		expect(await mcpClientPermissionStore.list()).toEqual([]);
	});

	it('permits it once acknowledged, and records who acknowledged', async () => {
		const { cookie, userId } = await superAdmin();
		const { identifier } = serveDocument({
			overrides: { redirect_uris: ['http://127.0.0.1:33418/callback'] }
		});

		const res = await api.admin.api.mcp.clients.post(
			{
				kind: 'identifier',
				value: identifier,
				acknowledgeLoopbackRisk: true
			},
			{ headers: { cookie } }
		);

		expect(res.status).toBe(201);
		const stored = await mcpClientPermissionStore.find(identifier);
		expect(stored?.loopbackAcknowledged).toBe(true);
		expect(stored?.acknowledgedBy).toBe(userId);

		const entries = await adminAuditStore.list({
			action: 'mcp.client.permit',
			limit: 10
		});
		expect(
			entries.entries.some(
				(e) => e.actorId === userId && e.targetId === identifier
			)
		).toBe(true);
	});

	/*
	 * An entry whose risk profile could not be established is refused rather than granted on trust.
	 * Permitting one would mean nobody had accepted anything in particular.
	 */
	it('refuses an identity whose document cannot be retrieved', async () => {
		const { cookie } = await superAdmin();
		mock('https://app.example.com');

		const res = await api.admin.api.mcp.clients.post(
			{
				kind: 'identifier',
				value: 'https://app.example.com/missing.json'
			},
			{ headers: { cookie } }
		);

		expect(res.status).toBe(400);
	});

	/*
	 * A host entry covers documents that do not exist yet, so its risk is unknowable in advance —
	 * always acknowledged, never inferred.
	 */
	it('always requires the acknowledgement for a host-wide entry', async () => {
		const { cookie } = await superAdmin();

		const refused = await api.admin.api.mcp.clients.post(
			{ kind: 'host', value: 'agent.example.com' },
			{ headers: { cookie } }
		);
		expect(refused.status).toBe(409);

		const accepted = await api.admin.api.mcp.clients.post(
			{
				kind: 'host',
				value: 'agent.example.com',
				acknowledgeLoopbackRisk: true
			},
			{ headers: { cookie } }
		);
		expect(accepted.status).toBe(201);
	});

	it('refuses a malformed identifier or host', async () => {
		const { cookie } = await superAdmin();

		for (const body of [
			{ kind: 'identifier' as const, value: 'http://app.example.com/c.json' },
			{ kind: 'identifier' as const, value: 'https://app.example.com' },
			{ kind: 'host' as const, value: 'https://agent.example.com/' },
			{ kind: 'host' as const, value: 'agent' }
		]) {
			const res = await api.admin.api.mcp.clients.post(body, {
				headers: { cookie }
			});
			expect(res.status, JSON.stringify(body)).toBe(400);
		}
	});

	it('withdraws a permission and audits it', async () => {
		const { cookie, userId } = await superAdmin();
		await mcpClientPermissionStore.create({
			kind: 'host',
			_id: 'agent.example.com'
		});

		const res = await api.admin.api.mcp
			.clients({ entryId: encodeURIComponent('agent.example.com') })
			.delete(undefined, { headers: { cookie } });

		expect(res.status).toBe(204);
		expect(await mcpClientPermissionStore.list()).toEqual([]);
		const entries = await adminAuditStore.list({
			action: 'mcp.client.withdraw',
			limit: 10
		});
		expect(entries.entries.some((e) => e.actorId === userId)).toBe(true);
	});
});
