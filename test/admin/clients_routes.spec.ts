import { describe, it, expect, beforeEach } from 'bun:test';
import { Elysia } from 'elysia';
import { treaty } from '@elysiajs/eden';
import { resolveAdmin } from 'lib/admin/auth/rbac.ts';
import { projectRoutes } from 'lib/admin/projects/routes.ts';
import { clientRoutes } from 'lib/admin/clients/routes.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import {
	adminSessionStore,
	getUserStore,
	getProjectStore
} from 'lib/adapters/index.ts';
import {
	ADMIN_BUCKET_ID,
	ADMIN_PROJECT_ID,
	ADMIN_CLIENT_ID,
	ADMIN_SESSION_COOKIE
} from 'lib/admin/consts.ts';

const app = new Elysia().use(resolveAdmin).use(projectRoutes).use(clientRoutes);
const client = treaty(app);

async function sessionCookieFor(roles: string[]) {
	const user = await getUserStore(ADMIN_BUCKET_ID).create(
		`${roles.join('-')}-${Math.random()}@x.io`,
		'hash',
		roles
	);
	const s = await adminSessionStore.create({
		userId: user._id,
		bucketId: ADMIN_BUCKET_ID,
		tokens: {},
		ttlSeconds: 60,
		absoluteTtlSeconds: 3600
	});
	return { cookie: `${ADMIN_SESSION_COOKIE}=${s._id}`, userId: user._id };
}

async function makeProject(managedBy: string[] = []) {
	return getProjectStore().create({
		name: 'P',
		slug: `p-${Math.random()}`,
		managedBy
	});
}

describe('clients API', () => {
	beforeEach(async () => {
		await ensureAdminSeed();
	});

	it('rejects anonymous access', async () => {
		const proj = await makeProject();
		const res = await client.admin.api
			.projects({ id: proj._id })
			.clients.get();
		expect(res.status).toBe(401);
	});

	it('creates, lists, and links a client to the project', async () => {
		const { cookie } = await sessionCookieFor(['super_admin']);
		const proj = await makeProject();
		const created = await client.admin.api
			.projects({ id: proj._id })
			.clients.post(
				{
					clientName: 'SPA',
					grantTypes: ['authorization_code'],
					redirectUris: ['https://a.example.com/cb'],
					tokenEndpointAuthMethod: 'none'
				},
				{ headers: { cookie } }
			);
		expect(created.status).toBe(201);
		const body = created.data as { clientId: string; secret?: string };
		expect(body.clientId).toBeTruthy();
		expect(body.secret).toBeUndefined(); // public client
		const reloaded = await getProjectStore().find(proj._id);
		expect(reloaded?.clientIds).toContain(body.clientId);
		const list = await client.admin.api
			.projects({ id: proj._id })
			.clients.get({ headers: { cookie } });
		const clients = list.data as Array<{ clientId: string }>;
		expect(clients.some((c) => c.clientId === body.clientId)).toBe(true);
	});

	it('returns a confidential secret once on create, never on GET', async () => {
		const { cookie } = await sessionCookieFor(['super_admin']);
		const proj = await makeProject();
		const created = await client.admin.api
			.projects({ id: proj._id })
			.clients.post(
				{
					grantTypes: ['client_credentials'],
					tokenEndpointAuthMethod: 'client_secret_basic'
				},
				{ headers: { cookie } }
			);
		const body = created.data as { clientId: string; secret?: string };
		expect(body.secret).toBeTruthy();
		const one = await client.admin.api
			.projects({ id: proj._id })
			.clients({ clientId: body.clientId })
			.get({ headers: { cookie } });
		expect((one.data as Record<string, unknown>).secret).toBeUndefined();
		expect((one.data as Record<string, unknown>).clientSecret).toBeUndefined();
	});

	it('maps invalid client metadata to 422', async () => {
		const { cookie } = await sessionCookieFor(['super_admin']);
		const proj = await makeProject();
		// authorization_code with no redirect_uris is invalid
		const res = await client.admin.api
			.projects({ id: proj._id })
			.clients.post(
				{ grantTypes: ['authorization_code'], tokenEndpointAuthMethod: 'none' },
				{ headers: { cookie } }
			);
		expect(res.status).toBe(422);
	});

	it('scopes project_admin to managed projects and 404s cross-project reads', async () => {
		const su = await sessionCookieFor(['super_admin']);
		const pa = await sessionCookieFor(['project_admin']);
		const mine = await makeProject([pa.userId]);
		const other = await makeProject();
		// create a client in `other` as super_admin
		const created = await client.admin.api
			.projects({ id: other._id })
			.clients.post(
				{
					grantTypes: ['authorization_code'],
					redirectUris: ['https://x.example.com/cb'],
					tokenEndpointAuthMethod: 'none'
				},
				{ headers: { cookie: su.cookie } }
			);
		const otherClientId = (created.data as { clientId: string }).clientId;
		// project_admin cannot list `other`
		const denied = await client.admin.api
			.projects({ id: other._id })
			.clients.get({ headers: { cookie: pa.cookie } });
		expect(denied.status).toBe(403);
		// even via a project they DO manage, the foreign clientId 404s
		const wrong = await client.admin.api
			.projects({ id: mine._id })
			.clients({ clientId: otherClientId })
			.get({ headers: { cookie: pa.cookie } });
		expect(wrong.status).toBe(404);
	});

	it('refuses to manage the reserved admin-panel client', async () => {
		const { cookie } = await sessionCookieFor(['super_admin']);
		const res = await client.admin.api
			.projects({ id: ADMIN_PROJECT_ID })
			.clients({ clientId: ADMIN_CLIENT_ID })
			.delete(undefined, { headers: { cookie } });
		expect(res.status === 403 || res.status === 404).toBe(true);
	});

	it('deletes a client and unlinks it from the project', async () => {
		const { cookie } = await sessionCookieFor(['super_admin']);
		const proj = await makeProject();
		const created = await client.admin.api
			.projects({ id: proj._id })
			.clients.post(
				{
					grantTypes: ['authorization_code'],
					redirectUris: ['https://d.example.com/cb'],
					tokenEndpointAuthMethod: 'none'
				},
				{ headers: { cookie } }
			);
		const id = (created.data as { clientId: string }).clientId;
		const del = await client.admin.api
			.projects({ id: proj._id })
			.clients({ clientId: id })
			.delete(undefined, { headers: { cookie } });
		expect(del.status).toBe(200);
		const reloaded = await getProjectStore().find(proj._id);
		expect(reloaded?.clientIds).not.toContain(id);
	});

	it('updates a client via PATCH', async () => {
		const { cookie } = await sessionCookieFor(['super_admin']);
		const proj = await makeProject();
		const created = await client.admin.api
			.projects({ id: proj._id })
			.clients.post(
				{
					grantTypes: ['authorization_code'],
					redirectUris: ['https://before.example.com/cb'],
					tokenEndpointAuthMethod: 'none'
				},
				{ headers: { cookie } }
			);
		const id = (created.data as { clientId: string }).clientId;
		const patched = await client.admin.api
			.projects({ id: proj._id })
			.clients({ clientId: id })
			.patch(
				{ redirectUris: ['https://updated.example.com/cb'] },
				{ headers: { cookie } }
			);
		expect(patched.status).toBe(200);
		const reloaded = await client.admin.api
			.projects({ id: proj._id })
			.clients({ clientId: id })
			.get({ headers: { cookie } });
		expect((reloaded.data as { redirectUris: string[] }).redirectUris).toEqual([
			'https://updated.example.com/cb'
		]);
	});

	it('rotates a confidential client secret; 400s for a public client', async () => {
		const { cookie } = await sessionCookieFor(['super_admin']);
		const proj = await makeProject();
		const confidential = await client.admin.api
			.projects({ id: proj._id })
			.clients.post(
				{
					grantTypes: ['client_credentials'],
					tokenEndpointAuthMethod: 'client_secret_basic'
				},
				{ headers: { cookie } }
			);
		const confidentialId = (confidential.data as { clientId: string }).clientId;
		const rotated = await client.admin.api
			.projects({ id: proj._id })
			.clients({ clientId: confidentialId })
			.secret.post(undefined, { headers: { cookie } });
		expect(rotated.status).toBe(200);
		expect((rotated.data as { secret: string }).secret).toBeTruthy();

		const pub = await client.admin.api
			.projects({ id: proj._id })
			.clients.post(
				{
					grantTypes: ['authorization_code'],
					redirectUris: ['https://pub.example.com/cb'],
					tokenEndpointAuthMethod: 'none'
				},
				{ headers: { cookie } }
			);
		const pubId = (pub.data as { clientId: string }).clientId;
		const pubRotate = await client.admin.api
			.projects({ id: proj._id })
			.clients({ clientId: pubId })
			.secret.post(undefined, { headers: { cookie } });
		expect(pubRotate.status).toBe(400);
	});

	it('404s cross-project ownership even for super_admin', async () => {
		const { cookie } = await sessionCookieFor(['super_admin']);
		const projA = await makeProject();
		const projB = await makeProject();
		const created = await client.admin.api
			.projects({ id: projA._id })
			.clients.post(
				{
					grantTypes: ['authorization_code'],
					redirectUris: ['https://a-owned.example.com/cb'],
					tokenEndpointAuthMethod: 'none'
				},
				{ headers: { cookie } }
			);
		const clientId = (created.data as { clientId: string }).clientId;
		const crossProject = await client.admin.api
			.projects({ id: projB._id })
			.clients({ clientId })
			.get({ headers: { cookie } });
		expect(crossProject.status).toBe(404);
	});
});
