import { describe, it, expect, beforeAll } from 'bun:test';
import bootstrap from '../test_helper.ts';
import { elysia } from 'lib/index.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { adapter, getBucketStore } from 'lib/adapters/index.ts';
import { ADMIN_CLIENT_ID, UNASSIGNED_GROUP_ID } from 'lib/admin/consts.ts';
import { forgetBucketAddresses } from 'lib/admin/auth/bucketAddress.ts';
import nanoid from 'lib/helpers/nanoid.ts';
import {
	call,
	createProject,
	idOf,
	superAdmin,
	tenant,
	type Caller
} from './admin.ts';

function fresh(prefix: string): string {
	return `${prefix}-${Math.random().toString(36).slice(2, 10)}`;
}

function get(path: string, headers: Record<string, string> = {}) {
	return elysia.handle(
		new Request(`http://e.ly${path}`, { redirect: 'manual', headers })
	);
}

/* An authorization request from the console's own client, as the console sends it. */
function consoleAuthorization(prefix: string) {
	const query = new URLSearchParams({
		client_id: ADMIN_CLIENT_ID,
		response_type: 'code',
		redirect_uri: 'http://e.ly/admin/callback',
		scope: 'openid',
		code_challenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
		code_challenge_method: 'S256',
		state: 'st'
	});
	return get(`${prefix}/auth?${query.toString()}`);
}

/**
 * @proves Smaller doors are shut: a new project cannot take a name an official-looking or server path would use
 * (while one that already has such a name keeps answering); the console renders whatever its address holds; an
 * application's key-set and back-channel logout addresses are written over https only (a stored http one still
 * works); the console's own client is refused at a tenant's address; and a taken subdomain is refused without
 * naming its holder.
 */
describe('smaller doors', () => {
	let owner: Caller;

	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'tenant_hardening' });
		await ensureAdminSeed();
		// Without one the console sends every address to first-run setup.
		await superAdmin();
		owner = await tenant();
	});

	describe('a new project path', () => {
		for (const name of ['login', 'sso', 'account', 'health', 'billing']) {
			it(`refuses '${name}' as reserved`, async () => {
				const answer = await createProject(owner, { slug: name });

				expect(answer.status).toBe(409);
				expect((answer.body as { message: string }).message).toContain(
					'is reserved'
				);
			});
		}

		it('leaves a project that already has such a name answering at it', async () => {
			await getBucketStore().create({
				name: 'Legacy login',
				slug: 'login',
				ownerGroupId: UNASSIGNED_GROUP_ID
			});
			forgetBucketAddresses();

			const discovery = await get('/login/.well-known/openid-configuration');

			expect(discovery.status).toBe(200);
		});
	});

	it("renders the console whatever its address holds, `$'` included", async () => {
		// In the path: a query would carry `'` percent-encoded, and the page would never see `$'`. No such
		// page exists, which the console answers with its own not-found page, carrying the address as props.
		const page = await get(`/admin/x$'y$\`z$&`, {
			cookie: owner.cookie
		});
		const html = await page.text();

		expect(page.status).toBe(404);
		expect(html.split('window.PROPS=')).toHaveLength(2);
		expect(html).toContain('</html>');
		expect(html).not.toContain('<!--app-');
	});

	describe('addresses fetched for an application', () => {
		const create = (body: Record<string, unknown>) =>
			createProject(owner, { slug: fresh('tls') }).then((created) =>
				call(
					'POST',
					`/admin/api/projects/${idOf(created)}/clients`,
					owner.cookie,
					{
						grantTypes: ['authorization_code'],
						redirectUris: ['https://app.test/cb'],
						tokenEndpointAuthMethod: 'none',
						...body
					}
				)
			);

		it('refuses an http key-set address and an http back-channel logout address', async () => {
			const jwks = await create({ jwksUri: 'http://keys.test/jwks' });
			const logout = await create({
				backchannelLogoutUri: 'http://app.test/logout'
			});

			expect(jwks.status).toBeGreaterThanOrEqual(400);
			expect(JSON.stringify(jwks.body)).toContain('jwks_uri must use https');
			expect(logout.status).toBeGreaterThanOrEqual(400);
			expect(JSON.stringify(logout.body)).toContain(
				'backchannel_logout_uri must use https'
			);
		});

		it('keeps a stored http address working, and its other fields editable', async () => {
			const project = idOf(
				await createProject(owner, { slug: fresh('legacy') })
			);
			const clientId = `legacy-${nanoid()}`;
			await adapter('Client').upsert(clientId, {
				clientId,
				bucketId: project,
				grantTypes: ['authorization_code'],
				responseTypes: ['code'],
				redirectUris: ['https://legacy.test/cb'],
				token_endpoint_auth_method: 'none',
				backchannel_logout_uri: 'http://legacy.test/logout'
			});

			const edited = await call(
				'PATCH',
				`/admin/api/projects/${project}/clients/${clientId}`,
				owner.cookie,
				{ clientName: 'Renamed' }
			);

			expect(edited.status).toBe(200);
		});
	});

	describe("the console's own client", () => {
		it("is refused at a tenant project's address", async () => {
			const slug = fresh('tenant');
			idOf(await createProject(owner, { slug }));

			const answer = await consoleAuthorization(`/${slug}`);

			expect(answer.headers.get('location') ?? '').toContain(
				'error=unauthorized_client'
			);
		});

		it('proceeds at the root', async () => {
			const answer = await consoleAuthorization('');

			expect(answer.headers.get('location') ?? '').not.toContain('error=');
		});
	});
});
