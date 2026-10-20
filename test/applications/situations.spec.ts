import { describe, it, expect, beforeAll } from 'bun:test';
import { Elysia } from 'elysia';
import { treaty } from '@elysiajs/eden';
import bootstrap from '../test_helper.ts';
import { resolveAdmin } from 'lib/admin/auth/rbac.ts';
import { clientRoutes } from 'lib/admin/clients/routes.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { getBucketStore } from 'lib/adapters/index.ts';
import { ADMIN_SESSION_COOKIE, UNASSIGNED_GROUP_ID } from 'lib/admin/consts.ts';
import nanoid from 'lib/helpers/nanoid.ts';
import { SITUATIONS } from 'lib/admin/ui/pages/applications/situations.ts';
import { sessionFor } from '../admin_session.ts';
import { createAdministrator } from '../administrators.ts';

const app = new Elysia().use(resolveAdmin).use(clientRoutes);
const client = treaty(app);

type Stored = {
	applicationType: string;
	grantTypes: string[];
	tokenEndpointAuthMethod: string;
	redirectUris: string[];
	postLogoutRedirectUris: string[];
	corsOrigins: string[];
	hasSecret: boolean;
};

/**
 * @proves Every situation a new application can be created from fills in settings the server accepts as they are,
 * and the application it creates holds exactly the settings the situation promised.
 */
describe('creating an application from a situation', () => {
	let cookie: string;
	let projectId: string;

	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'situations' });
		await ensureAdminSeed();
		const user = await createAdministrator('super', `sit-${nanoid()}@x.io`);
		cookie = `${ADMIN_SESSION_COOKIE}=${(await sessionFor(user))._id}`;
		const id = nanoid()
			.toLowerCase()
			.replace(/[^a-z0-9]/g, '');
		projectId = (
			await getBucketStore().create({
				name: `situations ${id}`,
				slug: `sit-${id}`,
				ownerGroupId: UNASSIGNED_GROUP_ID
			})
		)._id;
	});

	for (const situation of SITUATIONS) {
		const { expand } = situation;
		if (!expand) continue;
		it(`creates "${situation.title}" for a local development address with the settings it promises`, async () => {
			const expansion = expand(situation.devAddress ?? 'http://localhost:3000');
			const applications = client.admin.api.projects({ id: projectId }).clients;

			const created = await applications.post(
				{ clientName: situation.title, ...expansion },
				{ headers: { cookie } }
			);
			expect(created.status).toBe(201);
			const { clientId } = created.data as unknown as { clientId: string };

			const read = await applications({ clientId }).get({
				headers: { cookie }
			});
			const stored = read.data as unknown as Stored;
			expect(stored.applicationType).toBe(expansion.applicationType);
			expect([...stored.grantTypes].sort()).toEqual(
				[...expansion.grantTypes].sort()
			);
			expect(stored.tokenEndpointAuthMethod).toBe(
				expansion.tokenEndpointAuthMethod
			);
			expect(stored.redirectUris).toEqual(expansion.redirectUris);
			expect(stored.postLogoutRedirectUris).toEqual(
				expansion.postLogoutRedirectUris
			);
			expect(stored.corsOrigins).toEqual(expansion.corsOrigins);
			expect(stored.hasSecret).toBe(
				expansion.tokenEndpointAuthMethod !== 'none'
			);
		});
	}
});
