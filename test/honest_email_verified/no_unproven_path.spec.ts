import { describe, it, expect, beforeAll } from 'bun:test';
import bootstrap from '../test_helper.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { getUserStore } from 'lib/adapters/index.ts';
import { call, superAdmin, type Caller } from '../plans/admin.ts';
import { projectFor, signUp } from './sign_up.ts';

const projects: Record<'off' | 'on', { clientId: string; id: string }> = {
	off: { clientId: 'honest-off-app', id: '' },
	on: { clientId: 'honest-on-app', id: '' }
};
let operator: Caller;

/**
 * @proves No way of creating an end user that does not prove the address records it as verified: signing oneself up
 * and being created by an administrator both leave it unverified, whether or not the project requires verification.
 */
describe('a new end user’s address', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'honest_email_verified' });
		await ensureAdminSeed();
		projects.off.id = await projectFor(projects.off.clientId, false);
		projects.on.id = await projectFor(projects.on.clientId, true);
		operator = await superAdmin();
	});

	for (const setting of ['off', 'on'] as const) {
		describe(`in a project with verification ${setting}`, () => {
			it('is not verified after signing up', async () => {
				const email = `self-${setting}-${Date.now()}@honest.test`;

				await signUp(projects[setting].clientId, email);

				const user = await getUserStore(projects[setting].id).findByEmail(
					email
				);
				expect(user?.verified).toBe(false);
			});

			it('is not verified when an administrator creates the person', async () => {
				const created = await call(
					'POST',
					`/admin/api/projects/${projects[setting].id}/users`,
					operator.cookie,
					{
						email: `made-${setting}-${Date.now()}@honest.test`,
						password: 'an-administrator-chose-it'
					}
				);

				expect(created.status).toBe(201);
				expect((created.body as { verified: boolean }).verified).toBe(false);
			});
		});
	}
});
