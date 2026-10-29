import { beforeAll, describe, expect, it } from 'bun:test';
import { Elysia } from 'elysia';

import bootstrap from '../test_helper.ts';
import { sessionFor } from '../admin_session.ts';
import { createAdministrator } from '../administrators.ts';
import { resolveAdmin } from 'lib/admin/auth/rbac.ts';
import { keyringRoutes } from 'lib/admin/keyring/routes.ts';
import { ADMIN_SESSION_COOKIE } from 'lib/admin/consts.ts';

const app = new Elysia().use(resolveAdmin).use(keyringRoutes);

/**
 * @proves The encryption status is instance-wide, so only a super administrator reads it.
 */
describe('the encryption status', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	it('the keyring status is refused to an administrator who is not a super administrator', async () => {
		const user = await createAdministrator(
			'plain',
			`plain-${Math.random()}@x.io`
		);
		const cookie = `${ADMIN_SESSION_COOKIE}=${(await sessionFor(user))._id}`;

		const response = await app.handle(
			new Request('http://localhost/admin/api/keyring', { headers: { cookie } })
		);

		expect(response.status).toBe(403);
	});
});
