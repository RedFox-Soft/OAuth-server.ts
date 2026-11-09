import { beforeAll, describe, expect, it } from 'bun:test';

import bootstrap from '../test_helper.ts';
import { elysia } from 'lib/index.ts';
import { ISSUER } from 'lib/configs/env.js';
import { getBucketStore } from 'lib/adapters/index.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { ADMIN_BUCKET_ID, ADMIN_SESSION_COOKIE } from 'lib/admin/consts.ts';
import { sessionFor } from '../admin_session.ts';
import { createAdministrator } from '../administrators.ts';

/**
 * @proves No route can make the administrators' project refuse password sign-ins from listed addresses, so the
 * shared list can never lock every administrator out of the console that would undo it.
 */
describe("the administrators' project and the attacker list", () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
		await ensureAdminSeed();
	});

	it('refuses refusing password sign-ins on the administrators project', async () => {
		const admin = await createAdministrator('super', 'guard@x.io');
		const answer = await elysia.handle(
			new Request(`${ISSUER}/admin/api/projects/${ADMIN_BUCKET_ID}`, {
				method: 'PATCH',
				headers: {
					cookie: `${ADMIN_SESSION_COOKIE}=${(await sessionFor(admin))._id}`,
					'content-type': 'application/json'
				},
				body: JSON.stringify({
					passwordGuessing: { mode: 'refuse', exempt: [] }
				})
			})
		);

		expect({
			status: answer.status,
			stored: (await getBucketStore().find(ADMIN_BUCKET_ID))?.passwordGuessing
		}).toEqual({ status: 422, stored: undefined });
	});
});
