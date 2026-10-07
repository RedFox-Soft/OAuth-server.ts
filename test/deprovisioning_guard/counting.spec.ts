import { describe, it, beforeAll, expect } from 'bun:test';
import { Type } from '@sinclair/typebox';

import { admin } from '../provisioning/helpers.ts';
import { present, shaped } from '../shape.ts';
import bootstrap from '../test_helper.js';
import {
	deactivate,
	guarded,
	HOUR,
	plainAdministrator,
	provision,
	release,
	scim,
	setThreshold,
	scimUser,
	storedUser,
	tripped,
	viewOf,
	type Guarded
} from './helpers.ts';

/* A connection allowed one deprovisioning an hour: whether something counted shows in the next one. */
const ONE = { count: 1, windowSeconds: HOUR };

function usersPath(g: Guarded, uid = ''): string {
	return `/admin/api/buckets/${g.bucket._id}/users${uid ? `/${uid}` : ''}`;
}

/**
 * @proves Only a directory's deprovisioning counts toward its connection's threshold — never an assertion of
 * what is already so, a request for nobody, or an administrator's own act — and the threshold is exact:
 * however many deprovisionings arrive together, no more than the threshold are accepted, and only the
 * bucket's administrators can release the hold (spec 072, User Story 4, scenarios 7–9; FR-018, FR-019, FR-023).
 */
describe('what counts toward a mass-deprovisioning threshold', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	it('deprovisions without limit through a connection with no threshold', async () => {
		const g = await guarded();
		const ids = await provision(g, 8);

		const statuses = [];
		for (const id of ids) statuses.push((await deactivate(g, id)).status);

		expect(statuses.every((s) => s === 200)).toBe(true);
		expect((await viewOf(g)).hold).toBeUndefined();
	});

	it('does not count deactivating a user who is already inactive', async () => {
		const g = await guarded();
		const created = await scim('POST', `${g.base}/Users`, {
			token: g.token,
			body: scimUser('dormant@contoso.com', { active: false })
		});
		const dormant = shaped(Type.Object({ id: Type.String() }), created.json).id;
		const [active] = await provision(g, 1);
		expect((await setThreshold(g, ONE)).status).toBe(200);
		expect((await deactivate(g, dormant)).status).toBe(200);

		const res = await deactivate(g, present(active, 'an active user'));

		expect(res.status).toBe(200);
	});

	it('does not count deleting a user who does not exist', async () => {
		const g = await guarded(ONE);
		const [active] = await provision(g, 1);
		const unknown = await scim('DELETE', `${g.base}/Users/nobody-here`, {
			token: g.token
		});
		expect(unknown.status).toBe(404);

		const res = await deactivate(g, present(active, 'an active user'));

		expect(res.status).toBe(200);
	});

	it('does not count an administrator’s lock of a provisioned user', async () => {
		const g = await guarded(ONE);
		const [locked, active] = await provision(g, 2);
		const lock = await admin(
			'POST',
			`${usersPath(g, present(locked, 'a user'))}/lock`,
			g.cookie,
			{ reason: 'suspected compromise' }
		);
		expect(lock.status).toBe(200);

		const res = await deactivate(g, present(active, 'an active user'));

		expect(res.status).toBe(200);
	});

	it('does not count an administrator’s deactivation of a local user', async () => {
		const g = await guarded(ONE);
		const [active] = await provision(g, 1);
		const local = await admin('POST', usersPath(g), g.cookie, {
			email: `local-${Math.random().toString(36).slice(2)}@x.io`,
			password: 'a-long-enough-password'
		});
		expect(local.status).toBe(201);
		const localId = shaped(Type.Object({ _id: Type.String() }), local.json)._id;
		const deactivated = await admin('PATCH', usersPath(g, localId), g.cookie, {
			active: false
		});
		expect(deactivated.status).toBe(200);

		const res = await deactivate(g, present(active, 'an active user'));

		expect(res.status).toBe(200);
	});

	/*
	 * Signing a user out everywhere is the operation an upstream provider's global token revocation performs
	 * (lib/end_users/service.ts revokeEndUserAccess), so this is where "a revocation does not count" is seen.
	 */
	it('does not count signing a provisioned user out everywhere', async () => {
		const g = await guarded(ONE);
		const [signedOut, active] = await provision(g, 2);
		const out = await admin(
			'POST',
			`${usersPath(g, present(signedOut, 'a user'))}/sign-out`,
			g.cookie
		);
		expect(out.status).toBe(200);

		const res = await deactivate(g, present(active, 'an active user'));

		expect(res.status).toBe(200);
	});

	it('never accepts more concurrent deprovisionings than the threshold', async () => {
		const g = await guarded({ count: 5, windowSeconds: HOUR });
		const ids = await provision(g, 20);

		const statuses = (
			await Promise.all(ids.map((id) => deactivate(g, id)))
		).map((r) => r.status);

		expect(statuses.filter((s) => s === 200)).toHaveLength(5);
		expect(statuses.filter((s) => s === 429)).toHaveLength(15);
		const stillActive = await Promise.all(
			ids.map(async (id) => (await storedUser(g, id))?.active)
		);
		expect(stillActive.filter((a) => a === false)).toHaveLength(5);
	});

	it('refuses the release of a held connection to an administrator outside the bucket’s group', async () => {
		const g = await tripped(ONE);
		const { cookie: outsider } = await plainAdministrator();

		const res = await release(g, outsider);

		expect(res.status).toBe(403);
		expect((await viewOf(g)).hold).toBeDefined();
	});
});
