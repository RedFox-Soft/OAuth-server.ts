import {
	describe,
	it,
	beforeAll,
	beforeEach,
	afterEach,
	expect,
	mock,
	spyOn
} from 'bun:test';
import { Type } from '@sinclair/typebox';

import { resetSentEmails, sentEmails } from 'lib/mail/mailer.js';
import { eventBus } from 'lib/event_bus.js';
import { admin } from '../provisioning/helpers.ts';
import { present, shaped } from '../shape.ts';
import bootstrap from '../test_helper.js';
import {
	connectionPath,
	deactivate,
	deactivateAll,
	guarded,
	HOUR,
	plainAdministrator,
	provision,
	release,
	setThreshold,
	tripped,
	viewOf,
	type Guarded
} from './helpers.ts';

const AuditPage = Type.Object({
	entries: Type.Array(
		Type.Object({
			actorId: Type.String(),
			action: Type.String(),
			targetId: Type.String(),
			attributes: Type.Optional(Type.Array(Type.String()))
		})
	)
});

/* A connection with a threshold of one that has spent it: the next deprovisioning trips the hold. */
async function spent(): Promise<{ g: Guarded; next: string[] }> {
	const g = await guarded({ count: 1, windowSeconds: HOUR });
	const [first, ...next] = await provision(g, 3);
	await deactivateAll(g, [present(first, 'a user')]);
	return { g, next };
}

/* Resolves once `predicate` holds, for the alert that is sent after the refusal has been answered. */
async function eventually(predicate: () => boolean): Promise<void> {
	for (let i = 0; i < 100 && !predicate(); i += 1) await Bun.sleep(5);
}

/**
 * @proves An administrator responsible for a bucket learns that a connection is held — from the audit trail
 * once, from the connection's own view, and by one email — and is the only one who ends the hold, which
 * restarts the count; no edit of the connection ends it, and a threshold outside the permitted range is
 * refused naming that range (spec 072, User Story 4, scenarios 5, 6, 10; FR-017, FR-022–FR-024).
 */
describe('holding and releasing a provisioning connection', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	beforeEach(() => {
		resetSentEmails();
	});

	afterEach(() => {
		mock.restore();
	});

	describe('releasing', () => {
		it('lets the retried deactivation through after a release', async () => {
			const g = await guarded({ count: 1, windowSeconds: HOUR });
			const [first, refused] = await provision(g, 2);
			await deactivateAll(g, [present(first, 'a user')]);
			expect((await deactivate(g, present(refused, 'a user'))).status).toBe(
				429
			);
			expect((await release(g)).status).toBe(200);

			const retried = await deactivate(g, present(refused, 'a user'));

			expect(retried.status).toBe(200);
		});

		it('restarts the count after a release', async () => {
			const g = await tripped({ count: 2, windowSeconds: HOUR });
			const ids = await provision(g, 2);
			expect((await release(g)).status).toBe(200);

			const statuses = [];
			for (const id of ids) statuses.push((await deactivate(g, id)).status);

			expect(statuses).toEqual([200, 200]);
		});

		it('answers 409 to releasing a connection that is not held', async () => {
			const g = await guarded({ count: 1, windowSeconds: HOUR });

			const res = await release(g);

			expect(res.status).toBe(409);
		});

		it('records the release in the audit trail', async () => {
			const g = await tripped({ count: 1, windowSeconds: HOUR });

			await release(g);

			const page = shaped(
				AuditPage,
				(
					await admin(
						'GET',
						`/admin/api/audit?action=provisioning.connection.release&targetId=${g.connection._id}`,
						g.cookie
					)
				).json
			);
			expect(page.entries.map((e) => e.actorId)).toEqual([g.owner._id]);
		});
	});

	describe('editing a guarded connection', () => {
		it('restarts the count when the threshold changes', async () => {
			const g = await guarded({ count: 2, windowSeconds: HOUR });
			const ids = await provision(g, 3);
			await deactivateAll(g, ids.slice(0, 2));
			expect(
				(await setThreshold(g, { count: 2, windowSeconds: 2 * HOUR })).status
			).toBe(200);

			const res = await deactivate(g, present(ids[2], 'a third user'));

			expect(res.status).toBe(200);
		});

		it('leaves a held connection held when it is disabled and re-enabled', async () => {
			const g = await tripped({ count: 1, windowSeconds: HOUR });
			const [id] = await provision(g, 1);

			await admin('PATCH', connectionPath(g), g.cookie, { enabled: false });
			await admin('PATCH', connectionPath(g), g.cookie, { enabled: true });

			expect((await viewOf(g)).hold).toBeDefined();
			expect((await deactivate(g, present(id, 'a user'))).status).toBe(429);
		});

		it('leaves a held connection held when its threshold changes', async () => {
			const g = await tripped({ count: 1, windowSeconds: HOUR });

			await setThreshold(g, { count: 50, windowSeconds: HOUR });

			expect((await viewOf(g)).hold).toBeDefined();
		});

		it('refuses removing the threshold of a held connection', async () => {
			const g = await tripped({ count: 1, windowSeconds: HOUR });

			const res = await setThreshold(g, null);

			expect(res.status).toBe(409);
			expect((await viewOf(g)).threshold).toEqual({
				count: 1,
				windowSeconds: HOUR
			});
		});

		it('removes the threshold of a connection that is not held', async () => {
			const g = await guarded({ count: 1, windowSeconds: HOUR });

			const res = await setThreshold(g, null);

			expect(res.status).toBe(200);
			expect((await viewOf(g)).threshold).toBeUndefined();
		});

		it.each([
			['a count of zero', { count: 0, windowSeconds: HOUR }],
			['a negative count', { count: -5, windowSeconds: HOUR }],
			['a count above 100,000', { count: 100001, windowSeconds: HOUR }],
			['a window shorter than five minutes', { count: 10, windowSeconds: 299 }],
			['a window longer than seven days', { count: 10, windowSeconds: 604801 }]
		])('refuses %s, naming the permitted range', async (_, threshold) => {
			const g = await guarded();

			const res = await setThreshold(g, threshold);

			expect(res.status).toBe(422);
			expect(String(res.json.error_description)).toContain('1–100000');
			expect(String(res.json.error_description)).toContain('300–604800');
		});

		it('refuses an out-of-range threshold on a new connection too', async () => {
			const { cookie } = await plainAdministrator();
			const g = await guarded();

			const res = await admin(
				'POST',
				`/admin/api/buckets/${g.bucket._id}/provisioning-connections`,
				cookie,
				{
					displayName: 'Second',
					providerId: 'corp',
					threshold: { count: 0, windowSeconds: HOUR }
				}
			);

			expect(res.status).toBe(422);
		});
	});

	describe('becoming held', () => {
		it('records the hold once in the audit trail, under the connection', async () => {
			const { g, next } = await spent();

			await Promise.all(next.map((id) => deactivate(g, id)));

			const page = shaped(
				AuditPage,
				(
					await admin(
						'GET',
						`/admin/api/audit?viaSurface=scim&action=provisioning.connection.update&targetId=${g.connection._id}`,
						g.cookie
					)
				).json
			);
			expect(page.entries).toHaveLength(1);
			expect(page.entries[0]).toMatchObject({
				actorId: `connection:${g.connection._id}`,
				attributes: ['hold']
			});
		});

		it('shows when the connection was held and the count before it', async () => {
			const before = Date.now();
			const g = await tripped({ count: 2, windowSeconds: HOUR });

			const { hold } = await viewOf(g);

			expect(hold?.count).toBe(2);
			expect(Date.parse(hold?.since ?? '')).toBeGreaterThanOrEqual(
				before - 1000
			);
		});

		it('emails the administrators of the bucket’s owning group once', async () => {
			const { g, next } = await spent();
			const { user: outsider } = await plainAdministrator();

			await Promise.all(next.map((id) => deactivate(g, id)));

			await eventually(() => sentEmails.length > 0);
			await Bun.sleep(30);
			expect(sentEmails.map((m) => m.to)).toEqual([g.owner.email]);
			expect(sentEmails.map((m) => m.to)).not.toContain(outsider.email);
			expect(sentEmails[0]?.text).toContain(g.connection.displayName);
		});

		it('stays held when the alert email cannot be sent', async () => {
			const { g, next } = await spent();
			spyOn(sentEmails, 'push').mockImplementation(() => {
				throw new Error('smtp refused the message');
			});
			let failed = false;
			const onFailed = () => {
				failed = true;
			};
			eventBus.on('provisioning.hold.alert_failed', onFailed);
			try {
				const res = await deactivate(g, present(next[0], 'a user'));

				expect(res.status).toBe(429);
				await eventually(() => failed);
				expect(failed).toBe(true);
				expect((await viewOf(g)).hold).toBeDefined();
			} finally {
				eventBus.off('provisioning.hold.alert_failed', onFailed);
			}
		});
	});
});
