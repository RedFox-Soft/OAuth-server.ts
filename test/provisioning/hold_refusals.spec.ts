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

import {
	getProvisioningRefusalStore,
	getUserStore
} from 'lib/adapters/index.js';
import { resetSentEmails, sentEmails } from 'lib/mail/mailer.js';
import bootstrap from '../test_helper.js';
import { present, shaped } from '../shape.ts';
import {
	connectionPath,
	deactivate,
	deactivateAll,
	guarded,
	HOUR,
	plainAdministrator,
	provision,
	release,
	scim,
	storedUser,
	type Guarded
} from '../deprovisioning_guard/helpers.ts';
import { admin } from './helpers.ts';

const Refused = Type.Object({
	userId: Type.String(),
	email: Type.Union([Type.String(), Type.Null()]),
	userName: Type.Union([Type.String(), Type.Null()]),
	operation: Type.Union([Type.Literal('deactivate'), Type.Literal('delete')]),
	firstAt: Type.String(),
	lastAt: Type.String(),
	attempts: Type.Number()
});

const HeldRead = Type.Object({
	held: Type.Literal(true),
	since: Type.String(),
	count: Type.Number(),
	refused: Type.Array(Refused),
	total: Type.Number()
});

const AuditPage = Type.Object({
	entries: Type.Array(
		Type.Object({
			action: Type.String(),
			cascade: Type.Optional(
				Type.Union([Type.Record(Type.String(), Type.Number()), Type.Null()])
			)
		})
	)
});

/*
 * A connection with a threshold of one that has spent it, and three more people it provisioned: the next
 * removal it asks for trips the hold.
 */
async function spent(): Promise<{ g: Guarded; people: string[] }> {
	const g = await guarded({ count: 1, windowSeconds: HOUR });
	const [first, ...people] = await provision(g, 4);
	await deactivateAll(g, [present(first, 'a user')]);
	return { g, people };
}

function remove(g: Guarded, id: string) {
	return scim('DELETE', `${g.base}/Users/${id}`, { token: g.token });
}

async function holdOf(g: Guarded, cookie = g.cookie) {
	return admin('GET', `${connectionPath(g)}/hold`, cookie);
}

async function heldRead(g: Guarded) {
	const res = await holdOf(g);
	expect(res.status).toBe(200);
	return shaped(HeldRead, res.json);
}

/* Resolves once `predicate` holds, for the alert that is sent after the refusal has been answered. */
async function eventually(predicate: () => boolean): Promise<void> {
	for (let i = 0; i < 100 && !predicate(); i += 1) await Bun.sleep(5);
}

/**
 * @proves An administrator about to release a held provisioning connection can see whom the release lets the
 * directory remove — each person once per hold, with what was asked and how often — the release says how
 * many it re-admitted and the next hold starts empty, the hold email leads to that connection, and recording a
 * refusal can never change what the directory is answered (spec 084, User Story 6, R2, R3).
 */
describe('the removals a held connection was refused', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	beforeEach(() => {
		resetSentEmails();
	});

	afterEach(() => {
		mock.restore();
	});

	it('answers that a connection is not held when it is not', async () => {
		const g = await guarded({ count: 1, windowSeconds: HOUR });

		const res = await holdOf(g);

		expect(res.status).toBe(200);
		expect(res.json).toEqual({ held: false });
	});

	it('lists the person whose deactivation tripped the hold, as a deactivation', async () => {
		const { g, people } = await spent();
		const [tripping] = people;

		expect((await deactivate(g, present(tripping, 'a user'))).status).toBe(429);

		const read = await heldRead(g);
		expect(read.count).toBe(1);
		expect(read.refused).toHaveLength(1);
		expect(read.refused[0]).toMatchObject({
			userId: tripping,
			operation: 'deactivate',
			attempts: 1
		});
		expect(read.refused[0]?.email).toContain('@contoso.com');
	});

	it('lists a deletion refused while held as a deletion', async () => {
		const { g, people } = await spent();
		const [tripping, deleted] = people;
		await deactivate(g, present(tripping, 'a user'));

		expect((await remove(g, present(deleted, 'a user'))).status).toBe(429);

		const read = await heldRead(g);
		expect(read.refused.find((r) => r.userId === deleted)?.operation).toBe(
			'delete'
		);
	});

	it('counts a retried refusal as another attempt on the same person', async () => {
		const { g, people } = await spent();
		const [tripping] = people;
		await deactivate(g, present(tripping, 'a user'));

		await deactivate(g, present(tripping, 'a user'));
		await deactivate(g, present(tripping, 'a user'));

		const read = await heldRead(g);
		expect(read.total).toBe(1);
		expect(read.refused).toHaveLength(1);
		expect(read.refused[0]?.attempts).toBe(3);
	});

	it('lists the most recently refused person first', async () => {
		const { g, people } = await spent();
		const [tripping, second, third] = people;
		await deactivate(g, present(tripping, 'a user'));
		await Bun.sleep(5);
		await remove(g, present(second, 'a user'));
		await Bun.sleep(5);
		await deactivate(g, present(third, 'a user'));

		const read = await heldRead(g);

		expect(read.refused.map((r) => r.userId)).toEqual([
			third,
			second,
			tripping
		]);
	});

	it('leaves out a person deleted since, while still counting them', async () => {
		const { g, people } = await spent();
		const [tripping, gone] = people;
		await deactivate(g, present(tripping, 'a user'));
		await remove(g, present(gone, 'a user'));
		await getUserStore(g.bucket._id).destroy(present(gone, 'a user'));

		const read = await heldRead(g);

		expect(read.refused.map((r) => r.userId)).toEqual([tripping]);
		expect(read.total).toBe(2);
	});

	it('records in the release how many refused removals it re-admits', async () => {
		const { g, people } = await spent();
		const [tripping, deleted] = people;
		await deactivate(g, present(tripping, 'a user'));
		await remove(g, present(deleted, 'a user'));

		expect((await release(g)).status).toBe(200);

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
		expect(page.entries.map((e) => e.cascade)).toEqual([
			{ refusedRemovals: 2 }
		]);
	});

	it('starts the next hold with nobody listed', async () => {
		const g = await guarded({ count: 1, windowSeconds: HOUR });
		const [first, tripping, next, again] = await provision(g, 4);
		await deactivateAll(g, [present(first, 'a user')]);
		await deactivate(g, present(tripping, 'a user'));
		await release(g);
		await deactivateAll(g, [present(next, 'a user')]);

		expect((await deactivate(g, present(again, 'a user'))).status).toBe(429);

		const read = await heldRead(g);
		expect(read.refused.map((r) => r.userId)).toEqual([again]);
		expect(read.total).toBe(1);
	});

	it('links the hold email to the held connection’s page', async () => {
		const { g, people } = await spent();

		await deactivate(g, present(people[0], 'a user'));

		await eventually(() => sentEmails.length > 0);
		expect(sentEmails[0]?.text).toContain(
			`/admin/buckets/${g.bucket._id}/provisioning/${g.connection._id}`
		);
	});

	it('still refuses the removal with 429, and changes nobody, when the refusal cannot be recorded', async () => {
		const { g, people } = await spent();
		const [tripping] = people;
		spyOn(getProvisioningRefusalStore(), 'note').mockRejectedValue(
			new Error('the datastore refused the write')
		);

		const res = await deactivate(g, present(tripping, 'a user'));

		expect(res.status).toBe(429);
		expect(res.headers.get('retry-after')).toBe('300');
		expect((await storedUser(g, present(tripping, 'a user')))?.active).toBe(
			true
		);
	});

	it('refuses the read to an administrator with no access to the bucket', async () => {
		const { g, people } = await spent();
		await deactivate(g, present(people[0], 'a user'));
		const { cookie } = await plainAdministrator();

		const res = await holdOf(g, cookie);

		expect(res.status).toBe(403);
		expect(res.json.refused).toBeUndefined();
	});
});
