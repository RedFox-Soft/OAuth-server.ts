import {
	describe,
	it,
	expect,
	beforeAll,
	beforeEach,
	afterEach,
	setSystemTime
} from 'bun:test';
import bootstrap from '../test_helper.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { adminAuditStore } from 'lib/adapters/index.ts';
import { regularGroup } from '../admin/ownership_fixtures.ts';
import { emailsTo, resetSentEmails } from '../mail_capture.ts';
import {
	call,
	createProject,
	freshEmail,
	invite,
	superAdmin,
	tenant,
	type Caller
} from './admin.ts';

interface Refusal {
	message: string;
	retryAfter?: number;
}

function later(seconds: number) {
	setSystemTime(new Date(Date.now() + seconds * 1000));
}

async function invitationCreates(): Promise<number> {
	return (await adminAuditStore.list({ action: 'invitation.create' })).total;
}

/**
 * @proves The instance's mail cannot be spent by one administrator: an address is invited to a team at most once
 * every ten minutes and five times a day, revoking does not reset that, one inviter sends at most a hundred a day
 * across teams, a team holds at most fifty open invitations, a super administrator is bounded alike, and nothing is
 * recorded or mailed for a refused invitation.
 */
describe('team invitation bounds', () => {
	let owner: Caller;

	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'tenant_hardening' });
		await ensureAdminSeed();
	});

	beforeEach(async () => {
		resetSentEmails();
		owner = await tenant();
	});

	afterEach(() => {
		setSystemTime();
	});

	describe('one address and team', () => {
		it('refuses a second invitation within ten minutes, with the wait, mailing nothing', async () => {
			const email = freshEmail();
			await invite(owner, email);
			const before = await invitationCreates();

			const again = await invite(owner, email);

			expect(again.status).toBe(429);
			const refusal = again.body as Refusal;
			expect(refusal.message).toStartWith(
				'this address was invited to this team recently: try again in'
			);
			expect(refusal.retryAfter).toBeGreaterThan(0);
			expect(refusal.retryAfter).toBeLessThanOrEqual(600);
			expect(emailsTo(email)).toHaveLength(1);
			expect(await invitationCreates()).toBe(before);
		});

		it('accepts it again once the ten minutes are over', async () => {
			const email = freshEmail();
			await invite(owner, email);
			later(601);

			expect((await invite(owner, email)).status).toBe(201);
		});

		it('does not let revoking the invitation reset the wait', async () => {
			const email = freshEmail();
			const sent = await invite(owner, email);
			const id = (sent.body as { _id: string })._id;
			await call(
				'DELETE',
				`/admin/api/teams/${owner.teamId}/invitations/${id}`,
				owner.cookie
			);

			expect((await invite(owner, email)).status).toBe(429);
		});

		it('refuses a sixth invitation in a day, however spaced', async () => {
			const email = freshEmail();
			for (let sent = 0; sent < 5; sent += 1) {
				expect((await invite(owner, email)).status).toBe(201);
				later(601);
			}

			const sixth = await invite(owner, email);

			expect(sixth.status).toBe(429);
			expect((sixth.body as Refusal).retryAfter).toBeGreaterThan(600);
		});

		it('leaves the same address free to be invited to another team', async () => {
			const email = freshEmail();
			const other = await regularGroup([owner.user]);
			await invite(owner, email);

			expect((await invite(owner, email, 'member', other._id)).status).toBe(
				201
			);
		});
	});

	it('refuses a team its fifty-first open invitation', async () => {
		for (let sent = 0; sent < 50; sent += 1) {
			expect((await invite(owner, freshEmail())).status).toBe(201);
		}

		const fiftyFirst = await invite(owner, freshEmail());

		expect(fiftyFirst.status).toBe(409);
		expect((fiftyFirst.body as Refusal).message).toBe(
			'this team has 50 open invitations: revoke one or wait for one to be accepted'
		);
	});

	it('refuses one inviter their hundred-and-first invitation of the day, across teams', async () => {
		const teams = [
			owner.teamId,
			(await regularGroup([owner.user]))._id,
			(await regularGroup([owner.user]))._id
		];
		for (let sent = 0; sent < 100; sent += 1) {
			const team = teams[sent % teams.length];
			expect((await invite(owner, freshEmail(), 'member', team)).status).toBe(
				201
			);
		}

		const next = await invite(owner, freshEmail(), 'member', teams[0]);

		expect(next.status).toBe(429);
		expect((next.body as Refusal).message).toStartWith(
			'you have sent as many invitations as allowed today: try again in'
		);
	});

	it('bounds a super administrator the same way', async () => {
		const operator = await superAdmin();
		const email = freshEmail();
		await invite(operator, email);

		expect((await invite(operator, email)).status).toBe(429);
	});
});

/**
 * @proves A project's name is bounded, since it reaches the subject of the mail sent to its people.
 */
describe('a project name', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'tenant_hardening' });
		await ensureAdminSeed();
	});

	it('is refused over a hundred characters, at creation and on change', async () => {
		const owner = await tenant();
		const tooLong = 'x'.repeat(101);
		const created = await createProject(owner, {
			name: 'Fine',
			slug: `fine-${Math.random().toString(36).slice(2, 10)}`
		});
		const id = (created.body as { _id: string })._id;

		const atCreation = await createProject(owner, {
			name: tooLong,
			slug: `long-${Math.random().toString(36).slice(2, 10)}`
		});
		const onChange = await call(
			'PATCH',
			`/admin/api/projects/${id}`,
			owner.cookie,
			{ name: tooLong }
		);

		expect(created.status).toBe(201);
		expect(atCreation.status).toBe(422);
		expect(onChange.status).toBe(422);
	});
});
