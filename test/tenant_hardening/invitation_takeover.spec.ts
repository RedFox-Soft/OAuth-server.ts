import {
	describe,
	it,
	expect,
	beforeAll,
	beforeEach,
	afterEach
} from 'bun:test';
import bootstrap from '../test_helper.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import {
	adminAuditStore,
	adminSessionStore,
	getBucketStore,
	getUserStore
} from 'lib/adapters/index.ts';
import { ADMIN_BUCKET_ID } from 'lib/admin/consts.ts';
import { sessionFor } from '../admin_session.ts';
import { resetSentEmails } from '../mail_capture.ts';
import {
	accept,
	freshEmail,
	invitationTokenFor,
	invite,
	membersOf,
	tenant,
	type Caller
} from './admin.ts';

const users = () => getUserStore(ADMIN_BUCKET_ID);

/* Written to the store, as the guarded settings route would leave it: only the requirement matters here. */
function requireVerification(on: boolean) {
	return getBucketStore().update(ADMIN_BUCKET_ID, {
		emailVerificationRequired: on
	});
}

/* An administrator account somebody registered under an address, as the sign-up page stores it. */
async function registeredUnder(
	email: string,
	{ verified }: { verified: boolean }
) {
	const account = await users().create(
		email,
		await Bun.password.hash('the-earlier-password'),
		verified
	);
	await users().update(account._id, {
		totp: { secret: 'JBSWY3DPEHPK3PXP', enrolledAt: new Date(), lastStep: 0 },
		federated: [
			{ providerId: 'google', sub: `sub-${account._id}`, linkedAt: new Date() }
		]
	});
	const session = await sessionFor(account);
	return { account, sessionId: session._id };
}

async function stored(id: string) {
	const account = await users().find(id);
	if (!account) throw new Error('account gone');
	return account;
}

/**
 * @proves An invitation joins only the person who holds its address: while administrators must prove their
 * address, an account under that address that was never proven is reclaimed by the invitee on acceptance — their
 * password, nobody else's sessions, authenticator or linked providers — while a proven account, or any account
 * while proof is not required, joins unchanged; a new address gets a proven account; a deactivated one is refused.
 */
describe('accepting a team invitation', () => {
	let owner: Caller;

	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'tenant_hardening' });
		await ensureAdminSeed();
	});

	beforeEach(async () => {
		resetSentEmails();
		owner = await tenant();
	});

	describe('given an account under the address that was never proven, while administrators must prove theirs', () => {
		beforeEach(() => requireVerification(true));
		afterEach(() => requireVerification(false));

		it('hands the account to the invitee, with their password, when they choose one', async () => {
			const email = freshEmail('bob');
			const { account, sessionId } = await registeredUnder(email, {
				verified: false
			});
			await invite(owner, email, 'owner');

			const accepted = await accept(
				invitationTokenFor(email),
				'bobs-own-password'
			);

			expect(accepted.status).toBe(200);
			expect(await membersOf(owner.teamId)).toContain(`${account._id}:owner`);
			const after = await stored(account._id);
			expect(
				await Bun.password.verify('bobs-own-password', after.password)
			).toBe(true);
			expect(
				await Bun.password.verify('the-earlier-password', after.password)
			).toBe(false);
			expect(after.verified).toBe(true);
			expect(after.totp).toBeUndefined();
			expect(after.federated ?? []).toEqual([]);
			expect(await adminSessionStore.find(sessionId)).toBeNull();
		});

		it('records that the address was reclaimed, in the team’s trail', async () => {
			const email = freshEmail('bob');
			await registeredUnder(email, { verified: false });
			await invite(owner, email);

			await accept(invitationTokenFor(email), 'bobs-own-password');

			const { entries } = await adminAuditStore.list({
				ownerGroupIds: [owner.teamId]
			});
			const entry = entries.find((e) => e.action === 'invitation.accept');
			expect(entry?.attributes).toEqual(['address-reclaimed']);
		});

		it('asks for a password first, and the invitation stays usable', async () => {
			const email = freshEmail('bob');
			const { account } = await registeredUnder(email, { verified: false });
			await invite(owner, email);
			const token = invitationTokenFor(email);

			const withoutPassword = await accept(token);
			const membersBetween = await membersOf(owner.teamId);
			const withPassword = await accept(token, 'bobs-own-password');

			expect(withoutPassword.status).toBe(400);
			expect((withoutPassword.body as { message: string }).message).toBe(
				'choose a password to finish joining: it becomes the password of the administrator account for this address'
			);
			expect(membersBetween).not.toContain(`${account._id}:member`);
			expect(withPassword.status).toBe(200);
		});
	});

	describe('given an account under the address that was never proven, while proof is not required', () => {
		it('joins it as it is: sign-up cannot be open, so an operator made it', async () => {
			const email = freshEmail('frank');
			const { account, sessionId } = await registeredUnder(email, {
				verified: false
			});
			await invite(owner, email);

			const accepted = await accept(invitationTokenFor(email));

			expect(accepted.status).toBe(200);
			expect(await membersOf(owner.teamId)).toContain(`${account._id}:member`);
			const after = await stored(account._id);
			expect(
				await Bun.password.verify('the-earlier-password', after.password)
			).toBe(true);
			expect(await adminSessionStore.find(sessionId)).not.toBeNull();
		});
	});

	describe('given an account whose address is proven', () => {
		it('joins it to the team and changes nothing about how it signs in', async () => {
			const email = freshEmail('carol');
			const { account, sessionId } = await registeredUnder(email, {
				verified: true
			});
			await invite(owner, email);

			const accepted = await accept(
				invitationTokenFor(email),
				'ignored-password'
			);

			expect(accepted.status).toBe(200);
			expect(await membersOf(owner.teamId)).toContain(`${account._id}:member`);
			const after = await stored(account._id);
			expect(
				await Bun.password.verify('the-earlier-password', after.password)
			).toBe(true);
			expect(after.totp).toBeDefined();
			expect(await adminSessionStore.find(sessionId)).not.toBeNull();
		});

		it('refuses it while the account is deactivated, as any unusable invitation', async () => {
			const email = freshEmail('dave');
			const { account } = await registeredUnder(email, { verified: true });
			await users().update(account._id, { active: false });
			await invite(owner, email);

			const accepted = await accept(invitationTokenFor(email), 'a-password-1');

			expect(accepted.status).toBe(400);
			expect((accepted.body as { message: string }).message).toBe(
				'invitation is not valid'
			);
			expect(await membersOf(owner.teamId)).not.toContain(
				`${account._id}:member`
			);
		});
	});

	describe('given no account under the address', () => {
		it('creates one whose address is proven', async () => {
			const email = freshEmail('erin');
			await invite(owner, email);

			const accepted = await accept(
				invitationTokenFor(email),
				'erins-password'
			);

			expect(accepted.status).toBe(200);
			expect((await users().findByEmail(email))?.verified).toBe(true);
		});
	});
});
