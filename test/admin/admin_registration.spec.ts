import {
	describe,
	it,
	expect,
	beforeAll,
	afterAll,
	beforeEach
} from 'bun:test';
import bootstrap, { agent, getHeader } from '../test_helper.ts';
import { AuthorizationRequest } from '../AuthorizationRequest.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import {
	adminAuditStore,
	getBucketStore,
	getGroupStore,
	getUserStore,
	resetAdminMemoryStores
} from 'lib/adapters/index.ts';
import {
	ADMIN_BUCKET_ID,
	ADMIN_CLIENT_ID,
	ADMIN_SESSION_COOKIE
} from 'lib/admin/consts.ts';
import { isSuperAdmin } from 'lib/admin/super_admins.ts';
import { BOOTSTRAP_ACTOR } from 'lib/consts/admin_audit_routes.ts';
import {
	sentEmails,
	resetSentEmails,
	emailsTo,
	extractVerifyUrl,
	extractInvitationToken
} from '../mail_capture.ts';
import { elysia } from 'lib/index.ts';
import { sessionFor } from '../admin_session.ts';
import { createAdministrator } from '../administrators.ts';
import { present } from 'test/shape.js';

const PASSWORD = 'correct horse battery';

let seq = 0;
const unique = () => `registrant-${Date.now()}-${(seq += 1)}@x.io`;

// A real authorization request from the console's own client, so the registration door resolves the
// administrators' bucket exactly as it does for a person arriving at /admin.
async function startConsoleInteraction() {
	const auth = new AuthorizationRequest({
		client_id: ADMIN_CLIENT_ID,
		scope: 'openid'
	});
	const { response } = await agent.auth.get({ query: auth.params });
	const location = getHeader(response, 'location');
	const uid = location.split('/')[2];
	const cookie = response.headers.get('set-cookie');
	if (!cookie) throw new Error('expected an interaction cookie from /auth');
	return { uid, cookie };
}

async function register(email: string) {
	const { uid, cookie } = await startConsoleInteraction();
	const { response } = await agent
		.ui({ uid })
		.registration.post(
			{ email, password: PASSWORD, confirmPassword: PASSWORD },
			{ headers: { cookie } }
		);
	return { uid, response };
}

async function signIn(email: string) {
	const { uid, cookie } = await startConsoleInteraction();
	const { response } = await agent
		.ui({ uid })
		.login.post(
			{ username: email, password: PASSWORD },
			{ headers: { cookie } }
		);
	return response.status;
}

async function setRegistration(registrationOpen: boolean) {
	await getBucketStore().update(ADMIN_BUCKET_ID, { registrationOpen });
}

/**
 * @proves People can sign up for the console when a super administrator has opened it, each lands in a
 * console of their own and nothing more, and a closed console takes no sign-ups at all.
 */
describe('registering an administrator account', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'admin' });
		resetAdminMemoryStores();
		await ensureAdminSeed();
	});

	beforeEach(async () => {
		resetSentEmails();
		await setRegistration(true);
	});

	// The bucket's settings outlive this file; a console left open changes what later specs see.
	afterAll(async () => {
		await setRegistration(false);
		await getBucketStore().update(ADMIN_BUCKET_ID, {
			emailVerificationRequired: false
		});
	});

	it('admits an administrator at the next sign-in once they follow the mailed link, while administrators must verify their address', async () => {
		// Set on the record directly: the guards on the setting are proven in the settings spec.
		await getBucketStore().update(ADMIN_BUCKET_ID, {
			emailVerificationRequired: true,
			verificationMethod: 'link'
		});
		try {
			const email = unique();
			await register(email);
			expect(await signIn(email)).toBe(400);

			const url = present(
				extractVerifyUrl(present(emailsTo(email)[0], 'emailsTo(email)[0]')),
				'extractVerifyUrl'
			);
			const token = present(new URL(url).searchParams.get('token'), 'token');
			const opened = await agent['verify-email'].get({ query: { token } });
			expect(opened.response.status).toBe(200);

			expect(await signIn(email)).toBe(303);
		} finally {
			await getBucketStore().update(ADMIN_BUCKET_ID, {
				emailVerificationRequired: false
			});
		}
	});

	it('creates an administrator who signs in to a console holding only their personal group', async () => {
		const email = unique();
		const { response } = await register(email);
		expect(response.status).toBe(303);

		const account = await getUserStore(ADMIN_BUCKET_ID).findByEmail(email);
		expect(account).not.toBeNull();
		const groups = await getGroupStore().listByMember(account?._id ?? '');
		expect(groups.map((g) => g.kind)).toEqual(['personal']);

		expect(await signIn(email)).toBe(303);
	});

	it('gives a self-registered administrator no instance privilege', async () => {
		const email = unique();
		await register(email);

		const account = await getUserStore(ADMIN_BUCKET_ID).findByEmail(email);
		expect(await isSuperAdmin(account?._id ?? '')).toBe(false);
	});

	it('records the registration in the audit trail', async () => {
		const email = unique();
		await register(email);
		const account = await getUserStore(ADMIN_BUCKET_ID).findByEmail(email);

		const { entries } = await adminAuditStore.list({
			targetId: account?._id
		});
		const entry = entries.find((e) => e.action === 'admin.register');
		expect(entry?.actorId).toBe(BOOTSTRAP_ACTOR);
		expect(entry?.targetType).toBe('AdminUser');
	});

	it('creates no second account for an address an administrator already holds, and answers as for a new one', async () => {
		const email = unique();
		const first = await register(email);
		const second = await register(email);

		expect(second.response.status).toBe(first.response.status);
		expect(getHeader(second.response, 'location')).toBe(
			`/ui/${second.uid}/login`
		);
		const all = await getUserStore(ADMIN_BUCKET_ID).list();
		expect(all.filter((u) => u.email === email)).toHaveLength(1);
	});

	it('creates no account and sends no mail while administrator registration is closed', async () => {
		await setRegistration(false);
		const email = unique();
		const { response } = await register(email);

		expect(response.status).toBe(403);
		expect(await getUserStore(ADMIN_BUCKET_ID).findByEmail(email)).toBeNull();
		expect(sentEmails).toHaveLength(0);
	});
});

async function adminCall(path: string, cookie: string, body: unknown) {
	const res = await elysia.handle(
		new Request(`http://e.ly${path}`, {
			method: 'POST',
			headers: { 'content-type': 'application/json', cookie },
			body: JSON.stringify(body)
		})
	);
	return { status: res.status, body: (await res.json()) as unknown };
}

/**
 * @proves An administrator who joined through an invitation is not asked to prove an address the
 * invitation was already delivered to.
 */
describe('an administrator created through an invitation', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'admin' });
		await ensureAdminSeed();
	});

	afterAll(async () => {
		await getBucketStore().update(ADMIN_BUCKET_ID, {
			emailVerificationRequired: false
		});
	});

	it('is admitted while administrators must verify their address', async () => {
		const owner = await createAdministrator('plain');
		const session = await sessionFor(owner);
		const cookie = `${ADMIN_SESSION_COOKIE}=${session._id}`;
		const group = await adminCall('/admin/api/groups', cookie, {
			name: `Invited ${seq}`
		});
		const groupId = (group.body as { _id: string })._id;
		const invitee = unique();
		resetSentEmails();
		await adminCall(`/admin/api/groups/${groupId}/invitations`, cookie, {
			email: invitee,
			role: 'member'
		});
		const token = present(
			extractInvitationToken(present(emailsTo(invitee)[0], 'invitation')),
			'token'
		);
		const accepted = await adminCall('/admin/api/invitations/accept', '', {
			token,
			password: PASSWORD
		});
		expect(accepted.status).toBe(200);

		await getBucketStore().update(ADMIN_BUCKET_ID, {
			emailVerificationRequired: true
		});
		try {
			expect(await signIn(invitee)).toBe(303);
		} finally {
			await getBucketStore().update(ADMIN_BUCKET_ID, {
				emailVerificationRequired: false
			});
		}
	});
});
