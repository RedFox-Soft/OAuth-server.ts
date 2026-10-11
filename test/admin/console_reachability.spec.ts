import {
	describe,
	it,
	expect,
	afterAll,
	beforeAll,
	beforeEach
} from 'bun:test';
import bootstrap from '../test_helper.ts';
import {
	adminAuditStore,
	adminSessionStore,
	getBucketStore,
	getUserStore,
	resetAdminMemoryStores
} from 'lib/adapters/index.ts';
import { ADMIN_BUCKET_ID, ADMIN_SESSION_COOKIE } from 'lib/admin/consts.ts';
import { ensurePersonalGroup } from 'lib/admin/groups/personal.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { restorePasswordSignIn } from 'lib/admin/password_sign_in.ts';
import { elysia } from 'lib/index.ts';
import type { User } from 'lib/adapters/types.ts';
import { provider } from '../federation/harness.ts';
import { createAdministrator, type AdminKind } from '../administrators.ts';

const CORP = 'corp-sso';

/* A console session as `/admin/callback` leaves one, including how it signed in. */
async function signedIn(user: User, signedInWith: string | null) {
	const personal = await ensurePersonalGroup(user._id, user.email);
	const session = await adminSessionStore.create({
		userId: user._id,
		bucketId: ADMIN_BUCKET_ID,
		activeGroupId: personal._id,
		signedInWith,
		tokens: {},
		ttlSeconds: 60,
		absoluteTtlSeconds: 3600
	});
	return `${ADMIN_SESSION_COOKIE}=${session._id}`;
}

async function linked(kind: AdminKind, email: string) {
	const user = await createAdministrator(kind, email);
	return (
		(await getUserStore(ADMIN_BUCKET_ID).update(user._id, {
			federated: [
				{ providerId: CORP, sub: `sub-${email}`, linkedAt: new Date() }
			]
		})) ?? user
	);
}

async function send(
	method: string,
	path: string,
	cookie: string,
	body?: unknown
) {
	const res = await elysia.handle(
		new Request(`http://e.ly${path}`, {
			method,
			headers: { cookie, 'content-type': 'application/json' },
			...(body === undefined ? {} : { body: JSON.stringify(body) })
		})
	);
	return { status: res.status, body: (await res.json()) as unknown };
}

const passwordsOff = (cookie: string) =>
	send('PATCH', `/admin/api/buckets/${ADMIN_BUCKET_ID}`, cookie, {
		passwordLogin: false
	});

async function consoleBucket() {
	return getBucketStore().find(ADMIN_BUCKET_ID);
}

/**
 * @proves Password sign-in to the console goes off only for someone who has just come in through one of
 * the administrators' bucket's providers, and while it is off no change can leave every super
 * administrator without a way in; an operator with the server can always turn it back on.
 */
describe('keeping the console reachable', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'admin' });
	});

	// The administrators' bucket outlives this file; a provider left on it changes what later specs see.
	afterAll(async () => {
		await getBucketStore().update(ADMIN_BUCKET_ID, {
			federation: [],
			passwordLogin: true
		});
	});

	beforeEach(async () => {
		resetAdminMemoryStores();
		await ensureAdminSeed();
		await getBucketStore().update(ADMIN_BUCKET_ID, {
			federation: [
				provider('https://idp-reach.test', {
					id: CORP,
					emailTrusted: true,
					provisioning: 'existing_only',
					allowedEmailDomains: ['corp.example']
				})
			],
			passwordLogin: true
		});
	});

	it('turning password sign-in off is refused to a super administrator who signed in with a password', async () => {
		const root = await linked('super', 'root@corp.example');

		const res = await passwordsOff(await signedIn(root, null));

		expect(res.status).toBe(409);
		expect((await consoleBucket())?.passwordLogin).toBe(true);
	});

	it('turning password sign-in off is refused when the account is not linked at the provider the session came through', async () => {
		const root = await createAdministrator('super', 'root@corp.example');

		const res = await passwordsOff(await signedIn(root, CORP));

		expect(res.status).toBe(409);
		expect((await consoleBucket())?.passwordLogin).toBe(true);
	});

	it('turning password sign-in off is accepted after signing in through a linked provider', async () => {
		const root = await linked('super', 'root@corp.example');

		const res = await passwordsOff(await signedIn(root, CORP));

		expect(res.status).toBe(200);
		expect((await consoleBucket())?.passwordLogin).toBe(false);
	});

	describe('with password sign-in off', () => {
		let cookie: string;
		let root: User;

		beforeEach(async () => {
			root = await linked('super', 'root@corp.example');
			cookie = await signedIn(root, CORP);
			expect((await passwordsOff(cookie)).status).toBe(200);
		});

		it('disabling the last provider a super administrator can use is refused', async () => {
			const res = await send(
				'PATCH',
				`/admin/api/buckets/${ADMIN_BUCKET_ID}/federation/${CORP}`,
				cookie,
				{ enabled: false }
			);
			expect(res.status).toBe(409);
			expect((await consoleBucket())?.federation[0]?.enabled).toBe(true);
		});

		it('narrowing that provider so it no longer admits the super administrator is refused', async () => {
			const res = await send(
				'PATCH',
				`/admin/api/buckets/${ADMIN_BUCKET_ID}/federation/${CORP}`,
				cookie,
				{ allowedEmailDomains: ['elsewhere.example'] }
			);
			expect(res.status).toBe(409);
		});

		it('deleting that provider is refused', async () => {
			const res = await send(
				'DELETE',
				`/admin/api/buckets/${ADMIN_BUCKET_ID}/federation/${CORP}`,
				cookie
			);
			expect(res.status).toBe(409);
			expect((await consoleBucket())?.federation).toHaveLength(1);
		});

		it('deactivating or withdrawing the privilege of the last reachable super administrator is refused', async () => {
			// A second super administrator who signs in with a password, which is closed now.
			const other = await createAdministrator('super', 'other@corp.example');
			const otherCookie = await signedIn(other, null);

			const deactivate = await send(
				'DELETE',
				`/admin/api/admins/${root._id}`,
				otherCookie
			);
			const withdraw = await send(
				'DELETE',
				`/admin/api/admins/${root._id}/super-admin`,
				otherCookie
			);

			expect(deactivate.status).toBe(409);
			expect(withdraw.status).toBe(409);
		});

		it('a change that leaves another super administrator a way in is allowed', async () => {
			await linked('super', 'second@corp.example');

			const res = await send(
				'DELETE',
				`/admin/api/admins/${root._id}/super-admin`,
				cookie
			);

			expect(res.status).toBe(200);
		});
	});

	it('the readiness read names the administrators who would be shut out', async () => {
		const root = await linked('super', 'root@corp.example');
		const unlinked = await createAdministrator('plain', 'bob@corp.example');

		const res = await send(
			'GET',
			'/admin/api/admins/sign-in-readiness',
			await signedIn(root, CORP)
		);

		expect(res.status).toBe(200);
		expect(res.body).toMatchObject({
			passwordLogin: true,
			signedInWith: CORP,
			callerLinkedAt: [CORP],
			reachableSuperAdministrators: 1
		});
		const { unlinkedAdministrators } = res.body as {
			unlinkedAdministrators: { email: string }[];
		};
		expect(unlinkedAdministrators.map((a) => a.email)).toContain(
			unlinked.email
		);
	});

	it('the recovery command turns password sign-in back on and records it', async () => {
		await getBucketStore().update(ADMIN_BUCKET_ID, { passwordLogin: false });

		expect(await restorePasswordSignIn()).toBe('restored');
		expect((await consoleBucket())?.passwordLogin).toBe(true);
		const { entries } = await adminAuditStore.list({
			action: 'admin.passwordsignin.restore',
			targetId: ADMIN_BUCKET_ID
		});
		expect(entries.length).toBeGreaterThan(0);
		expect(await restorePasswordSignIn()).toBe('already_on');
	});
});
