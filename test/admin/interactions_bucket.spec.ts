import { describe, it, expect, beforeAll } from 'bun:test';
import bootstrap, { agent, getHeader } from '../test_helper.ts';
import { AuthorizationRequest } from '../AuthorizationRequest.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import {
	getBucketStore,
	getUserStore,
	resetAdminMemoryStores
} from 'lib/adapters/index.ts';
import { ADMIN_BUCKET_ID, ADMIN_CLIENT_ID } from 'lib/admin/consts.ts';
import { elysia } from 'lib/index.ts';

// These specs prove the additive client -> bucket routing added to
// `POST ui/:uid/login`: the `admin-panel` client authenticates against the
// admin bucket, every other client keeps the default ('redfox') bucket. The
// branch is exercised end-to-end through the real authorization dance so a
// regression (e.g. the admin client wrongly using the default bucket) fails
// the suite.

const PASSWORD = 'correct horse battery';

// Start a real authorization request for `clientId` (no existing session, so the
// provider prompts login) and return the interaction uid + its `_interaction`
// cookie so we can POST credentials to /ui/:uid/login.
async function startLogin(clientId: string) {
	const auth = new AuthorizationRequest({
		client_id: clientId,
		scope: 'openid'
	});
	const { response } = await agent.auth.get({ query: auth.params });
	const location = getHeader(response, 'location');
	const uid = location.split('/')[2];
	const cookie = response.headers.get('set-cookie');
	if (!cookie) throw new Error('expected an interaction cookie from /auth');
	return { uid, cookie };
}

async function submitLogin(clientId: string, username: string) {
	const { uid, cookie } = await startLogin(clientId);
	const { response } = await agent
		.ui({ uid })
		.login.post({ username, password: PASSWORD }, { headers: { cookie } });
	return response.status;
}

/**
 * @proves Which bucket a client signs a user into is decided by the client, so console
 * credentials and end-user credentials cannot be crossed.
 */
describe('interaction login bucket routing', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'admin' });
		resetAdminMemoryStores();
		await ensureAdminSeed();
		// Seeded ONLY in the admin bucket.
		await getUserStore(ADMIN_BUCKET_ID).create(
			'admin-only@x.io',
			await Bun.password.hash(PASSWORD)
		);
		// Seeded ONLY in the default ('redfox') bucket.
		await getUserStore().create(
			'default-only@x.io',
			await Bun.password.hash(PASSWORD)
		);
		const deactivated = await getUserStore().create(
			'deactivated@x.io',
			await Bun.password.hash(PASSWORD)
		);
		await getUserStore().update(deactivated._id, { active: false });
	});

	// A successful login hands the flow back to the authorization pipeline (a
	// redirect); a failed credential/bucket lookup re-renders the login form (400).
	it('admin-panel client authenticates an admin-bucket user', async () => {
		expect(await submitLogin('admin-panel', 'admin-only@x.io')).toBe(303);
	});

	it('admin-panel client rejects a default-bucket user (wrong bucket)', async () => {
		expect(await submitLogin('admin-panel', 'default-only@x.io')).toBe(400);
	});

	it('non-admin client authenticates a default-bucket user', async () => {
		expect(await submitLogin('regular-app', 'default-only@x.io')).toBe(303);
	});

	it('non-admin client rejects an admin-bucket user (wrong bucket)', async () => {
		expect(await submitLogin('regular-app', 'admin-only@x.io')).toBe(400);
	});

	it('rejects a deactivated user (active:false)', async () => {
		expect(await submitLogin('regular-app', 'deactivated@x.io')).toBe(400);
	});

	/*
	 * The administrators' bucket is gated by the same rule as every bucket. Its lockout guard sits at the
	 * setting — the requirement cannot be turned on without mail delivery and without the acting
	 * administrator's own address proven — not at the door, so an administrator created before the
	 * requirement is checked at their next sign-in like anyone else.
	 */
	it('refuses an unverified administrator while administrators must verify their address, including one created before the requirement', async () => {
		const unverified = await getUserStore(ADMIN_BUCKET_ID).create(
			'unverified-admin@x.io',
			await Bun.password.hash(PASSWORD)
		);
		expect(unverified.verified).toBe(false);

		await getBucketStore().update(ADMIN_BUCKET_ID, {
			emailVerificationRequired: true
		});
		try {
			expect(await submitLogin('admin-panel', 'unverified-admin@x.io')).toBe(
				400
			);
		} finally {
			await getBucketStore().update(ADMIN_BUCKET_ID, {
				emailVerificationRequired: false
			});
		}
	});

	// The same flag gates an ordinary bucket.
	it('still gates an ordinary bucket on email verification', async () => {
		const user = await getUserStore().create(
			'unverified-regular@x.io',
			await Bun.password.hash(PASSWORD)
		);
		expect(user.verified).toBe(false);

		await getBucketStore().update('redfox', {
			emailVerificationRequired: true
		});
		try {
			expect(await submitLogin('regular-app', 'unverified-regular@x.io')).toBe(
				400
			);
		} finally {
			await getBucketStore().update('redfox', {
				emailVerificationRequired: false
			});
		}
	});
});

/**
 * @proves The console's sign-in page offers no door the administrators' bucket keeps shut, so an operator
 * is never sent to a refusal the page could have known about.
 */
describe("the console's sign-in page", () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'admin' });
		resetAdminMemoryStores();
		await ensureAdminSeed();
	});

	it('offers neither a registration nor a password-reset link while administrator registration is closed', async () => {
		const { uid, cookie } = await startLogin(ADMIN_CLIENT_ID);
		const res = await elysia.handle(
			new Request(`http://e.ly/ui/${uid}/login`, { headers: { cookie } })
		);
		const html = await res.text();

		expect(html).toContain('name="password"');
		expect(html).not.toContain(`/ui/${uid}/registration`);
		expect(html).not.toContain(`/ui/${uid}/forgot-password`);
	});
});
