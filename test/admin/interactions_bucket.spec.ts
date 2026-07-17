import { describe, it, expect, beforeAll } from 'bun:test';
import bootstrap, { agent, getHeader } from '../test_helper.ts';
import { AuthorizationRequest } from '../AuthorizationRequest.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { getUserStore, resetAdminMemoryStores } from 'lib/adapters/index.ts';
import { ADMIN_BUCKET_ID } from 'lib/admin/consts.ts';

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

describe('interaction login bucket routing', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'admin' });
		resetAdminMemoryStores();
		await ensureAdminSeed();
		// Seeded ONLY in the admin bucket.
		await getUserStore(ADMIN_BUCKET_ID).create(
			'admin-only@x.io',
			await Bun.password.hash(PASSWORD),
			['project_admin']
		);
		// Seeded ONLY in the default ('redfox') bucket.
		await getUserStore().create(
			'default-only@x.io',
			await Bun.password.hash(PASSWORD)
		);
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
});
