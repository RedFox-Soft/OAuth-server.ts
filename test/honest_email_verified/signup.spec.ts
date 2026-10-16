import { describe, it, expect, beforeAll } from 'bun:test';
import bootstrap from '../test_helper.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { getUserStore } from 'lib/adapters/index.ts';
import { findAccount } from 'lib/addon/account.ts';
import {
	DEFAULT_REQUEST_BUCKET,
	OIDCContext
} from 'lib/helpers/oidc_context.ts';
import { call, superAdmin } from '../plans/admin.ts';
import { projectFor, signIn, signUp } from './sign_up.ts';

const CLIENT = 'honest-off-app';
let projectId: string;

/* What the ID token and userinfo carry for a person, as the token endpoint loads them for this application. */
async function releasedFor(sub: string) {
	const account = await findAccount(
		new OIDCContext({ params: {}, bucket: DEFAULT_REQUEST_BUCKET }),
		sub,
		{ payload: { clientId: CLIENT } }
	);
	if (!account) throw new Error('account not found');
	return account.claims('id_token', 'openid email');
}

async function person(email: string) {
	await signUp(CLIENT, email);
	const user = await getUserStore(projectId).findByEmail(email);
	if (!user) throw new Error('sign-up created no account');
	return user;
}

/**
 * @proves In a project that does not require email verification, a person who signs themselves up still signs in,
 * and every application is told their address is not verified until it is proven — here by an administrator marking
 * it — after which the next token says it is.
 */
describe('signing up where verification is not required', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'honest_email_verified' });
		await ensureAdminSeed();
		projectId = await projectFor(CLIENT, false);
	});

	it('records the address as not verified, and still signs the person in', async () => {
		const user = await person(`self-${Date.now()}@honest.test`);

		expect(user.verified).toBe(false);
		expect(await signIn(CLIENT, user.email)).toBe(303);
	});

	it('tells applications the address is not verified', async () => {
		const user = await person(`claim-${Date.now()}@honest.test`);

		expect(await releasedFor(user._id)).toMatchObject({
			email: user.email,
			email_verified: false
		});
	});

	it('tells them it is verified once it is proven', async () => {
		const user = await person(`proven-${Date.now()}@honest.test`);
		const operator = await superAdmin();

		const marked = await call(
			'POST',
			`/admin/api/projects/${projectId}/users/${user._id}/verified`,
			operator.cookie
		);

		expect(marked.status).toBe(200);
		expect((await releasedFor(user._id)).email_verified).toBe(true);
	});
});
