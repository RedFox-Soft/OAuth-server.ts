import {
	afterEach,
	beforeAll,
	beforeEach,
	describe,
	expect,
	it,
	setSystemTime
} from 'bun:test';

import bootstrap, { agent } from '../test_helper.js';
import { getUserStore } from 'lib/adapters/index.ts';
import { DEFAULT_BUCKET_ID } from 'lib/admin/consts.ts';
import { configuration } from 'lib/configs/application.ts';
import { resetSentEmails } from 'lib/mail/mailer.ts';
import { RefreshToken } from 'lib/models/refresh_token.js';
import { Grant } from 'lib/models/grant.js';
import { AuthorizationRequest } from '../AuthorizationRequest.ts';
import { present } from '../shape.ts';
import {
	AGENT,
	apis,
	Browser,
	FILES,
	mailOn,
	payloadOf,
	person,
	project,
	redeem,
	renew,
	requireOnFiles,
	SECRET,
	signIn,
	tokensFrom,
	type Tokens
} from './helpers.ts';

async function signedIn(withCode: boolean): Promise<Tokens> {
	const { email, accountId } = await person();
	if (withCode) {
		await getUserStore(DEFAULT_BUCKET_ID).update(accountId, {
			totp: { secret: SECRET, enrolledAt: new Date(), lastStep: 0, via: 'self' }
		});
	}
	const reached = await signIn(new Browser(), email, withCode);
	return tokensFrom(reached.auth, reached.url);
}

function refreshTokenOf(tokens: Tokens): string {
	return present(tokens.refresh_token, 'a refresh token');
}

/**
 * @proves No token for an API that requires a code or a recent sign-in is issued on the strength of a sign-in that
 * does not meet it, through a code issued before the requirement or a renewal; a renewal so refused spends nothing, so
 * a retry is refused the same way and never revokes the person's sign-in, which keeps renewing for the other APIs;
 * and introspection tells an API's own server how and when the person signed in.
 */
describe('tokens for an API that requires a code or a recent sign-in', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	beforeEach(async () => {
		resetSentEmails();
		await mailOn();
		await project({ totpSelfService: true });
		await apis();
	});

	afterEach(() => {
		setSystemTime();
	});

	it('refuses a code issued before the requirement, from a sign-in without one', async () => {
		const { email } = await person();
		const reached = await signIn(new Browser(), email, false);
		const code = present(
			new URL(reached.url).searchParams.get('code'),
			'a code'
		);
		await requireOnFiles({ requireCode: true });

		const { error } = await redeem(reached.auth, code, FILES);

		expect(error?.status).toBe(400);
		expect(error?.value).toMatchObject({ error: 'invalid_grant' });
	});

	it('refuses a renewal for the API without spending it, never revokes the sign-in on a retry, and still renews it for anything else', async () => {
		const tokens = await signedIn(false);
		const refreshToken = refreshTokenOf(tokens);
		await requireOnFiles({ requireCode: true });

		const first = await renew(refreshToken, FILES);
		const retry = await renew(refreshToken, FILES);
		const other = await renew(refreshToken);

		expect(first.error?.value).toMatchObject({ error: 'invalid_grant' });
		expect(retry.error?.value).toMatchObject({ error: 'invalid_grant' });
		expect(other.status).toBe(200);
		expect(present(other.data, 'a renewal').refresh_token).toBeString();
	});

	it('keeps the grant behind a refused renewal standing', async () => {
		const tokens = await signedIn(false);
		const refreshToken = refreshTokenOf(tokens);
		const stored = present(await RefreshToken.find(refreshToken), 'the token');
		await requireOnFiles({ requireCode: true });

		await renew(refreshToken, FILES);
		await renew(refreshToken, FILES);

		const grant = await Grant.find(present(stored.payload.grantId, 'a grant'));
		expect(grant).toBeDefined();
		expect(await RefreshToken.find(refreshToken)).toBeDefined();
	});

	it('keeps renewing a sign-in that had a code', async () => {
		const tokens = await signedIn(true);
		await requireOnFiles({ requireCode: true });

		const renewed = await renew(refreshTokenOf(tokens), FILES);

		expect(renewed.status).toBe(200);
		expect(
			payloadOf(present(renewed.data, 'a renewal').access_token)
		).toMatchObject({ aud: FILES, acr: configuration.acrMap.multi_factor });
	});

	it('refuses a renewal once the sign-in is older than the API allows, however recent the renewal', async () => {
		const tokens = await signedIn(true);
		await requireOnFiles({ signInEveryMinutes: 60 });
		setSystemTime(Date.now() + 2 * 3_600_000);

		const renewed = await renew(refreshTokenOf(tokens), FILES);

		expect(renewed.error?.value).toMatchObject({ error: 'invalid_grant' });
	});

	it('tells an API that checks its own tokens how and when the person signed in', async () => {
		await apis({}, 'opaque');
		const tokens = await signedIn(true);

		const { data } = await agent.token.introspect.post(
			{ token: tokens.access_token },
			{ headers: AuthorizationRequest.basicAuthHeader(AGENT, 'secret') }
		);

		expect(data).toMatchObject({
			active: true,
			acr: configuration.acrMap.multi_factor
		});
		expect(typeof (data as { auth_time?: unknown }).auth_time).toBe('number');
	});
});
