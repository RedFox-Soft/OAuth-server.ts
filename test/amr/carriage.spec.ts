import { describe, it, expect, beforeAll } from 'bun:test';
import bootstrap, { agent } from '../test_helper.ts';
import { AuthorizationRequest } from '../AuthorizationRequest.ts';
import { resetAdminMemoryStores } from 'lib/adapters/index.ts';
import { addons } from 'lib/addon/index.js';
import { refreshTokenOf } from '../acr/response.ts';
import {
	Browser,
	amrOf,
	codeFor,
	seedBucket,
	seedUser,
	signIn,
	uidOf,
	PASSWORD
} from './flow.ts';

let mfaBucketId: string;

async function refreshedAfterTwoFactors() {
	const email = await seedUser(mfaBucketId, { enrolled: true });
	const auth = new AuthorizationRequest({
		client_id: 'amr-mfa-app',
		scope: 'openid offline_access',
		prompt: 'consent'
	});
	const first = await auth.getToken(
		await signIn(new Browser(), auth, email, { second: true })
	);
	return agent.token.post({
		client_id: 'amr-mfa-app',
		grant_type: 'refresh_token',
		refresh_token: refreshTokenOf(first)
	});
}

async function devicePoll(deviceCode: string) {
	return agent.token.post({
		client_id: 'amr-tv',
		grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
		device_code: deviceCode
	});
}

/**
 * @proves The authentication methods a relying party is told of describe the sign-in that happened
 * whichever way its tokens were issued — on refresh, through the device flow, and when it asked
 * about them through the claims parameter — and asking never fails the request.
 */
describe('the authentication methods on every way a token is issued', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'amr' });
		resetAdminMemoryStores();
		mfaBucketId = await seedBucket('AMR carriage', ['amr-mfa-app', 'amr-tv'], {
			totpRequired: true
		});
	});

	it('carries the original methods when tokens are refreshed with rotation', async () => {
		// A public client's refresh tokens rotate by default.
		const refreshed = await refreshedAfterTwoFactors();

		expect(refreshed.response.status).toBe(200);
		expect(amrOf(refreshed)).toEqual(['mfa', 'otp', 'pwd']);
	});

	it('carries the original methods when tokens are refreshed without rotation', async () => {
		addons.override({ rotateRefreshToken: () => false });

		const refreshed = await refreshedAfterTwoFactors();

		expect(refreshed.response.status).toBe(200);
		expect(amrOf(refreshed)).toEqual(['mfa', 'otp', 'pwd']);
	});

	it('carries the methods of the sign-in that approved a device', async () => {
		const email = await seedUser(mfaBucketId, { enrolled: true });
		const started = await agent.device.auth.post({
			client_id: 'amr-tv',
			scope: 'openid'
		});
		const { device_code, user_code } = started.data ?? {};
		if (!device_code || !user_code) throw new Error('expected a device code');
		const browser = new Browser();
		const page = await browser.request('/device');
		const xsrf = /name="xsrf" value="([0-9a-f]+)"/.exec(await page.text())?.[1];
		const confirmed = await browser.post('/device', {
			xsrf: xsrf ?? '',
			user_code,
			confirm: 'yes'
		});
		const uid = uidOf(confirmed.headers.get('location'));
		await browser.post(`/ui/${uid}/login`, {
			username: email,
			password: PASSWORD
		});
		const signedIn = await browser.post(`/ui/${uid}/totp`, { code: codeFor() });
		// Consent is its own interaction, under a uid of its own.
		const consentUid = uidOf(signedIn.headers.get('location'));
		await browser.post(`/ui/${consentUid}/consent`, { action: 'allow' });

		expect(amrOf(await devicePoll(device_code))).toEqual(['mfa', 'otp', 'pwd']);
	});

	it('completes the request and reports the methods used when amr is required with values the sign-in did not use', async () => {
		const email = await seedUser(mfaBucketId, { enrolled: true });
		// OIDC Core §5.5.1 gives `amr` no failure rule: asking for it can never refuse or loop.
		const auth = new AuthorizationRequest({
			client_id: 'amr-mfa-app',
			scope: 'openid',
			claims: { id_token: { amr: { essential: true, values: ['hwk'] } } }
		});

		const code = await signIn(new Browser(), auth, email, { second: true });

		expect(amrOf(await auth.getToken(code))).toEqual(['mfa', 'otp', 'pwd']);
	});
});
