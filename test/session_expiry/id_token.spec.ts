import { shownAccount } from '../consent_form.js';
import { describe, it, expect, beforeAll, afterAll } from 'bun:test';
import bootstrap, { agent } from '../test_helper.ts';
import { AuthorizationRequest } from '../AuthorizationRequest.ts';
import { configStore, resetAdminMemoryStores } from 'lib/adapters/index.ts';
import { refreshTokenOf } from '../acr/response.ts';
import { saveSettings, superAdminCookie } from '../settings_apply/helpers.ts';
import {
	Browser,
	seedBucket,
	seedUser,
	signIn,
	uidOf,
	PASSWORD
} from '../amr/flow.ts';
import { expiryOf } from './expiry.ts';

const DAY = 24 * 60 * 60;

let bucketId: string;

function request(extra: Record<string, string> = {}) {
	return new AuthorizationRequest({
		client_id: 'amr-app',
		scope: 'openid',
		...extra
	});
}

/**
 * @proves A relying party's ID token says when it must send the person back, whichever grant issued it,
 * never sooner than five minutes after it was issued and never later than the bound the operator set.
 */
describe('when an ID token says the relying party must send the person back', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'session_expiry' });
		resetAdminMemoryStores();
		await configStore.set({});
		bucketId = await seedBucket('Session expiry', ['amr-app', 'amr-tv']);
	});

	afterAll(async () => {
		await configStore.set({});
	});

	it('the ID token carries session_expiry from the authorization code grant', async () => {
		const auth = request();
		const token = await auth.getToken(
			await signIn(new Browser(), auth, await seedUser(bucketId))
		);

		const { iat, sessionExpiry } = expiryOf(token);
		expect(Number.isInteger(sessionExpiry)).toBe(true);
		expect(sessionExpiry).toBeGreaterThanOrEqual(iat + 300);
	});

	it('the ID token carries session_expiry from the refresh token grant', async () => {
		const auth = request({ scope: 'openid offline_access', prompt: 'consent' });
		const first = await auth.getToken(
			await signIn(new Browser(), auth, await seedUser(bucketId))
		);

		const refreshed = await agent.token.post({
			client_id: 'amr-app',
			grant_type: 'refresh_token',
			refresh_token: refreshTokenOf(first)
		});

		expect(refreshed.response.status).toBe(200);
		const { iat, sessionExpiry } = expiryOf(refreshed);
		expect(Number.isInteger(sessionExpiry)).toBe(true);
		expect(sessionExpiry).toBeGreaterThanOrEqual(iat + 300);
	});

	it('the ID token carries session_expiry from the device code grant', async () => {
		const email = await seedUser(bucketId);
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
		const signedIn = await browser.post(`/ui/${uid}/login`, {
			username: email,
			password: PASSWORD
		});
		const consentUid = uidOf(signedIn.headers.get('location'));
		await browser.post(`/ui/${consentUid}/consent`, {
			action: 'allow',
			accountId: await shownAccount(consentUid)
		});

		const polled = await agent.token.post({
			client_id: 'amr-tv',
			grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
			device_code
		});

		const { iat, sessionExpiry } = expiryOf(polled);
		expect(Number.isInteger(sessionExpiry)).toBe(true);
		expect(sessionExpiry).toBeGreaterThanOrEqual(iat + 300);
	});

	it('session_expiry is iat plus 24 hours with the default bound', async () => {
		const auth = request();
		const token = await auth.getToken(
			await signIn(new Browser(), auth, await seedUser(bucketId))
		);

		const { iat, sessionExpiry } = expiryOf(token);
		expect(sessionExpiry).toBe(iat + DAY);
	});

	it('session_expiry follows a bound the operator changed, without a restart', async () => {
		const cookie = await superAdminCookie();
		const saved = await saveSettings(cookie, {
			'idToken.relyingPartySessionLifetime': 600
		});
		expect(saved.status).toBe(200);
		try {
			const auth = request();
			const token = await auth.getToken(
				await signIn(new Browser(), auth, await seedUser(bucketId))
			);

			const { iat, sessionExpiry } = expiryOf(token);
			expect(sessionExpiry).toBe(iat + 600);
		} finally {
			await saveSettings(cookie, {
				'idToken.relyingPartySessionLifetime': DAY
			});
		}
	});
});
