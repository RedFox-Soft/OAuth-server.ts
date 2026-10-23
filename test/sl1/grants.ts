import { shownAccount } from '../consent_form.js';
import { agent } from '../test_helper.ts';
import { AuthorizationRequest } from '../AuthorizationRequest.ts';
import { refreshTokenOf } from '../acr/response.ts';
import { Browser, seedUser, signIn, uidOf, PASSWORD } from '../amr/flow.ts';

/*
 * One ID token from each browser grant, for a person signed in with a password: the cases about what every
 * ID token carries run once per grant, because each grant assembles its token in code of its own. The
 * clients are test/amr/amr.config.ts's — `amr-app` and `amr-tv` — so a spec reuses that config.
 */

export async function authorizationCodeToken(bucketId: string) {
	const auth = new AuthorizationRequest({
		client_id: 'amr-app',
		scope: 'openid'
	});
	return auth.getToken(
		await signIn(new Browser(), auth, await seedUser(bucketId))
	);
}

export async function refreshTokenToken(bucketId: string) {
	const auth = new AuthorizationRequest({
		client_id: 'amr-app',
		scope: 'openid offline_access',
		prompt: 'consent'
	});
	const first = await auth.getToken(
		await signIn(new Browser(), auth, await seedUser(bucketId))
	);
	return agent.token.post({
		client_id: 'amr-app',
		grant_type: 'refresh_token',
		refresh_token: refreshTokenOf(first)
	});
}

export async function deviceCodeToken(bucketId: string) {
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
	return agent.token.post({
		client_id: 'amr-tv',
		grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
		device_code
	});
}
