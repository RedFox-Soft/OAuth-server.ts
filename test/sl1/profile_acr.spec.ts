import { describe, it, expect, beforeAll } from 'bun:test';

import bootstrap from '../test_helper.ts';
import { ApplicationConfig } from 'lib/configs/application.ts';
import { AuthorizationRequest } from '../AuthorizationRequest.ts';
import {
	Browser,
	PASSWORD,
	codeFor as oneTimeCode,
	seedBucket,
	seedUser,
	uidOf
} from '../amr/flow.ts';

const PWD = 'urn:example:acr:pwd';
const MFA = 'urn:example:acr:mfa';

/* Where the browser is sent after the sign-in form, and the second-factor form when `second` is set. */
async function afterSignIn(
	clientId: string,
	email: string,
	acrValues: string,
	{ second = false }: { second?: boolean } = {}
) {
	const browser = new Browser();
	const started = await browser.authorize(
		new AuthorizationRequest({
			client_id: clientId,
			scope: 'openid',
			acr_values: acrValues
		})
	);
	const uid = uidOf(started.headers.get('location'));
	let res = await browser.post(`/ui/${uid}/login`, {
		username: email,
		password: PASSWORD
	});
	if (second) {
		res = await browser.post(`/ui/${uid}/totp`, { code: oneTimeCode() });
	}
	return new URL(res.headers.get('location') ?? '', 'https://acr.example.com');
}

/**
 * @proves Under the IPSIE SL1 profile a relying party receives the authentication class it asked for in acr_values,
 * or a stronger one, or an error — never a code for a weaker sign-in, which is what it gets with the profile off.
 */
describe('acr_values under the IPSIE SL1 profile', () => {
	let passwordUser: string;
	let secondFactorUser: string;

	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'profile_acr' });
		const passwordOnly = await seedBucket('acr-pwd', ['acr-pwd-app']);
		const secondFactor = await seedBucket('acr-mfa', ['acr-mfa-app'], {
			totpRequired: true
		});
		passwordUser = await seedUser(passwordOnly);
		secondFactorUser = await seedUser(secondFactor, { enrolled: true });
	});

	it('ends a request for the multi-factor class in unmet_authentication_requirements after a password sign-in', async () => {
		const back = await afterSignIn('acr-pwd-app', passwordUser, MFA);

		expect(back.pathname).toContain('/callback');
		expect(back.searchParams.get('error')).toBe(
			'unmet_authentication_requirements'
		);
		expect(back.searchParams.get('state')).toBeTruthy();
		expect(back.searchParams.get('iss')).toBeTruthy();
	});

	it('answers a request for the password class with a code after a multi-factor sign-in', async () => {
		const back = await afterSignIn('acr-mfa-app', secondFactorUser, PWD, {
			second: true
		});

		expect(back.searchParams.get('code')).toBeTruthy();
	});

	it('answers the same multi-factor request with a code while the profile is off', async () => {
		ApplicationConfig['ipsieSl1.enabled'] = false;
		try {
			const back = await afterSignIn('acr-pwd-app', passwordUser, MFA);

			expect(back.searchParams.get('code')).toBeTruthy();
		} finally {
			ApplicationConfig['ipsieSl1.enabled'] = true;
		}
	});
});
