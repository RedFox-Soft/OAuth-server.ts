import { describe, it, expect, beforeAll, afterAll } from 'bun:test';
import { Type } from '@sinclair/typebox';
import bootstrap from '../test_helper.ts';
import { configStore, resetAdminMemoryStores } from 'lib/adapters/index.ts';
import { decode as decodeJWT } from 'lib/helpers/jwt.ts';
import { shaped } from 'test/shape.ts';
import { idTokenOf } from '../acr/response.ts';
import { seedBucket } from '../amr/flow.ts';
import {
	discoveryDocument,
	saveSettings,
	superAdminCookie
} from '../settings_apply/helpers.ts';
import {
	authorizationCodeToken,
	deviceCodeToken,
	refreshTokenToken
} from './grants.ts';

/* test/amr/amr.config.ts's name for the password-only sign-in. */
const PWD = 'urn:example:acr:pwd';

function claimsOf(res: { data: unknown }) {
	return decodeJWT(idTokenOf(res)).payload;
}

async function supportedClaims() {
	return shaped(
		Type.Object({ claims_supported: Type.Array(Type.String()) }),
		await discoveryDocument()
	).claims_supported;
}

/**
 * @proves A relying party is told, in every ID token and without asking, when the person last
 * authenticated and which authentication context that satisfied — as IPSIE SL1 §3.2.1 requires — and can
 * discover that it will be, whatever claims setting the operator saved.
 */
describe('what every ID token says about the sign-in, unasked', () => {
	let bucketId: string;

	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'sl1' });
		resetAdminMemoryStores();
		await configStore.set({});
		bucketId = await seedBucket('SL1 claims', ['amr-app', 'amr-tv']);
	});

	afterAll(async () => {
		await configStore.set({});
	});

	for (const [grant, tokenFor] of [
		['authorization code', authorizationCodeToken],
		['refresh token', refreshTokenToken],
		['device code', deviceCodeToken]
	] as const) {
		it(`carries auth_time and acr from the ${grant} grant when the request asked for neither`, async () => {
			const claims = claimsOf(await tokenFor(bucketId));

			expect(typeof claims.auth_time).toBe('number');
			expect(claims.auth_time).toBeLessThanOrEqual(Number(claims.iat));
			expect(claims.acr).toBe(PWD);
		});
	}

	it('advertises auth_time and acr after an administrator saves a claims setting that names neither', async () => {
		const saved = await saveSettings(await superAdminCookie(), {
			claims: { openid: ['sub'] }
		});
		expect(saved.status).toBe(200);

		const supported = await supportedClaims();
		expect(supported).toContain('auth_time');
		expect(supported).toContain('acr');
	});
});
