import { describe, it, expect, beforeAll } from 'bun:test';
import bootstrap, {
	bindClientToBucket,
	agent,
	getHeader,
	locationParameter
} from '../test_helper.ts';
import { AuthorizationRequest } from '../AuthorizationRequest.ts';
import {
	getBucketStore,
	getUserStore,
	resetAdminMemoryStores
} from 'lib/adapters/index.ts';
import { elysia } from 'lib/index.ts';
import { UNASSIGNED_GROUP_ID } from 'lib/admin/consts.ts';
import { decode as decodeJWT } from 'lib/helpers/jwt.ts';
import epochTime from 'lib/helpers/epoch_time.ts';
import { encodeBase32, decodeBase32 } from 'lib/totp/base32.ts';
import { hotp, stepFor } from 'lib/totp/code.ts';
import { present } from '../shape.ts';
import { idTokenOf } from './response.ts';

const PASSWORD = 'correct horse battery';
const MFA = 'urn:example:acr:mfa';
const SECRET = encodeBase32(Buffer.from('12345678901234567890', 'ascii'));

let bucketId: string;

async function personWithCode(email: string): Promise<void> {
	const user = await getUserStore(bucketId).create(
		email,
		await Bun.password.hash(PASSWORD),
		true
	);
	await getUserStore(bucketId).update(user._id, {
		totp: {
			secret: SECRET,
			enrolledAt: new Date(),
			lastStep: 0,
			via: 'self'
		}
	});
}

function requiringMfa(): AuthorizationRequest {
	return new AuthorizationRequest({
		client_id: 'acr-app',
		scope: 'openid',
		claims: { id_token: { acr: { essential: true, value: MFA } } }
	});
}

async function post(
	path: string,
	cookie: string,
	fields: Record<string, string>
) {
	const res = await elysia.handle(
		new Request(`http://e.ly${path}`, {
			method: 'POST',
			headers: {
				'content-type': 'application/x-www-form-urlencoded',
				cookie
			},
			body: new URLSearchParams(fields).toString(),
			redirect: 'manual'
		})
	);
	return res.headers.get('location') ?? '';
}

/**
 * @proves An application that requires a multi-factor sign-in gets one from a person who set up an authenticator app
 * themselves, in a project that does not require one, through the ordinary sign-in: password, then code.
 */
describe('a required multi-factor context met by the person’s own factor', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'acr' });
		resetAdminMemoryStores();
		const bucket = await getBucketStore().create({
			ownerGroupId: UNASSIGNED_GROUP_ID,
			name: 'Own factor'
		});
		bucketId = bucket._id;
		await bindClientToBucket('acr-app', bucketId);
	});

	it('asks for the code after the password and answers with the multi-factor context', async () => {
		const email = `own-${Math.random()}@x.io`;
		await personWithCode(email);
		const auth = requiringMfa();
		const { response } = await agent.auth.get({ query: auth.params });
		const uid = getHeader(response, 'location').split('/')[2] ?? '';
		const cookie = present(response.headers.get('set-cookie'), 'a cookie');

		const afterPassword = await post(`/ui/${uid}/login`, cookie, {
			username: email,
			password: PASSWORD
		});
		expect(afterPassword).toBe(`/ui/${uid}/totp`);
		const resumed = await post(`/ui/${uid}/totp`, cookie, {
			code: hotp(decodeBase32(SECRET), stepFor(epochTime()))
		});
		expect(resumed).toContain('/acr/callback');
		const code = locationParameter(resumed, 'code');
		const token = await auth.getToken(code);
		expect(decodeJWT(idTokenOf(token)).payload.acr).toBe(MFA);
	});
});
