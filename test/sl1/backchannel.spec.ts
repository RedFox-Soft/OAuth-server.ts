import { describe, it, expect, beforeAll } from 'bun:test';
import bootstrap, { seedAccount, formAgent } from '../test_helper.ts';
import { backchannelResult } from 'lib/actions/authorization/backchannel_result.js';
import { Grant } from 'lib/models/grant.js';
import { decode as decodeJWT } from 'lib/helpers/jwt.ts';
import { isPlainObject } from 'lib/helpers/_/object.js';
import { idTokenOf } from '../acr/response.ts';
import { CIBA_CLIENT_SECRET } from './backchannel.config.ts';

const ACCOUNT = 'ciba-sl1-account';
const MFA = 'urn:example:acr:mfa';

/* Ask, have the end user's device report back with what it knows of the authentication, and collect the ID token. */
async function authenticate(reported: { acr?: string; authTime?: number }) {
	const asked = await formAgent.backchannel.post({
		client_id: 'ciba-poll',
		client_secret: CIBA_CLIENT_SECRET,
		scope: 'openid',
		login_hint: ACCOUNT
	});
	const id = asked.data?.auth_req_id;
	if (!id) throw new Error('expected an auth_req_id');
	const grant = new Grant({ clientId: 'ciba-poll', accountId: ACCOUNT });
	grant.addOIDCScope('openid');
	await grant.save();
	await backchannelResult(id, grant, reported);
	const res = await formAgent.token.post({
		client_id: 'ciba-poll',
		client_secret: CIBA_CLIENT_SECRET,
		grant_type: 'urn:openid:params:grant-type:ciba',
		auth_req_id: id
	});
	expect(res.response.status).toBe(200);
	return decodeJWT(idTokenOf({ data: isPlainObject(res.data) ? res.data : {} }))
		.payload;
}

/**
 * @proves On the backchannel, where the authentication happens on the end user's own device, a relying party
 * is told unasked when it happened and which context it satisfied whenever the integration reported them —
 * and never a value the server made up when it did not.
 */
describe('what a backchannel ID token says about the authentication, unasked', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'backchannel' });
		seedAccount(ACCOUNT);
	});

	it('carries the reported auth_time and acr when the request asked for neither', async () => {
		const authTime = Math.floor(Date.now() / 1000) - 30;

		const claims = await authenticate({ acr: MFA, authTime });

		expect(claims.auth_time).toBe(authTime);
		expect(claims.acr).toBe(MFA);
	});

	it('carries neither auth_time nor acr when the integration reported neither', async () => {
		const claims = await authenticate({});

		expect(claims).not.toHaveProperty('auth_time');
		expect(claims).not.toHaveProperty('acr');
	});
});
