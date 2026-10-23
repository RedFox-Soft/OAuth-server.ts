import { describe, it, expect, beforeAll } from 'bun:test';
import bootstrap, { seedAccount, formAgent } from '../test_helper.ts';
import { backchannelResult } from 'lib/actions/authorization/backchannel_result.js';
import { Grant } from 'lib/models/grant.js';
import { isPlainObject } from 'lib/helpers/_/object.js';
import { CIBA_CLIENT_SECRET } from './backchannel.config.ts';
import { expiryOf } from './expiry.ts';

const ACCOUNT = 'ciba-session-expiry-account';

/**
 * @proves A relying party authenticated over the backchannel, where there is no browser session, is told
 * when to send the person back all the same.
 */
describe('when a backchannel ID token says the relying party must send the person back', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'backchannel' });
		seedAccount(ACCOUNT);
	});

	it('the ID token carries session_expiry from the CIBA grant', async () => {
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
		await backchannelResult(id, grant, {});

		const res = await formAgent.token.post({
			client_id: 'ciba-poll',
			client_secret: CIBA_CLIENT_SECRET,
			grant_type: 'urn:openid:params:grant-type:ciba',
			auth_req_id: id
		});

		expect(res.response.status).toBe(200);
		const { iat, sessionExpiry } = expiryOf({
			data: isPlainObject(res.data) ? res.data : {}
		});
		expect(Number.isInteger(sessionExpiry)).toBe(true);
		expect(sessionExpiry).toBeGreaterThanOrEqual(iat + 300);
	});
});
