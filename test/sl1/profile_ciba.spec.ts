import { describe, it, expect, beforeAll } from 'bun:test';
import { generateKeyPair } from 'jose';

import bootstrap, { formAgent, seedAccount } from '../test_helper.ts';
import { backchannelResult } from 'lib/actions/authorization/backchannel_result.js';
import { Grant } from 'lib/models/grant.js';
import { dpopProof } from '../assertion_grants/helpers.ts';
import { CIBA_CLIENT_SECRET } from './profile_ciba.config.ts';

const PWD = 'urn:example:acr:pwd';
const MFA = 'urn:example:acr:mfa';
const ACCOUNT = 'sl1-ciba-account';

/**
 * @proves Under the IPSIE SL1 profile a backchannel authentication that does not satisfy the class the relying party
 * named in acr_values ends in a failed transaction, rather than tokens for a weaker sign-in.
 */
describe('acr_values on the backchannel under the IPSIE SL1 profile', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'profile_ciba' });
		seedAccount(ACCOUNT);
	});

	it('fails the transaction when the reported sign-in does not satisfy acr_values', async () => {
		const asked = await formAgent.backchannel.post({
			client_id: 'ciba-poll',
			client_secret: CIBA_CLIENT_SECRET,
			scope: 'openid',
			login_hint: ACCOUNT,
			acr_values: MFA
		});
		const id = asked.data?.auth_req_id;
		if (!id) throw new Error('expected an auth_req_id');
		const grant = new Grant({ clientId: 'ciba-poll', accountId: ACCOUNT });
		grant.addOIDCScope('openid');
		await grant.save();
		await backchannelResult(id, grant, { acr: PWD });

		const res = await formAgent.token.post(
			{
				client_id: 'ciba-poll',
				client_secret: CIBA_CLIENT_SECRET,
				grant_type: 'urn:openid:params:grant-type:ciba',
				auth_req_id: id
			},
			{ headers: { dpop: await dpopProof(await generateKeyPair('ES256')) } }
		);

		expect(res.error?.value).toMatchObject({ error: 'transaction_failed' });
	});
});
