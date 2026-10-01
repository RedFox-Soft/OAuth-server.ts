import { describe, it, expect, beforeAll } from 'bun:test';
import bootstrap, { seedAccount, formAgent } from '../test_helper.ts';
import { backchannelResult } from 'lib/actions/authorization/backchannel_result.js';
import { Grant } from 'lib/models/grant.js';
import { isPlainObject } from 'lib/helpers/_/object.js';
import { amrOf } from './flow.ts';

const ACCOUNT = 'ciba-amr-account';

/*
 * Ask, have the end user's device report back — with the methods it used, or without — and collect
 * what the relying party is given.
 */
async function authenticate(amr?: string[]) {
	const asked = await formAgent.backchannel.post({
		client_id: 'ciba-poll',
		scope: 'openid',
		login_hint: ACCOUNT
	});
	const id = asked.data?.auth_req_id;
	if (!id) throw new Error('expected an auth_req_id');
	const grant = new Grant({ clientId: 'ciba-poll', accountId: ACCOUNT });
	grant.addOIDCScope('openid');
	await grant.save();
	await backchannelResult(id, grant, amr ? { amr } : {});
	const res = await formAgent.token.post({
		client_id: 'ciba-poll',
		grant_type: 'urn:openid:params:grant-type:ciba',
		auth_req_id: id
	});
	expect(res.response.status).toBe(200);
	return { data: isPlainObject(res.data) ? res.data : {} };
}

/**
 * @proves On the backchannel, where the authentication happens on the end user's own device, the
 * relying party is told the methods the deployment's integration reported — and nothing at all when
 * it reported none, because this server does not invent them.
 */
describe('authentication methods reported from a backchannel authentication', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'backchannel' });
		seedAccount(ACCOUNT);
	});

	it('carries the reported methods when the integration reports them', async () => {
		const token = await authenticate(['pwd', 'otp', 'mfa']);

		expect(amrOf(token)).toEqual(['mfa', 'otp', 'pwd']);
	});

	it('carries no amr when the integration reports none', async () => {
		const token = await authenticate();

		expect(amrOf(token)).toBeUndefined();
	});
});
