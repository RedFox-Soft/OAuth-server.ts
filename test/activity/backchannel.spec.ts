import { describe, it, expect, beforeAll } from 'bun:test';

import bootstrap, { formAgent, seedAccount } from '../test_helper.ts';
import { backchannelResult } from 'lib/actions/authorization/backchannel_result.js';
import { Grant } from 'lib/models/grant.js';
import { resetAdminMemoryStores } from 'lib/adapters/index.ts';
import { DEFAULT_BUCKET_ID } from 'lib/admin/consts.ts';
import { figureOf, startCounting, thisMonth } from './fixtures.ts';

const ACCOUNT = 'ciba-activity-account';

/**
 * @proves An end user who approves a back-channel authentication on their own device is counted as active
 * once the client receives its tokens, as a sign-in rather than a renewal.
 */
describe('active users approving a back-channel authentication', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'backchannel' });
		resetAdminMemoryStores();
		await startCounting();
		seedAccount(ACCOUNT);
	});

	it('counts an end user approving a back-channel request once the client receives its tokens', async () => {
		const before = await figureOf(DEFAULT_BUCKET_ID, thisMonth());
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
		await backchannelResult(id, grant, {});

		const tokens = await formAgent.token.post({
			client_id: 'ciba-poll',
			grant_type: 'urn:openid:params:grant-type:ciba',
			auth_req_id: id
		});

		expect(tokens.response.status).toBe(200);
		const after = await figureOf(DEFAULT_BUCKET_ID, thisMonth());
		expect(after.total - before.total).toBe(1);
		expect(after.byKind.local - before.byKind.local).toBe(1);
	});
});
