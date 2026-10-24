import { describe, it, expect, beforeAll } from 'bun:test';

import bootstrap from '../test_helper.ts';
import { adminCookie } from '../end_user_lifecycle/fixtures.ts';
import { connect, scimBucket, slugOf } from '../scim/helpers.ts';
import { admin, basic, token } from '../provisioning/helpers.ts';

/**
 * @proves A provisioning connection still obtains its SCIM token while the IPSIE SL1 profile is on, without a DPoP
 * proof: its token reaches only the SCIM endpoint, which SL1 does not govern, and directory services hold no DPoP keys.
 */
describe('a SCIM connection under the IPSIE SL1 profile', () => {
	let cookie: string;

	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'profile_scim' });
		cookie = await adminCookie();
	});

	it('obtains its token without a DPoP proof', async () => {
		const c = await connect(await scimBucket());
		const issued = await admin(
			'POST',
			`/admin/api/projects/${c.bucket._id}/provisioning-connections/${c.connection._id}/credentials`,
			cookie,
			{ kind: 'secret' }
		);
		expect(issued.status).toBe(201);

		const granted = await token(
			`/${slugOf(c.bucket)}/token`,
			{ grant_type: 'client_credentials' },
			basic(`scim-${c.connection._id}`, issued.json.secret as string)
		);

		expect(granted.status).toBe(200);
	});
});
