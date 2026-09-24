import { describe, it, beforeAll, expect } from 'bun:test';

import bootstrap, {
	DEFAULT_SESSION_COOKIE,
	seedAccount
} from '../test_helper.js';
import { elysia } from 'lib/index.js';
import { ISSUER } from 'lib/configs/env.js';
import { DEFAULT_BUCKET_ID } from 'lib/admin/consts.js';
import { Session } from 'lib/models/session.js';
import { Interaction } from 'lib/models/interaction.js';
import nanoid from '../../lib/helpers/nanoid.ts';
import epochTime from '../../lib/helpers/epoch_time.ts';

/**
 * @proves When a different account of the same bucket signs in during an interaction, the end user
 * is asked to sign out first, and confirming that sign-out carries it out.
 */
describe('an interaction completed by a different account of the same bucket', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'end_session' });
		seedAccount('alice');
		seedAccount('bob');
	});

	/* Alice holds the browser's sign-in; the interaction she started was completed by Bob. */
	async function resumeAsAnotherAccount() {
		const session = new Session({
			jti: nanoid(),
			accountId: 'alice',
			bucketId: DEFAULT_BUCKET_ID,
			loginTs: epochTime()
		});
		const sessionId = await session.save();
		const uid = nanoid();
		await new Interaction(uid, {
			cookieID: 'interaction-cookie',
			params: {
				client_id: 'client',
				redirect_uri: 'https://client.example.com/cb',
				response_type: 'code',
				scope: 'openid'
			},
			session: { uid: session.payload.uid, accountId: 'alice' },
			result: { login: { accountId: 'bob' } }
		}).save(60);

		const cookie = `_interaction=interaction-cookie; ${DEFAULT_SESSION_COOKIE}=${sessionId}`;
		const page = await elysia.handle(
			new Request(`http://localhost/ui/${uid}/resume`, { headers: { cookie } })
		);
		const xsrf = (await page.text()).match(/name="xsrf" value="([^"]+)"/)?.[1];
		return { uid, cookie, xsrf };
	}

	it('continues the interaction once the end user confirms the sign-out', async () => {
		const { uid, cookie, xsrf } = await resumeAsAnotherAccount();
		if (!xsrf) throw new Error('expected the sign-out confirmation form');

		const confirmed = await elysia.handle(
			new Request('http://localhost/logout/confirm', {
				method: 'POST',
				headers: {
					cookie,
					'content-type': 'application/x-www-form-urlencoded'
				},
				body: `xsrf=${xsrf}&logout=true`
			})
		);

		expect(confirmed.status).toBe(303);
		expect(confirmed.headers.get('location')).toBe(
			`${ISSUER}/ui/${uid}/resume`
		);
	});
});
