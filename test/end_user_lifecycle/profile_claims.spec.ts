import { describe, it, beforeAll, afterEach, expect, mock } from 'bun:test';

import { getUserStore } from 'lib/adapters/index.ts';
import { DEFAULT_BUCKET_ID } from 'lib/admin/consts.ts';
import nanoid from 'lib/helpers/nanoid.js';
import bootstrap, { type Setup } from '../test_helper.js';
import { signIn, userinfo } from './fixtures.ts';

/* A fresh username each time: usernames are unique in the bucket, and every case signs a new user in. */
function profileOf(userName: string) {
	return {
		userName,
		profile: { name: { givenName: 'Ada', familyName: 'Lovelace' } }
	};
}

/**
 * @proves A client application receives a user's profile as standard OpenID Connect claims, and
 * only under the scope that releases them (spec 069, FR-011).
 */
describe('a user with a provisioned profile', () => {
	let setup: Setup;

	beforeAll(async () => {
		setup = await bootstrap(import.meta.url);
	});

	afterEach(() => {
		mock.restore();
	});

	it('is described by preferred_username, given_name and family_name under the profile scope', async () => {
		const user = await signIn(setup, 'openid profile');
		const userName = `ada.${nanoid()}`;
		await getUserStore(DEFAULT_BUCKET_ID).update(
			user.accountId,
			profileOf(userName)
		);

		const claims = await userinfo(user.accessToken);

		expect(claims).toMatchObject({
			preferred_username: userName,
			given_name: 'Ada',
			family_name: 'Lovelace'
		});
	});

	it('discloses none of those claims without the profile scope', async () => {
		const user = await signIn(setup, 'openid');
		await getUserStore(DEFAULT_BUCKET_ID).update(
			user.accountId,
			profileOf(`ada.${nanoid()}`)
		);

		const claims = await userinfo(user.accessToken);

		expect(claims).not.toHaveProperty('preferred_username');
		expect(claims).not.toHaveProperty('given_name');
		expect(claims).not.toHaveProperty('family_name');
	});

	it('carries an administrator-set claim over the derived one of the same name', async () => {
		const user = await signIn(setup, 'openid profile');
		await getUserStore(DEFAULT_BUCKET_ID).update(user.accountId, {
			...profileOf(`ada.${nanoid()}`),
			claims: { given_name: 'Augusta' }
		});

		const claims = await userinfo(user.accessToken);

		expect(claims).toHaveProperty('given_name', 'Augusta');
	});
});
