import {
	afterEach,
	beforeAll,
	beforeEach,
	describe,
	expect,
	it,
	mock
} from 'bun:test';
import { Type } from '@sinclair/typebox';

import bootstrap from '../test_helper.js';
import { assertNoPendingInterceptors } from '../fetch_mock.js';
import { getUserStore } from 'lib/adapters/index.ts';
import { DEFAULT_BUCKET_ID } from 'lib/admin/consts.ts';
import { resetKeyringForTests } from 'lib/sealing/keyring.ts';
import { shaped } from '../shape.js';
import { TEST_KEYRING } from '../sealing/fixtures.ts';
import { createAdministrator } from '../administrators.ts';
import { cookieFor } from '../admin/ownership_fixtures.ts';
import {
	PAGE,
	admin,
	seededAccount,
	signedInPerson
} from '../connected_services/harness.ts';
import { linkedProject } from './harness.ts';

const Listed = Type.Object({
	accounts: Type.Array(
		Type.Object({
			upstreamId: Type.String(),
			via: Type.Optional(Type.String())
		})
	)
});

/**
 * @proves A person and an administrator can tell how each connected account was connected: on the account page,
 * through an agent's link, or when the person signed in through a linked provider.
 */
describe('how a connected account was connected', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'signin_tokens' });
	});

	beforeEach(() => {
		resetKeyringForTests(TEST_KEYRING);
	});

	afterEach(() => {
		assertNoPendingInterceptors();
		mock.restore();
	});

	it('is said on the account page for an account connected when the person signed in', async () => {
		const linked = await linkedProject({ signsIn: false });
		const person = await signedInPerson();
		await seededAccount(person, linked.service, { via: 'sign_in' });

		const page = await (await person.browser.request(PAGE)).text();

		expect(page).toContain('Connected when you signed in with Acme SSO.');
	});

	it('is said in the person’s own language', async () => {
		const linked = await linkedProject({ signsIn: false });
		const person = await signedInPerson();
		await getUserStore(DEFAULT_BUCKET_ID).update(person.accountId, {
			profile: { locale: 'ru' }
		});
		await seededAccount(person, linked.service, { via: 'sign_in' });

		const page = await (await person.browser.request(PAGE)).text();

		expect(page).toContain('Подключён, когда вы вошли через Acme SSO.');
	});

	it('is given to an administrator for each way, and for none on an older account', async () => {
		const linked = await linkedProject({ signsIn: false });
		const person = await signedInPerson();
		await seededAccount(person, linked.service, {
			upstreamId: 'page',
			via: 'account_page'
		});
		await seededAccount(person, linked.service, {
			upstreamId: 'link',
			via: 'connect_link'
		});
		await seededAccount(person, linked.service, {
			upstreamId: 'sign-in',
			via: 'sign_in'
		});
		await seededAccount(person, linked.service, { upstreamId: 'older' });
		const cookie = await cookieFor(await createAdministrator('super'));

		const answer = await admin(
			cookie,
			'GET',
			`/admin/api/projects/${DEFAULT_BUCKET_ID}/users/${person.accountId}/connected-accounts`
		);

		const via = Object.fromEntries(
			shaped(Listed, answer.json).accounts.map((account) => [
				account.upstreamId,
				account.via ?? null
			])
		);
		expect(via).toEqual({
			page: 'account_page',
			link: 'connect_link',
			'sign-in': 'sign_in',
			older: null
		});
	});
});
