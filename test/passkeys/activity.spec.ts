import {
	afterEach,
	beforeAll,
	beforeEach,
	describe,
	expect,
	it
} from 'bun:test';

import bootstrap from '../test_helper.js';
import {
	getBucketStore,
	getPersonActivityStore,
	getUserStore
} from 'lib/adapters/index.ts';
import { flushPersonActivityNow } from 'lib/person_activity/flush.ts';
import { createAdministrator } from '../administrators.ts';
import { cookieFor } from '../admin/ownership_fixtures.ts';
import { activityOf, from } from '../person_activity/helpers.ts';
import {
	HOME,
	HOSTING,
	newSignInMailsTo,
	ready
} from '../sign_in_alerts/helpers.ts';
import { present } from '../shape.ts';
import { SoftAuthenticator } from './authenticator.ts';
import {
	ACME,
	Browser,
	holdingPasskey,
	presentedAt,
	project,
	signInWithPasskey,
	signedInWithPasskey,
	textOf,
	type Project
} from './helpers.ts';

let acme: Project;
let cookie: string;

/**
 * @proves A sign-in with a passkey is told as "Passkey" wherever a sign-in method is shown or mailed: the person's
 * recent sign-ins, the email about a sign-in from somewhere new, and the project's activity; a refused passkey is
 * recorded against a person only when the passkey is theirs, never for one nobody here holds; a locked or deactivated
 * account turned away at the passkey door is recorded with what that door showed, which never mentions a password.
 */
describe('a passkey sign-in in the records', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'activity' });
		acme = await project(ACME);
		await getBucketStore().update(acme.bucketId, {
			displayName: 'Acme',
			newSignInAlerts: true
		});
		cookie = await cookieFor(await createAdministrator('super'));
	});

	beforeEach(async () => {
		await ready();
		from(HOME);
	});

	afterEach(() => {
		from(undefined);
	});

	it('reads "Passkey" in the person’s recent sign-ins', async () => {
		const { device } = await holdingPasskey(acme);
		const browser = await signedInWithPasskey(acme, device);
		await flushPersonActivityNow();

		const page = await browser.request(`${acme.prefix}/account/sign-ins`);

		const shown = textOf(await page.text());
		expect(shown).toContain('(just now) · Passkey');
	});

	it('names a passkey in the email about a sign-in from a new network', async () => {
		const { device, email } = await holdingPasskey(acme);
		await flushPersonActivityNow();
		from(HOSTING);

		await signInWithPasskey(new Browser(acme.origin), device, acme);
		await flushPersonActivityNow();

		const mail = present(newSignInMailsTo(email).at(-1), 'the email');
		expect(mail.text).toContain('How: Passkey');
	});

	it('reads "Passkey" in the project’s activity', async () => {
		const { device, accountId } = await holdingPasskey(acme);

		await signInWithPasskey(new Browser(acme.origin), device, acme);

		const { rows } = await activityOf(cookie, acme.bucketId, accountId);
		const methods = rows
			.filter((row) => row.kind === 'signIn' && row.outcome === 'let_in')
			.map((row) => row.words.method);
		expect(methods).toContain('Passkey');
	});

	it('records a refused passkey against the person whose passkey it is', async () => {
		const { device, accountId } = await holdingPasskey(acme);

		await presentedAt(acme, device, {
			context: { origin: 'http://other.e.ly' }
		});

		const { rows } = await activityOf(cookie, acme.bucketId, accountId);
		const refused = present(
			rows.find((row) => row.reason === 'passkey_refused'),
			'the refusal'
		);
		expect(refused.words.sawText).toBe(
			'This passkey isn’t for the project. Choose another one, or sign in another way.'
		);
	});

	for (const [state, change] of [
		[
			'locked',
			{ lockedLocally: { at: new Date(), by: 'an-administrator', reason: 'x' } }
		],
		['deactivated', { active: false }]
	] as const) {
		it(`records a ${state} account turned away at the passkey door with what that door showed`, async () => {
			const { device, accountId } = await holdingPasskey(acme);
			await getUserStore(acme.bucketId).update(accountId, change);

			await presentedAt(acme, device);

			const { rows } = await activityOf(cookie, acme.bucketId, accountId);
			const refused = present(
				rows.find((row) => row.reason === state),
				'the refusal'
			);
			expect(refused.words).toMatchObject({
				reason: `Right passkey, but the account is ${state}`,
				sawText:
					'This account can’t sign in right now. Ask the people who run the project.'
			});
		});
	}

	it('records nothing for a passkey nobody here holds', async () => {
		const stranger = new SoftAuthenticator();
		await stranger.create(
			{ challenge: 'AAAA', rp: { id: 'e.ly' }, user: { id: 'bm9ib2R5' } },
			{ origin: 'http://e.ly' }
		);
		const since = new Date();

		await presentedAt(acme, stranger);
		await flushPersonActivityNow();

		const refusals = await getPersonActivityStore().listRefusals(
			acme.bucketId,
			{ since, now: new Date(), limit: 100 }
		);
		expect(refusals.map((row) => row.reason)).not.toContain('passkey_refused');
	});
});
