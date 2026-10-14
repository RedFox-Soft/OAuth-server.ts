import { describe, it, expect, beforeAll, afterEach } from 'bun:test';

import bootstrap, { setSeedClaims, type Setup } from '../test_helper.js';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { getBucketStore } from 'lib/adapters/index.ts';
import { DEFAULT_BUCKET_ID } from 'lib/admin/consts.ts';
import { CONSENT_TEXTS } from 'lib/i18n/texts/consent/index.ts';
import { text as fill } from 'lib/i18n/message.tsx';

const T = CONSENT_TEXTS.en;
import { openConsent } from './flow.ts';

/**
 * @proves A person signing in to an application of the organization that runs their account is told, in
 * one sentence, who is asking, which of their accounts is agreeing and what will be shared — and nothing
 * the server could not stand behind.
 */
describe('the consent page for a sign-in to the organization’s own app', () => {
	let setup: Setup;

	beforeAll(async () => {
		setup = await bootstrap(import.meta.url, { config: 'consent_page' });
		await ensureAdminSeed();
	});

	afterEach(async () => {
		setSeedClaims(undefined);
		await getBucketStore().update(DEFAULT_BUCKET_ID, {
			displayName: undefined
		});
	});

	async function signIn(claims: Record<string, unknown>) {
		setSeedClaims(claims);
		return setup.login({ scope: 'openid' });
	}

	it('names the app, the account and the shared data in one sentence when only sign-in data is asked for', async () => {
		const cookie = await signIn({
			email: 'anna@example.com',
			name: 'Anna Ivanova',
			picture: 'https://pictures.example/anna.png'
		});

		const page = await openConsent(
			{ client_id: 'own-app', scope: 'openid profile email' },
			cookie
		);

		expect(page.text).toContain(
			fill(T.headline.signIn, { app: 'Acme Billing' })
		);
		expect(page.text).toContain('billing.acme.test');
		expect(page.text).toContain(
			fill(T.account.signedInAs, { account: 'anna@example.com' })
		);
		expect(page.text).toContain(T.categories.profile);
		expect(page.text).toContain(T.categories.email);
		expect(page.text).toContain(T.signIn.noPassword);
		expect(page.view.warning).toBeUndefined();
		// The account's internal identifier is the one thing it must never be shown as.
		expect(page.text).not.toContain(page.view.account.id);
	});

	it('leaves out the profile photo when the person has none', async () => {
		const cookie = await signIn({ name: 'Anna Ivanova' });

		const page = await openConsent(
			{ client_id: 'own-app', scope: 'openid profile' },
			cookie
		);

		expect(page.text).toContain(T.categories.profileName);
		expect(page.text).not.toContain(T.categories.profilePhoto);
		expect(page.text).not.toContain(T.categories.profile);
	});

	it('names the service by its address when the bucket has no display name', async () => {
		const cookie = await signIn({});

		const page = await openConsent(
			{ client_id: 'own-app', scope: 'openid email' },
			cookie
		);

		expect(page.view.service.displayName).toBeUndefined();
		expect(page.text).toContain(
			fill(T.signIn.shares, { service: page.view.service.host })
		);
	});

	it('names the service by the bucket’s display name, never its internal name, when it has one', async () => {
		await getBucketStore().update(DEFAULT_BUCKET_ID, {
			displayName: 'Acme ID'
		});
		const bucket = await getBucketStore().find(DEFAULT_BUCKET_ID);
		const cookie = await signIn({});

		const page = await openConsent(
			{ client_id: 'own-app', scope: 'openid email' },
			cookie
		);

		expect(page.text).toContain(fill(T.signIn.shares, { service: 'Acme ID' }));
		expect(page.text).not.toContain(bucket?.name ?? '\u0000');
	});

	it('lists everything under groups when the request also asks for long-lived access', async () => {
		const cookie = await signIn({});

		const page = await openConsent(
			{
				client_id: 'own-app',
				scope: 'openid email offline_access',
				prompt: 'consent'
			},
			cookie
		);

		expect(page.view.mode).toBe('full');
		expect(page.text).toContain(
			fill(T.headline.ownAccess, {
				app: 'Acme Billing',
				service: page.view.service.host
			})
		);
		expect(page.text).toContain(T.groups.see);
	});
});

/**
 * @proves A person shown the wrong account on the consent page can switch to another one — unless the
 * application asked for a particular account, where switching could only lead back to it.
 */
describe('switching accounts from the consent page', () => {
	let setup: Setup;

	beforeAll(async () => {
		setup = await bootstrap(import.meta.url, { config: 'consent_page' });
		await ensureAdminSeed();
	});

	it('offers to switch accounts', async () => {
		const cookie = await setup.login({ scope: 'openid' });

		const page = await openConsent(
			{ client_id: 'own-app', scope: 'openid email' },
			cookie
		);

		expect(page.text).toContain(T.account.switch);
		expect(page.html).toContain(`href="/ui/${page.uid}/login"`);
	});

	it('does not offer to switch when the request names the account it wants', async () => {
		const cookie = await setup.login({ scope: 'openid' });

		const page = await openConsent(
			{
				client_id: 'own-app',
				scope: 'openid email',
				claims: {
					id_token: { sub: { value: setup.getLastSession().payload.accountId } }
				}
			},
			cookie
		);

		expect(page.text).not.toContain(T.account.switch);
	});
});
