import { describe, it, expect, beforeAll, afterEach } from 'bun:test';

import bootstrap, { type Setup } from '../test_helper.js';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import {
	getBucketStore,
	getGroupStore,
	getProjectStore
} from 'lib/adapters/index.ts';
import { DEFAULT_BUCKET_ID } from 'lib/admin/consts.ts';
import { CONSENT_TEXTS as T } from 'lib/interactions/consentTexts.js';
import { openConsent } from './flow.ts';

/**
 * @proves An application that named itself cannot borrow the server's credibility on the consent page:
 * it is never spoken of as the organization's own, its address is always shown in the server's own
 * words, and a single warning appears exactly when what it asks for or how it looks makes that worth
 * reading.
 */
describe('who the consent page says is asking', () => {
	let setup: Setup;
	let cookie: string;

	beforeAll(async () => {
		setup = await bootstrap(import.meta.url, { config: 'consent_page' });
		await ensureAdminSeed();
		// Another tenant's project: an administrator of this server made the client, but not of the
		// group that owns the default bucket every tenant shares.
		const tenant = await getGroupStore().create({
			name: 'Tenant',
			kind: 'regular',
			members: [{ userId: 'tenant-owner', role: 'owner' }]
		});
		const project = await getProjectStore().create({
			ownerGroupId: tenant._id,
			name: 'Partner',
			slug: 'partner-project'
		});
		await getProjectStore().update(project._id, {
			clientIds: ['tenant-app']
		});
		cookie = await setup.login({ scope: 'openid' });
	});

	afterEach(async () => {
		await getBucketStore().update(DEFAULT_BUCKET_ID, {
			displayName: undefined
		});
	});

	it('heads a self-registered app as an app and says the server has not checked it', async () => {
		const page = await openConsent(
			{ client_id: 'self-registered', scope: 'openid email' },
			cookie
		);

		expect(page.view.client.tier).toBe('self-registered');
		expect(page.text).toContain(
			`${T.headline.appBefore}Google${T.headline.appAfter}`
		);
		expect(page.text).toContain(T.host.notChecked(page.view.service.host));
	});

	it('never heads a self-registered app as a sign-in to it', async () => {
		const page = await openConsent(
			{ client_id: 'self-registered', scope: 'openid email' },
			cookie
		);

		expect(page.text).not.toContain(T.headline.signIn('Google'));
	});

	it('shows where a self-registered app sends the answer', async () => {
		const page = await openConsent(
			{ client_id: 'self-registered', scope: 'openid email' },
			cookie
		);

		expect(page.view.redirect).toMatchObject({
			kind: 'web',
			host: 'evil.example.net'
		});
		expect(page.text).toContain(`${T.host.label} evil.example.net`);
	});

	it('does not speak of another tenant’s app as the organization’s own in the shared bucket', async () => {
		const page = await openConsent(
			{ client_id: 'tenant-app', scope: 'openid email' },
			cookie
		);

		expect(page.view.client.tier).toBe('operator-registered');
		expect(page.text).not.toContain(T.headline.signIn('Partner Tool'));
		expect(page.text).toContain(T.host.notChecked(page.view.service.host));
	});

	it('warns once when an unchecked app asks for long-lived access', async () => {
		const page = await openConsent(
			{
				client_id: 'self-registered',
				scope: 'openid email offline_access',
				prompt: 'consent'
			},
			cookie
		);

		expect(page.view.warning).toEqual({
			kind: 'unverified',
			reasons: ['offline']
		});
		expect(page.text).toContain(
			`${T.warning.unverifiedBefore}Google${T.warning.unverifiedAfter('evil.example.net')}`
		);
	});

	it('does not warn when an unchecked app asks only for sign-in data', async () => {
		const page = await openConsent(
			{ client_id: 'self-registered', scope: 'openid email' },
			cookie
		);

		expect(page.view.warning).toBeUndefined();
	});

	it('warns when an app’s name imitates the service’s own', async () => {
		await getBucketStore().update(DEFAULT_BUCKET_ID, {
			displayName: 'Acme ID'
		});

		const page = await openConsent(
			{ client_id: 'look-alike', scope: 'openid email' },
			cookie
		);

		expect(page.view.warning).toEqual({
			kind: 'unverified',
			reasons: ['confusable']
		});
	});

	it('keeps the app’s name out of the buttons', async () => {
		const page = await openConsent(
			{ client_id: 'self-registered', scope: 'openid email' },
			cookie
		);

		const buttons = [
			...page.html.matchAll(/<button[^>]*>([\s\S]*?)<\/button>/g)
		]
			.map((m) => m[1].replace(/<[^>]*>/g, ''))
			.join(' ');
		expect(buttons).toContain(T.buttons.allow);
		expect(buttons).not.toContain('Google');
	});

	it('removes direction overrides and decoration from a self-chosen name', async () => {
		const page = await openConsent(
			{ client_id: 'self-registered', scope: 'openid email' },
			cookie
		);

		expect(page.view.client.name).toBe('Google');
	});

	it('warns that a program on this computer receives the answer when every redirect is loopback', async () => {
		const page = await openConsent(
			{
				client_id: 'local-program',
				scope: 'openid email',
				redirect_uri: 'http://127.0.0.1/callback'
			},
			cookie
		);

		expect(page.view.warning).toEqual({ kind: 'loopback' });
		expect(page.view.redirect.host).toBeUndefined();
		expect(page.text).toContain(T.next.loopback);
	});

	it('says the server cannot check which app on the device receives a private-use scheme redirect', async () => {
		const page = await openConsent(
			{
				client_id: 'scheme-app',
				scope: 'openid email',
				redirect_uri: 'com.acme.mobile:/callback'
			},
			cookie
		);

		expect(page.text).toContain(
			T.host.privateUse('com.acme.mobile', page.view.service.host)
		);
	});
});
