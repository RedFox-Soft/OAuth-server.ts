import { describe, it, expect, beforeAll } from 'bun:test';

import bootstrap, { encodeParams, type Setup } from '../test_helper.js';
import { elysia } from 'lib/index.ts';
import { ISSUER } from 'lib/configs/env.js';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { getBucketStore, getProjectStore } from 'lib/adapters/index.ts';
import { ADMIN_BUCKET_ID, UNASSIGNED_GROUP_ID } from 'lib/admin/consts.ts';
import { forgetBucketAddresses } from 'lib/admin/auth/bucketAddress.ts';
import { CONSENT_TEXTS as T } from 'lib/interactions/consentTexts.js';
import type { ConsentView } from 'lib/interactions/consentView.js';
import { AuthorizationRequest } from 'test/AuthorizationRequest.js';
import { openConsent, withCookies } from './flow.ts';
import { visible } from '../page_text.js';

/* The consent page of a request made at a bucket's own address, as `openConsent` opens one at the root. */
async function consentAt(
	prefix: string,
	params: Record<string, string>,
	cookie: string
) {
	const auth = new AuthorizationRequest(params);
	const started = await elysia.handle(
		new Request(`${ISSUER}${prefix}/auth?${encodeParams(auth.params)}`, {
			headers: { cookie }
		})
	);
	const location = started.headers.get('location') ?? '';
	expect(location).toMatch(/\/ui\/[^/]+\/consent$/);
	const response = await elysia.handle(
		new Request(new URL(location, ISSUER), {
			headers: { cookie: withCookies(cookie, started) }
		})
	);
	const html = await response.text();
	const json = /window\.PROPS=(.*?)<\/script>/s.exec(html)?.[1] ?? '{}';
	return { html, text: visible(html), view: JSON.parse(json) as ConsentView };
}

/**
 * @proves The consent page tells the person they can take the access back later and links to the page where
 * they can — their own bucket's connected-applications page — and says nothing of the kind where there is
 * no such page.
 */
describe('the consent page’s line about removing access later', () => {
	let setup: Setup;

	beforeAll(async () => {
		setup = await bootstrap(import.meta.url, { config: 'consent_page' });
		await ensureAdminSeed();
		forgetBucketAddresses();
		await getBucketStore().create({
			_id: 'acme-bucket',
			name: 'acme people',
			slug: 'acme',
			ownerGroupId: UNASSIGNED_GROUP_ID
		});
		const acme = await getProjectStore().create({
			ownerGroupId: UNASSIGNED_GROUP_ID,
			name: 'Acme',
			slug: 'acme-project'
		});
		await getProjectStore().update(acme._id, {
			bucketId: 'acme-bucket',
			clientIds: ['tenant-app']
		});
		const admins = await getProjectStore().create({
			ownerGroupId: UNASSIGNED_GROUP_ID,
			name: 'Admin tools',
			slug: 'admin-tools'
		});
		await getProjectStore().update(admins._id, {
			bucketId: ADMIN_BUCKET_ID,
			clientIds: ['scheme-app']
		});
	});

	it('links the default bucket’s page at the root, in the same tab', async () => {
		const cookie = await setup.login({ scope: 'openid' });

		const page = await openConsent(
			{ client_id: 'self-registered', scope: 'openid email' },
			cookie
		);

		expect(page.view.revokeHint).toEqual({ href: `${ISSUER}/account/apps` });
		expect(page.text).toContain(`${T.revokeHint.before}${T.revokeHint.link}`);
		const anchor = /<a[^>]*href="http:\/\/e\.ly\/account\/apps"[^>]*>/.exec(
			page.html
		)?.[0];
		expect(anchor).toBeDefined();
		expect(anchor).not.toContain('target=');
	});

	it('links a path-addressed bucket’s own page', async () => {
		const cookie = await setup.login({
			scope: 'openid',
			bucketId: 'acme-bucket'
		});

		const page = await consentAt(
			'/acme',
			{ client_id: 'tenant-app', scope: 'openid email' },
			cookie
		);

		expect(page.view.revokeHint).toEqual({
			href: `${ISSUER}/acme/account/apps`
		});
	});

	it('says nothing of it in the administrators’ bucket, which has no such page', async () => {
		const cookie = await setup.login({
			scope: 'openid',
			bucketId: ADMIN_BUCKET_ID
		});

		const page = await openConsent(
			{ client_id: 'scheme-app', scope: 'openid email', prompt: 'consent' },
			cookie
		);

		expect(page.view.revokeHint).toBeUndefined();
		expect(page.text).not.toContain(T.revokeHint.link);
	});
});
