import { beforeAll, describe, expect, it } from 'bun:test';

import bootstrap from '../test_helper.js';
import { adminAuditStore } from 'lib/adapters/index.ts';
import { DEFAULT_BUCKET_ID } from 'lib/admin/consts.ts';
import { openPage, PAGE, signedIn, xsrfFrom } from './helpers.ts';

async function entriesFor(accountId: string) {
	return (await adminAuditStore.list({ targetId: accountId })).entries;
}

/**
 * @proves The people who run the project see in the person's Changes that the person signed out everywhere
 * themselves, as the sign-out an administrator would have made; reading one's own sign-ins leaves no record.
 */
describe('what the audit trail keeps of recent sign-ins', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'own_sign_ins' });
	});

	it('records signing out everywhere as the person’s own sign-out', async () => {
		const { browser, accountId } = await signedIn();
		const { html } = await openPage(browser, '?confirm=1');

		await browser.post(PAGE, { xsrf: xsrfFrom(html) });
		const [entry, ...more] = (await entriesFor(accountId)).filter(
			(e) => e.action === 'enduser.signout'
		);

		expect(more).toHaveLength(0);
		expect(entry).toMatchObject({
			action: 'enduser.signout',
			targetId: accountId,
			targetScope: DEFAULT_BUCKET_ID,
			viaSurface: 'self-service'
		});
	});

	it('records nothing when the person only reads their sign-ins', async () => {
		const { browser, accountId } = await signedIn();
		const before = (await entriesFor(accountId)).length;

		await openPage(browser);

		expect(await entriesFor(accountId)).toHaveLength(before);
	});
});
