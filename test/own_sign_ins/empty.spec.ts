import { afterEach, beforeAll, describe, expect, it } from 'bun:test';

import bootstrap from '../test_helper.js';
import { getBucketStore } from 'lib/adapters/index.ts';
import { DEFAULT_BUCKET_ID } from 'lib/admin/consts.ts';
import { ApplicationConfig } from 'lib/configs/application.ts';
import { formatDate } from 'lib/i18n/format.ts';
import { ACCOUNT_TEXTS } from 'lib/i18n/texts/account/index.ts';
import { text as fill } from 'lib/i18n/message.tsx';
import { present } from '../shape.ts';
import {
	itemsOf,
	minutesAgo,
	openPage,
	seed,
	signedIn,
	signInRow,
	textOf
} from './helpers.ts';

const T = ACCOUNT_TEXTS.en;
const DAY_MS = 86_400_000;

/**
 * @proves When there is nothing to list, Recent sign-ins says why (recording is off here, or nothing since recording
 * began on a given day) rather than looking like nobody ever signed in, and still offers to sign out everywhere.
 */
describe('recent sign-ins with nothing to show', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'own_sign_ins' });
	});

	afterEach(() => {
		ApplicationConfig['personActivity.enabled'] = true;
	});

	it('says sign-ins aren’t recorded here when recording is turned off, and lists nothing', async () => {
		const { browser, accountId } = await signedIn();
		await seed([signInRow(accountId, minutesAgo(30))]);
		ApplicationConfig['personActivity.enabled'] = false;

		const { html } = await openPage(browser);

		expect(textOf(html)).toContain(T.signInsOff);
		expect(itemsOf(html)).toHaveLength(0);
		expect(textOf(html)).toContain(T.signOutEverywhere);
	});

	it('says since when recording began when nothing was recorded in 90 days', async () => {
		const { browser } = await signedIn();
		const bucket = present(
			await getBucketStore().find(DEFAULT_BUCKET_ID),
			'the default bucket'
		);
		const since = Math.max(
			bucket.createdAt.getTime(),
			Date.now() - 90 * DAY_MS
		);

		const { html } = await openPage(browser);

		expect(itemsOf(html)).toHaveLength(0);
		expect(textOf(html)).toContain(
			fill(T.signInsEmpty, { date: formatDate('en', since) })
		);
		expect(textOf(html)).not.toMatch(/\bnever\b/i);
	});
});
