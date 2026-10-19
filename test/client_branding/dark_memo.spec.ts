import { beforeAll, describe, expect, it } from 'bun:test';
import { theme } from 'antd';

import bootstrap, { type Setup } from '../test_helper.js';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { paintedAccent } from 'lib/html/theme/accent.ts';
import { DARK_TOKENS } from 'lib/html/theme/tokens.ts';
import { ACME, consentPage, giveColour, ownProjects, painted } from './seed.ts';

/**
 * @proves A page's dark scheme is its own application's: two applications with different colours, and one
 * with none, are each served their own dark colours however their pages follow one another — the server
 * remembers dark schemes it has built, and never hands one application's to another.
 */
describe('the dark scheme of pages that follow one another', () => {
	let setup: Setup;
	let member: string;

	beforeAll(async () => {
		setup = await bootstrap(import.meta.url, { config: 'client_branding' });
		await ensureAdminSeed();
		await ownProjects();
		await giveColour('own-app', '#2f7d32');
		await giveColour('own-second', '#c2185b');
		member = await setup.login({ accountId: 'acme-member', bucketId: ACME });
	});

	it('serves each application its own dark colour, and the server’s to one without a colour', async () => {
		const first = painted((await consentPage('own-app', member)).html);
		const second = painted((await consentPage('own-second', member)).html);
		const plain = painted((await consentPage('own-plain', member)).html);

		expect(first.darkPrimary).toBe(paintedAccent('#2f7d32')?.dark.primary);
		expect(second.darkPrimary).toBe(paintedAccent('#c2185b')?.dark.primary);
		expect(plain.darkPrimary).toBe(
			theme.getDesignToken({
				algorithm: theme.darkAlgorithm,
				token: DARK_TOKENS
			}).colorPrimary
		);
	});
});
