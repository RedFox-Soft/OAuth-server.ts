/*
 * The pages outside the sign-in follow the reader's language too: the error page and the connected-apps page.
 */

import { beforeAll, describe, expect, it } from 'bun:test';

import bootstrap from '../test_helper.js';
import { visible } from '../page_text.js';
import { APPLICATION_ROW } from '../end_user_pages.ts';
import { ISSUER } from 'lib/configs/env.js';
import { elysia } from 'lib/index.ts';
import { listPage } from 'lib/account_page/html.ts';
import { PAGES_TEXTS } from 'lib/i18n/texts/pages/index.ts';

/**
 * @proves A Russian-speaking end user who lands on an error page reads its heading in Russian while the
 * protocol's own code and description are shown exactly as a developer needs them, marked as English; and the
 * connected-apps page writes its dates and counts the Russian way.
 */
describe('pages outside the sign-in in Russian', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	it('gives an error page a Russian heading and keeps the protocol description unchanged in English', async () => {
		const response = await elysia.handle(
			new Request(`${ISSUER}/auth?client_id=nobody&response_type=code`, {
				headers: {
					accept: 'text/html',
					'accept-language': 'ru-RU,ru;q=0.9'
				}
			})
		);
		const html = await response.text();

		expect(response.status).toBeGreaterThanOrEqual(400);
		expect(html).toContain('<html lang="ru">');
		expect(visible(html)).toContain(PAGES_TEXTS.ru.error.details);
		const english = /<span lang="en">([\s\S]*?)<\/span>/.exec(html)?.[1] ?? '';
		expect(english).toMatch(/client/);
		expect(english).not.toMatch(/[а-яё]/i);
	});

	it('writes the connected-apps page’s dates and “and N more” the Russian way', async () => {
		const response = listPage(
			{
				service: 'Acme ID',
				logoSrc: '/public/logo.svg',
				path: '/account/apps',
				signOutHref: '/logout',
				email: 'person@example.com',
				language: 'ru'
			},
			[
				{
					...APPLICATION_ROW,
					hosts: ['a.example', 'b.example', 'c.example'],
					moreHosts: 2
				}
			]
		);
		const text = visible(await response.text());

		expect(text).toContain('и ещё 2 сайтах');
		expect(text).toContain('1 окт. 2026 г., 10:00 UTC');
	});
});
