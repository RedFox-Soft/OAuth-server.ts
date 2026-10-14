/*
 * The language switch takes nothing from the request but a choice between two known values.
 */

import { beforeAll, describe, expect, it } from 'bun:test';

import bootstrap from '../test_helper.js';
import { Browser, langOf } from './switch_flow.ts';
import { TestAdapter } from '../models.js';
import { ISSUER } from 'lib/configs/env.js';
import { elysia } from 'lib/index.ts';

const REFUSED: Array<[string, Record<string, string>]> = [
	[
		'a language other than English or the visitor’s own',
		{ lang: 'zh-Hans', page: 'login' }
	],
	['a language this server does not speak', { lang: 'de', page: 'login' }],
	['a malformed value', { lang: 'en"><script>', page: 'login' }],
	['an enormous value', { lang: 'en'.repeat(1000), page: 'login' }],
	['a page that is an address', { lang: 'en', page: 'https://evil.example/' }],
	['a page outside the sign-in', { lang: 'en', page: '../../admin' }]
];

/**
 * @proves Whatever a request puts in the language switch, it changes nothing unless it names English or the
 * visitor's own language and one of the sign-in's own pages, it is sent back only to a page of this sign-in,
 * nothing submitted is echoed, and a request without the sign-in's cookie is refused as every other form here.
 */
describe('a language switch the server will not act on', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	for (const [name, fields] of REFUSED) {
		it(`changes nothing and returns to a page of the sign-in for ${name}`, async () => {
			const browser = new Browser('ru');
			const { uid } = await browser.startSignIn();
			const before = TestAdapter.for('Interaction').syncFind(uid);

			const response = await browser.post(`/ui/${uid}/language`, fields);

			expect(response.status).toBe(303);
			expect(response.headers.get('location')).toMatch(
				new RegExp(`^/ui/${uid}/(login|consent)$`)
			);
			expect(response.headers.getSetCookie().join()).not.toContain('_lang=');
			expect(TestAdapter.for('Interaction').syncFind(uid)).toEqual(before);
			const body = await response.text();
			for (const value of Object.values(fields)) {
				expect(body).not.toContain(value);
			}
			const { html } = await browser.page(`/ui/${uid}/login`);
			expect(langOf(html)).toBe('ru');
		});
	}

	it('refuses a switch sent without the sign-in’s cookie', async () => {
		const browser = new Browser('ru');
		const { uid } = await browser.startSignIn();

		const response = await elysia.handle(
			new Request(`${ISSUER}/ui/${uid}/language`, {
				method: 'POST',
				headers: { 'content-type': 'application/x-www-form-urlencoded' },
				body: new URLSearchParams({ lang: 'en', page: 'login' })
			})
		);

		expect(response.status).toBeGreaterThanOrEqual(400);
		expect(response.headers.getSetCookie().join()).not.toContain('_lang=');
	});
});
