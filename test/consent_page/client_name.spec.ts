import { describe, it, expect, beforeAll } from 'bun:test';

import bootstrap, { changeClient, type Setup } from '../test_helper.js';
import { openConsent } from './flow.ts';

/*
 * Names a registrant could choose, drawn from the characters that make a name lie about its surroundings —
 * direction overrides and isolates, zero-width and control characters, emoji and symbols used as badges,
 * look-alike letters — mixed with ordinary ones. A fixed seed, so a failure names a case that can be run
 * again.
 */
const POOLS = [
	'abcdefghijklmnopqrstuvwxyz ',
	'АаЕеОоРрСсІі',
	'‪‫‬‭‮⁦⁧⁨⁩',
	'​‌‍﻿\u0000\u0007\u001B  ',
	'✅🔒⭐️🇫🇷👍™®©',
	'()[]{}«»“”"\'-—.!?'
];

function generator(seed: number) {
	let state = seed;
	const next = () => {
		state = (state * 1103515245 + 12345) & 0x7fffffff;
		return state;
	};
	return (): string => {
		const length = 1 + (next() % 70);
		let name = '';
		for (let i = 0; i < length; i++) {
			// Code points, not graphemes, on purpose: a lone combining or override character is the case.
			const pool = Array.from(POOLS[next() % POOLS.length]);
			name += pool[next() % pool.length];
		}
		return name;
	};
}

const graphemes = new Intl.Segmenter(undefined, { granularity: 'grapheme' });

/**
 * @proves Whatever name an application chose for itself, the consent page shows it without characters
 * that can hide in it or reorder the page around it, never longer than forty characters, and never as
 * nothing when it had a letter or digit to show.
 */
describe('a self-chosen application name on the consent page', () => {
	let setup: Setup;

	beforeAll(async () => {
		setup = await bootstrap(import.meta.url, { config: 'consent_page' });
	});

	it('for every generated name, shows no hidden or reordering character, at most forty characters, and something when the name had a letter or digit', async () => {
		const cookie = await setup.login({ scope: 'openid' });
		const nextName = generator(92);

		for (let i = 0; i < 25; i++) {
			const raw = nextName();
			const undo = await changeClient('self-registered', { client_name: raw });
			try {
				const page = await openConsent(
					{ client_id: 'self-registered', scope: 'openid email' },
					cookie
				);
				const shown = page.view.client.name;

				expect(shown).not.toMatch(/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/u);
				expect([...graphemes.segment(shown)].length).toBeLessThanOrEqual(40);
				if (/[\p{L}\p{N}]/u.test(raw)) expect(shown.length).toBeGreaterThan(0);
			} finally {
				await undo();
			}
		}
	});
});
