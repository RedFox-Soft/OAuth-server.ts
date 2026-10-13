import { beforeAll, describe, expect, it } from 'bun:test';
import { renderToString } from 'react-dom/server';

import bootstrap from '../test_helper.js';
import {
	consentServer,
	loginServer,
	registrationServer,
	totpServer
} from 'lib/interactions/serverRender.tsx';
import { emptyConsentView } from 'lib/interactions/consentView.ts';
import { clientRoot } from 'lib/interactions/clientRoot.tsx';

function served(html: string): { markup: string; props: object } {
	const markup = /<div id="root">([\s\S]*)<\/div>\s*<script/.exec(html)?.[1];
	const props = /<script>window\.PROPS=([\s\S]*?)<\/script>/.exec(html)?.[1];
	if (markup === undefined || props === undefined)
		throw new Error('not a hydrated page');
	return { markup, props: JSON.parse(props) as object };
}

const PAGES: Array<[string, string, () => Promise<Response>]> = [
	['sign-in', 'login', () => loginServer('uid-1', { errorMessage: 'wrong' })],
	['registration', 'registration', () => registrationServer('uid-1')],
	['two-step code', 'totp', () => totpServer('uid-1', { mode: 'verify' })],
	[
		'two-step enrolment',
		'totp',
		() =>
			totpServer('uid-1', {
				mode: 'enroll',
				otpauthUri: 'otpauth://totp/x?secret=ABC',
				secretText: 'ABC'
			})
	],
	[
		'consent',
		'consent',
		() =>
			consentServer({
				...emptyConsentView('uid-1'),
				client: { name: 'Acme Notes', tier: 'self-registered' }
			})
	]
];

/**
 * @proves A hydrated sign-in page looks the same before and after its script takes over, in either colour
 * scheme: the tree the browser hydrates renders exactly the markup the server sent, so React keeps it rather
 * than redrawing the page — and nothing about the scheme lives in that markup (specs/096 FR-003).
 */
describe('a hydrated page keeps the markup the server sent', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	for (const [name, path, render] of PAGES) {
		it(`hydrates the ${name} page to the served markup`, async () => {
			const { markup, props } = served(await (await render()).text());

			expect(renderToString(clientRoot(path, 'uid-1', props))).toBe(markup);
		});
	}
});
