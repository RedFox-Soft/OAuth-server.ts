import { beforeAll, describe, expect, it } from 'bun:test';
import { createElement } from 'react';
import { renderToString } from 'react-dom/server';
import { createCache, extractStyle, StyleProvider } from '@ant-design/cssinjs';

import bootstrap from '../test_helper.js';
import {
	consentServer,
	loginServer,
	registrationServer,
	totpServer
} from 'lib/interactions/serverRender.tsx';
import { emptyConsentView } from 'lib/interactions/consentView.ts';
import { clientRoot } from 'lib/interactions/clientRoot.tsx';
import { SUPPORTED_LANGUAGES, type Language } from 'lib/i18n/languages.ts';
import { paintedAccent } from 'lib/html/theme/accent.ts';

function served(html: string): { markup: string; props: object } {
	const markup = /<div id="root">([\s\S]*)<\/div>\s*<script/.exec(html)?.[1];
	const props = /<script>window\.PROPS=([\s\S]*?)<\/script>/.exec(html)?.[1];
	if (markup === undefined || props === undefined)
		throw new Error('not a hydrated page');
	return { markup, props: JSON.parse(props) as object };
}

const PASSKEY_OPTIONS = {
	challenge: 'Y2hhbGxlbmdl',
	rpId: 'e.ly',
	userVerification: 'required' as const,
	timeout: 300000,
	allowCredentials: []
};

const PAGES: Array<
	[string, string, (language: Language) => Promise<Response>]
> = [
	[
		'sign-in',
		'login',
		(language) => loginServer('uid-1', { errorMessage: 'wrong', language })
	],
	/*
	 * With a passkey offer (specs/139): its button is disabled in both renders until the script checks the browser,
	 * and the passkey door answers a refusal with this page at its own path, which hydrates the same way.
	 */
	[
		'sign-in with a passkey offer',
		'login',
		(language) =>
			loginServer('uid-1', {
				passkey: { options: PASSKEY_OPTIONS, remember: true },
				language
			})
	],
	[
		'passkey door’s refusal',
		'passkey',
		(language) =>
			loginServer('uid-1', {
				errorMessage: 'This passkey isn’t for Acme.',
				passwordLogin: false,
				passkey: { options: PASSKEY_OPTIONS, remember: false },
				language
			})
	],
	[
		'registration',
		'registration',
		(language) => registrationServer('uid-1', { language })
	],
	[
		'two-step code',
		'totp',
		(language) => totpServer('uid-1', { mode: 'verify', language })
	],
	[
		'two-step enrolment',
		'totp',
		(language) =>
			totpServer('uid-1', {
				mode: 'enroll',
				otpauthUri: 'otpauth://totp/x?secret=ABC',
				secretText: 'ABC',
				language
			})
	],
	[
		'consent',
		'consent',
		(language) =>
			consentServer(
				{
					...emptyConsentView('uid-1'),
					client: { name: 'Acme Notes', tier: 'self-registered' }
				},
				{ language }
			)
	]
];

/**
 * @proves A hydrated sign-in page looks the same before and after its script takes over, in either colour
 * scheme: the tree the browser hydrates renders exactly the markup the server sent, so React keeps it rather
 * than redrawing the page — and nothing about the scheme lives in that markup (specs/096 FR-003). The same holds
 * in every language: the browser reads the language from the props and shows the server's words (specs/097).
 * An application's colour survives too: the theme the browser builds paints the primary the server did
 * (specs/106).
 */
describe('a hydrated page keeps the markup the server sent', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	for (const [name, path, render] of PAGES) {
		for (const language of SUPPORTED_LANGUAGES) {
			it(`hydrates the ${name} page in ${language} to the served markup`, async () => {
				const { markup, props } = served(await (await render(language)).text());

				expect(renderToString(clientRoot(path, 'uid-1', props))).toBe(markup);
			});
		}
	}

	const accent = paintedAccent('#2f7d32');
	const BRANDED: Array<[string, string, () => Promise<Response>]> = [
		['sign-in', 'login', () => loginServer('uid-1', { accent })],
		[
			'consent',
			'consent',
			() =>
				consentServer(
					{
						...emptyConsentView('uid-1'),
						client: { name: 'Timesheets', tier: 'this-organization' }
					},
					{ accent }
				)
		]
	];

	for (const [name, path, render] of BRANDED) {
		it(`hydrates the ${name} page of an application with a colour to the served markup`, async () => {
			const { markup, props } = served(await (await render()).text());

			expect(renderToString(clientRoot(path, 'uid-1', props))).toBe(markup);
		});

		it(`hydrates the ${name} page of an application with a colour in that colour`, async () => {
			const html = await (await render()).text();
			const { props } = served(html);
			const cache = createCache();
			renderToString(
				createElement(
					StyleProvider,
					{ cache },
					clientRoot(path, 'uid-1', props)
				)
			);
			const primary = (css: string) =>
				/--ant-color-primary:([^;}]+)/.exec(css)?.[1];

			expect(primary(extractStyle(cache, { plain: true }))).toBe(
				accent?.light.primary
			);
			expect(primary(html)).toBe(accent?.light.primary);
		});
	}
});
