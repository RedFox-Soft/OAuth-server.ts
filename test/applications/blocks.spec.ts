import { describe, it, expect } from 'bun:test';
import { SITUATIONS } from 'lib/admin/ui/pages/applications/situations.ts';
import {
	agentBlock,
	envBlock
} from 'lib/admin/ui/pages/applications/blocks.ts';

/*
 * The prefixes front-end build tools copy into the bundle every visitor downloads (Next.js, Vite, Create React App,
 * SvelteKit/Astro, Expo). A secret under one of them is published with the site.
 */
const BROWSER_EXPOSED = [
	'NEXT_PUBLIC_',
	'VITE_',
	'REACT_APP_',
	'PUBLIC_',
	'EXPO_PUBLIC_'
];

const SECRET = 'the-one-time-secret-value';

/**
 * @proves The configuration block a developer copies never places the client secret where a front-end build would
 * ship it to every visitor, whatever kind of application it was made for.
 */
describe('the configuration block', () => {
	for (const situation of SITUATIONS) {
		const { expand } = situation;
		if (!expand) continue;
		it(`never puts the secret under a browser-exposed name for "${situation.title}"`, () => {
			const expansion = expand(situation.devAddress ?? 'http://localhost:3000');
			const block = envBlock(
				{
					issuer: 'https://acme.auth.example',
					clientId: 'client-1',
					redirectUris: expansion.redirectUris
				},
				SECRET
			);
			const secretLines = block
				.split('\n')
				.filter((line) => line.includes(SECRET));
			expect(secretLines.length).toBe(1);
			for (const line of secretLines) {
				const name = line.split('=')[0] ?? '';
				for (const prefix of BROWSER_EXPOSED) {
					expect(name.startsWith(prefix), `${name} starts with ${prefix}`).toBe(
						false
					);
				}
			}
		});
	}
});

/**
 * @proves The instructions a developer copies for their AI coding agent carry every connection value and never the
 * client secret, so the secret does not pass through a chat log.
 */
describe('the copy for an AI agent', () => {
	for (const situation of SITUATIONS) {
		const { expand } = situation;
		if (!expand) continue;
		it(`carries the values and no secret for "${situation.title}", even right after creation`, () => {
			const expansion = expand(situation.devAddress ?? 'http://localhost:3000');
			const confidential = expansion.tokenEndpointAuthMethod !== 'none';
			const text = agentBlock(
				{
					clientId: 'client-1',
					applicationType: expansion.applicationType,
					grantTypes: expansion.grantTypes,
					tokenEndpointAuthMethod: expansion.tokenEndpointAuthMethod,
					redirectUris: expansion.redirectUris,
					requireConsent: true,
					hasSecret: confidential
				},
				{
					issuer: 'https://acme.auth.example',
					discoveryUrl:
						'https://acme.auth.example/.well-known/openid-configuration',
					clientId: 'client-1',
					redirectUris: expansion.redirectUris,
					postLogoutRedirectUris: expansion.postLogoutRedirectUris,
					endpoints: {},
					signInPageUrl: null,
					lastUsed: null
				},
				'https://api.example.com'
			);
			expect(text).toContain('https://acme.auth.example');
			expect(text).toContain('client-1');
			expect(text).not.toContain(SECRET);
			expect(text).not.toMatch(/FOXAUTH_CLIENT_SECRET=\S/);
		});
	}
});
