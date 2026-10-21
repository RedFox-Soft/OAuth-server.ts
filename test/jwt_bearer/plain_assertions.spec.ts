import { describe, beforeAll, it, expect } from 'bun:test';
import { decodeJwt } from 'jose';

import bootstrap, { seedAccount } from '../test_helper.js';
import { ISSUER } from 'lib/configs/env.js';
import { shaped } from 'test/shape.js';
import {
	OAuthError,
	TokenBody,
	declareApi,
	enterprise,
	present,
	type Enterprise
} from '../assertion_grants/helpers.js';

const PROFILE_API = 'https://api.profile.acme.example/';
const OTHER_API = 'https://api.other.acme.example/';
const SUBJECT = 'L-77';

/**
 * @proves A plain assertion about a person, from a provider the project trusts for them, yields a token for
 * the application the trust names — once, within the APIs and scopes the trust allows, addressed to this
 * project's issuer or token endpoint (draft-ietf-oauth-rfc7523bis §4) — and nothing typed for another purpose
 * is ever taken for one.
 */
describe('a plain assertion presented with the JWT bearer grant', () => {
	let legacy: Enterprise;

	beforeAll(async () => {
		await bootstrap(import.meta.url);
		await declareApi(PROFILE_API, ['profile.read', 'profile.write'], 'jwt');
		await declareApi(OTHER_API, ['other.read']);
		legacy = await enterprise('legacy', {
			acceptsIdentityAssertions: undefined,
			plainAssertions: {
				clientIds: ['migrator'],
				resources: [{ identifier: PROFILE_API, scopes: ['profile.read'] }]
			}
		});
		seedAccount('person-1', {
			email: 'person-1@acme.example',
			federated: [
				{ providerId: legacy.provider.id, sub: SUBJECT, linkedAt: new Date() }
			]
		});
		seedAccount('locked-person', {
			email: 'locked@acme.example',
			lockedLocally: { at: new Date(), by: 'admin', reason: 'test' },
			federated: [
				{ providerId: legacy.provider.id, sub: 'locked', linkedAt: new Date() }
			]
		});
	});

	const plain = (
		claims: Record<string, unknown> = {},
		typ: string | null = null
	) =>
		legacy.stub.assertion({ aud: ISSUER, sub: SUBJECT, ...claims }, 'jwt', {
			typ
		});

	const asMigrator = (
		assertion: string,
		extra: {
			resource?: string;
			scope?: string;
			clientId?: string;
			secret?: string;
		} = {}
	) =>
		present({
			assertion,
			clientId: extra.clientId ?? 'migrator',
			secret: extra.secret ?? 'migrator-secret',
			resource: extra.resource ?? PROFILE_API,
			...(extra.scope === undefined ? {} : { scope: extra.scope })
		});

	function refusal(res: Awaited<ReturnType<typeof present>>) {
		expect(res.status).toBe(400);
		return shaped(OAuthError, res.error?.value).error;
	}

	it('yields a token for the person, for the trusted API, with no refresh token', async () => {
		const res = await asMigrator(await plain(), { scope: 'profile.read' });

		expect(res.status).toBe(200);
		const body = shaped(TokenBody, res.data);
		expect(body.refresh_token).toBeUndefined();
		expect(decodeJwt(body.access_token)).toMatchObject({
			sub: 'person-1',
			aud: PROFILE_API,
			scope: 'profile.read'
		});
	});

	it("accepts the project's token endpoint as the audience", async () => {
		const res = await asMigrator(await plain({ aud: `${ISSUER}/token` }), {
			scope: 'profile.read'
		});

		expect(res.status).toBe(200);
	});

	it('is refused with invalid_grant when addressed to anybody else', async () => {
		const res = await asMigrator(
			await plain({ aud: 'https://elsewhere.example' }),
			{
				scope: 'profile.read'
			}
		);

		expect(refusal(res)).toBe('invalid_grant');
	});

	it('is refused with invalid_grant the second time it is presented', async () => {
		const assertion = await plain();
		await asMigrator(assertion, { scope: 'profile.read' });

		const again = await asMigrator(assertion, { scope: 'profile.read' });

		expect(refusal(again)).toBe('invalid_grant');
	});

	it('is refused with invalid_grant when presented by an application the trust does not name', async () => {
		const res = await asMigrator(await plain(), {
			clientId: 'bystander',
			secret: 'bystander-secret',
			scope: 'profile.read'
		});

		expect(refusal(res)).toBe('invalid_grant');
	});

	it('is refused with invalid_grant when typed as an ID-JAG by a provider not trusted for those', async () => {
		const assertion = await plain(
			{ client_id: 'migrator' },
			'oauth-id-jag+jwt'
		);

		expect(
			refusal(await asMigrator(assertion, { scope: 'profile.read' }))
		).toBe('invalid_grant');
	});

	for (const typ of [
		'client-authentication+jwt',
		'dpop+jwt',
		'at+jwt',
		'logout+jwt',
		'secevent+jwt'
	]) {
		it(`is refused with invalid_grant when typed ${typ}`, async () => {
			const res = await asMigrator(await plain({}, typ), {
				scope: 'profile.read'
			});

			expect(refusal(res)).toBe('invalid_grant');
		});
	}

	it('is refused with invalid_grant for a subject nobody is linked to and the provider cannot resolve', async () => {
		const res = await asMigrator(await plain({ sub: 'nobody' }), {
			scope: 'profile.read'
		});

		expect(refusal(res)).toBe('invalid_grant');
	});

	it('is refused with invalid_grant for a person who cannot sign in', async () => {
		const res = await asMigrator(await plain({ sub: 'locked' }), {
			scope: 'profile.read'
		});

		expect(refusal(res)).toBe('invalid_grant');
	});

	it('grants only the scopes the trust allows', async () => {
		const res = await asMigrator(await plain(), {
			scope: 'profile.read profile.write'
		});

		expect(shaped(TokenBody, res.data).scope).toBe('profile.read');
	});

	it('is refused with invalid_scope when no requested scope is allowed', async () => {
		const res = await asMigrator(await plain(), { scope: 'profile.write' });

		expect(refusal(res)).toBe('invalid_scope');
	});

	it('is refused with invalid_target for an API the trust does not allow', async () => {
		const res = await asMigrator(await plain(), {
			resource: OTHER_API,
			scope: 'other.read'
		});

		expect(refusal(res)).toBe('invalid_target');
	});
});
