import { describe, beforeAll, afterEach, it, expect } from 'bun:test';
import { Type } from '@sinclair/typebox';

import bootstrap, { agent } from '../test_helper.js';
import { ApplicationConfig } from 'lib/configs/application.js';
import { present as presentValue, shaped } from 'test/shape.js';
import {
	JWT_BEARER,
	JWT_DPOP,
	OAuthError,
	enterprise,
	idJag,
	present,
	type Enterprise
} from '../assertion_grants/helpers.js';

const Metadata = Type.Object({
	grant_types_supported: Type.Array(Type.String()),
	authorization_grant_profiles_supported: Type.Optional(
		Type.Array(Type.String())
	)
});

async function openid() {
	const { data } = await agent['.well-known']['openid-configuration'].get();
	return presentValue(data, 'the OpenID discovery document');
}

async function oauth() {
	const { data } =
		await agent['.well-known']['oauth-authorization-server'].get();
	return presentValue(data, 'the authorization server metadata');
}

/**
 * @proves The receiving profile is discoverable, in both metadata documents, exactly when the instance
 * redeems it — which is how an MCP client finds it (MCP enterprise-managed authorization §6) — and neither
 * document names a provider the project trusts.
 */
describe('the metadata of an instance that accepts ID-JAGs', () => {
	let acme: Enterprise;

	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'id_jag_receiving' });
		acme = await enterprise('discovery');
	});

	afterEach(() => {
		ApplicationConfig['jwtBearer.enabled'] = true;
	});

	for (const [name, read] of [
		['OpenID discovery document', openid],
		['authorization server metadata', oauth]
	] as const) {
		it(`advertises the JWT bearer grants and the ID-JAG profile in the ${name}`, async () => {
			const metadata = shaped(Metadata, await read());

			expect(metadata.grant_types_supported).toContain(JWT_BEARER);
			expect(metadata.grant_types_supported).toContain(JWT_DPOP);
			expect(metadata.authorization_grant_profiles_supported).toEqual([
				'urn:ietf:params:oauth:grant-profile:id-jag'
			]);
		});

		it(`names no trusted provider anywhere in the ${name}`, async () => {
			expect(JSON.stringify(await read())).not.toContain(acme.provider.issuer);
		});
	}

	it('advertises neither the grants nor the profile when the grant is switched off', async () => {
		ApplicationConfig['jwtBearer.enabled'] = false;

		const metadata = shaped(Metadata, await openid());

		expect(metadata.grant_types_supported).not.toContain(JWT_BEARER);
		expect(metadata.grant_types_supported).not.toContain(JWT_DPOP);
		expect(metadata.authorization_grant_profiles_supported).toBeUndefined();
	});

	it('answers unsupported_grant_type when the grant is switched off', async () => {
		ApplicationConfig['jwtBearer.enabled'] = false;
		const assertion = await idJag(acme.stub, {});

		const res = await present({ assertion });

		expect(res.status).toBe(400);
		expect(shaped(OAuthError, res.error?.value).error).toBe(
			'unsupported_grant_type'
		);
	});
});
