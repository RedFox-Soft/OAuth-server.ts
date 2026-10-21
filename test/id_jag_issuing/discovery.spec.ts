import { describe, beforeAll, afterEach, it, expect } from 'bun:test';
import { Type } from '@sinclair/typebox';

import bootstrap, { agent } from '../test_helper.js';
import { ApplicationConfig } from 'lib/configs/application.js';
import { present, shaped } from 'test/shape.js';
import { OAuthError } from '../assertion_grants/helpers.js';
import {
	EXCHANGE,
	ID_JAG_TOKEN_TYPE,
	connect,
	exchange
} from '../assertion_grants/issuing.js';

const OUTSIDE = 'https://as.discovery-outside.example';

const Metadata = Type.Object({
	grant_types_supported: Type.Array(Type.String()),
	identity_chaining_requested_token_types_supported: Type.Optional(
		Type.Array(Type.String())
	)
});

async function openid() {
	const { data } = await agent['.well-known']['openid-configuration'].get();
	return present(data, 'the OpenID discovery document');
}

async function oauth() {
	const { data } =
		await agent['.well-known']['oauth-authorization-server'].get();
	return present(data, 'the authorization server metadata');
}

/**
 * @proves The issuing profile is discoverable, in both metadata documents, exactly when the instance issues
 * ID-JAGs, and neither document names an outside server a project vouches to.
 */
describe('the metadata of an instance that issues ID-JAGs', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'id_jag_issuing' });
		await connect({ issuer: OUTSIDE });
	});

	afterEach(() => {
		ApplicationConfig['tokenExchange.enabled'] = true;
	});

	for (const [name, read] of [
		['OpenID discovery document', openid],
		['authorization server metadata', oauth]
	] as const) {
		it(`advertises token exchange and the ID-JAG token type in the ${name}`, async () => {
			const metadata = shaped(Metadata, await read());

			expect(metadata.grant_types_supported).toContain(EXCHANGE);
			expect(
				metadata.identity_chaining_requested_token_types_supported
			).toEqual([ID_JAG_TOKEN_TYPE]);
		});

		it(`names no connected outside server in the ${name}`, async () => {
			expect(JSON.stringify(await read())).not.toContain(OUTSIDE);
		});
	}

	it('advertises neither when token exchange is switched off', async () => {
		ApplicationConfig['tokenExchange.enabled'] = false;

		const metadata = shaped(Metadata, await openid());

		expect(metadata.grant_types_supported).not.toContain(EXCHANGE);
		expect(
			metadata.identity_chaining_requested_token_types_supported
		).toBeUndefined();
	});

	it('answers unsupported_grant_type when token exchange is switched off', async () => {
		ApplicationConfig['tokenExchange.enabled'] = false;

		const res = await exchange({ subjectToken: 'x', audience: OUTSIDE });

		expect(res.status).toBe(400);
		expect(shaped(OAuthError, res.error?.value).error).toBe(
			'unsupported_grant_type'
		);
	});
});
