import { beforeAll, describe, expect, it } from 'bun:test';
import { Type } from '@sinclair/typebox';

import bootstrap from '../test_helper.js';
import { elysia } from 'lib/index.ts';
import { shaped } from '../shape.ts';
import {
	ACME,
	BETA,
	SUB,
	acceptPasskeys,
	project,
	type Project
} from './helpers.ts';

const PHISHING_RESISTANT = 'urn:example:acr:phr';
const MULTI_FACTOR = 'urn:example:acr:mfa';

const Document = Type.Object({
	acr_values_supported: Type.Array(Type.String())
});

/*
 * What a project's OpenID discovery document advertises; `acr_values_supported` is OpenID's, so the RFC 8414
 * document leaves it out (lib/configs/discoverySupport.ts metadataClassification).
 */
async function advertisedBy(at: Project): Promise<string[]> {
	const response = await elysia.handle(
		new Request(`${at.origin}${at.prefix}/.well-known/openid-configuration`)
	);
	expect(response.status).toBe(200);
	return shaped(Document, await response.json()).acr_values_supported;
}

let acme: Project;
let beta: Project;
let sub: Project;

beforeAll(async () => {
	await bootstrap(import.meta.url);
	acme = await project(ACME);
	beta = await project(BETA, { passkeys: false });
	sub = await project(SUB, { subdomain: true });
});

/**
 * @proves A project's discovery documents advertise the phishing-resistant context exactly while that project accepts
 * passkeys, at a path or a subdomain address, and follow a change of the setting without a restart.
 */
describe('advertising phr', () => {
	it('is done by a project that accepts passkeys, at its path and at its subdomain', async () => {
		for (const at of [acme, sub]) {
			const advertised = await advertisedBy(at);
			expect(advertised).toContain(PHISHING_RESISTANT);
			expect(advertised).toContain(MULTI_FACTOR);
		}
	});

	it('is not done by a project that does not accept passkeys', async () => {
		const advertised = await advertisedBy(beta);
		expect(advertised).not.toContain(PHISHING_RESISTANT);
		expect(advertised).toContain(MULTI_FACTOR);
	});

	it('follows the project’s setting without a restart', async () => {
		await acceptPasskeys(beta.bucketId, true);
		const on = await advertisedBy(beta);
		await acceptPasskeys(beta.bucketId, false);
		const off = await advertisedBy(beta);

		expect(on).toContain(PHISHING_RESISTANT);
		expect(off).not.toContain(PHISHING_RESISTANT);
	});
});
