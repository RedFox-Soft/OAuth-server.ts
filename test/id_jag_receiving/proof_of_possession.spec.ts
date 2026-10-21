import { describe, beforeAll, it, expect } from 'bun:test';

import bootstrap, { seedAccount } from '../test_helper.js';
import { shaped } from 'test/shape.js';
import {
	JWT_DPOP,
	OAuthError,
	TokenBody,
	declareApi,
	dpopKey,
	dpopProof,
	enterprise,
	idJag,
	present,
	type Enterprise
} from '../assertion_grants/helpers.js';

const DOCS = 'https://mcp.docs.pop.example/mcp';
const SUBJECT = '00u-linked';

/**
 * @proves An ID-JAG bound to a key is redeemable only by whoever holds that key, under either grant type
 * a client of the profile may send (ID-JAG §9.8.1.2), and the token it yields is bound to the same key.
 */
describe('an ID-JAG bound to a DPoP key', () => {
	let acme: Enterprise;

	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'id_jag_receiving' });
		await declareApi(DOCS, ['docs.read']);
		acme = await enterprise('pop');
		seedAccount('person-1', {
			email: 'person-1@acme.example',
			federated: [
				{ providerId: acme.provider.id, sub: SUBJECT, linkedAt: new Date() }
			]
		});
	});

	async function bound(thumbprint: string) {
		return idJag(acme.stub, {
			sub: SUBJECT,
			resource: DOCS,
			scope: 'docs.read',
			cnf: { jkt: thumbprint }
		});
	}

	it('is refused with invalid_grant when presented without a proof', async () => {
		const { thumbprint } = await dpopKey();

		const res = await present({ assertion: await bound(thumbprint) });

		expect(res.status).toBe(400);
		expect(shaped(OAuthError, res.error?.value).error).toBe('invalid_grant');
	});

	it('is refused with invalid_grant when presented with a proof by another key', async () => {
		const { thumbprint } = await dpopKey();
		const other = await dpopKey();

		const res = await present({
			assertion: await bound(thumbprint),
			dpop: await dpopProof(other.keypair)
		});

		expect(res.status).toBe(400);
		expect(shaped(OAuthError, res.error?.value).error).toBe('invalid_grant');
	});

	it('yields a DPoP-bound token when presented with a proof by its key', async () => {
		const { keypair, thumbprint } = await dpopKey();

		const res = await present({
			assertion: await bound(thumbprint),
			dpop: await dpopProof(keypair)
		});

		expect(res.status).toBe(200);
		expect(shaped(TokenBody, res.data).token_type).toBe('DPoP');
	});

	it('is accepted under the jwt-dpop grant type with a proof by its key', async () => {
		const { keypair, thumbprint } = await dpopKey();

		const res = await present({
			assertion: await bound(thumbprint),
			grantType: JWT_DPOP,
			dpop: await dpopProof(keypair)
		});

		expect(res.status).toBe(200);
		expect(shaped(TokenBody, res.data).token_type).toBe('DPoP');
	});

	it('is refused with invalid_grant under the jwt-dpop grant type when the assertion names no key', async () => {
		const { keypair } = await dpopKey();
		const unbound = await idJag(acme.stub, {
			sub: SUBJECT,
			resource: DOCS,
			scope: 'docs.read'
		});

		const res = await present({
			assertion: unbound,
			grantType: JWT_DPOP,
			dpop: await dpopProof(keypair)
		});

		expect(res.status).toBe(400);
		expect(shaped(OAuthError, res.error?.value).error).toBe('invalid_grant');
	});
});
