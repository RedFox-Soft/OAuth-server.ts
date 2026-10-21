import { describe, beforeAll, it, expect } from 'bun:test';

import bootstrap, { seedAccount } from '../test_helper.js';
import { errorStore } from 'lib/adapters/index.js';
import { flushForTest } from 'lib/error_store/queue.js';
import { ISSUER } from 'lib/configs/env.js';
import { MCP_RESOURCE } from 'lib/mcp/consts.js';
import { shaped } from 'test/shape.js';
import { idpStub } from '../federation/idp_stub.js';
import {
	defaultBucketWith,
	uniqueOrigin,
	upstreamProvider
} from '../global_token_revocation/helpers.js';
import {
	ID_JAG_TYP,
	OAuthError,
	declareApi,
	enterprise,
	idJag,
	present,
	type Enterprise
} from '../assertion_grants/helpers.js';

const TICKETS = 'https://mcp.tickets.refuse.example/mcp';
const DOCS = 'https://mcp.docs.refuse.example/mcp';
const SUBJECT = '00u-linked';

type Result = Awaited<ReturnType<typeof present>>;

function refusal(res: Result) {
	expect(res.status).toBe(400);
	return shaped(OAuthError, res.error?.value);
}

/**
 * @proves An ID-JAG is honoured only when every check of the profile passes — the issuer is one the project
 * trusts for it, the JWT is typed, signed, current, addressed to this project alone and bound to the agent
 * presenting it, the person can sign in, and the API is one the project declared — and a refusal reveals
 * nothing about which check failed beyond its error code.
 */
describe('an ID-JAG the project must not honour', () => {
	let acme: Enterprise;

	beforeAll(async () => {
		await bootstrap(import.meta.url);
		await declareApi(TICKETS, ['tickets.read']);
		await declareApi(DOCS, ['docs.read']);
		acme = await enterprise('acme');
		seedAccount('person-1', {
			email: 'person-1@acme.example',
			federated: [
				{ providerId: acme.provider.id, sub: SUBJECT, linkedAt: new Date() }
			]
		});
		seedAccount('locked-person', {
			email: 'locked@acme.example',
			lockedLocally: { at: new Date(), by: 'admin', reason: 'test' },
			federated: [
				{
					providerId: acme.provider.id,
					sub: 'locked-subject',
					linkedAt: new Date()
				}
			]
		});
	});

	const valid = (claims: Record<string, unknown> = {}) =>
		idJag(acme.stub, {
			sub: SUBJECT,
			resource: TICKETS,
			scope: 'tickets.read',
			...claims
		});

	it('is refused with invalid_grant when its JWT is not typed as an ID-JAG', async () => {
		const assertion = await acme.stub.assertion(
			{ aud: ISSUER, client_id: 'agent', sub: SUBJECT, resource: TICKETS },
			'jwt'
		);

		expect(refusal(await present({ assertion })).error).toBe('invalid_grant');
	});

	it('is refused with invalid_grant when addressed to the token endpoint instead of the issuer', async () => {
		const assertion = await valid({ aud: `${ISSUER}/token` });

		expect(refusal(await present({ assertion })).error).toBe('invalid_grant');
	});

	it('is refused with invalid_grant when addressed to another issuer', async () => {
		const assertion = await valid({ aud: 'https://elsewhere.example' });

		expect(refusal(await present({ assertion })).error).toBe('invalid_grant');
	});

	it('is refused with invalid_grant when addressed to this issuer among others', async () => {
		const assertion = await valid({
			aud: [ISSUER, 'https://elsewhere.example']
		});

		expect(refusal(await present({ assertion })).error).toBe('invalid_grant');
	});

	it('is refused with invalid_grant when it binds another client', async () => {
		const assertion = await valid({ client_id: 'someone-else' });

		expect(refusal(await present({ assertion })).error).toBe('invalid_grant');
	});

	it('is refused with invalid_grant once expired', async () => {
		const assertion = await idJag(
			acme.stub,
			{ sub: SUBJECT, resource: TICKETS, scope: 'tickets.read' },
			{ expiresIn: -60 }
		);

		expect(refusal(await present({ assertion })).error).toBe('invalid_grant');
	});

	it('is refused with invalid_grant before its not-before time', async () => {
		const assertion = await idJag(
			acme.stub,
			{ sub: SUBJECT, resource: TICKETS, scope: 'tickets.read' },
			{ notBefore: 120 }
		);

		expect(refusal(await present({ assertion })).error).toBe('invalid_grant');
	});

	it('is refused with invalid_grant when signed with a key the provider does not publish', async () => {
		const assertion = await idJag(
			acme.stub,
			{ sub: SUBJECT, resource: TICKETS, scope: 'tickets.read' },
			{ foreignKey: true }
		);

		expect(refusal(await present({ assertion })).error).toBe('invalid_grant');
	});

	it('is refused with invalid_grant without a jti', async () => {
		const assertion = await idJag(
			acme.stub,
			{ sub: SUBJECT, resource: TICKETS, scope: 'tickets.read' },
			{ noJti: true }
		);

		expect(refusal(await present({ assertion })).error).toBe('invalid_grant');
	});

	it('is refused with invalid_grant without a client_id', async () => {
		const assertion = await valid({ client_id: undefined });

		expect(refusal(await present({ assertion })).error).toBe('invalid_grant');
	});

	it('is refused with invalid_grant when it claims to live longer than the project accepts', async () => {
		const assertion = await idJag(
			acme.stub,
			{ sub: SUBJECT, resource: TICKETS, scope: 'tickets.read' },
			{ expiresIn: 3600 }
		);

		expect(refusal(await present({ assertion })).error).toBe('invalid_grant');
	});

	it('is refused with invalid_grant when it names the project itself as its issuer', async () => {
		const assertion = await valid({ iss: ISSUER });

		expect(refusal(await present({ assertion })).error).toBe('invalid_grant');
	});

	it('is refused with invalid_grant for a person who cannot sign in', async () => {
		const assertion = await valid({ sub: 'locked-subject' });

		expect(refusal(await present({ assertion })).error).toBe('invalid_grant');
	});

	it('is refused with invalid_target for an API the project has not declared', async () => {
		const assertion = await valid({
			resource: 'https://undeclared.example/mcp'
		});

		expect(refusal(await present({ assertion })).error).toBe('invalid_target');
	});

	it("is refused with invalid_target for the instance's own administrative MCP endpoint", async () => {
		const assertion = await valid({ resource: MCP_RESOURCE });

		expect(refusal(await present({ assertion })).error).toBe('invalid_target');
	});

	it('is refused with invalid_target when it names several APIs and the request picks none', async () => {
		const assertion = await valid({ resource: [TICKETS, DOCS] });

		expect(refusal(await present({ assertion })).error).toBe('invalid_target');
	});

	it('is refused with invalid_target when the request picks an API the ID-JAG does not name', async () => {
		const assertion = await valid();

		expect(refusal(await present({ assertion, resource: DOCS })).error).toBe(
			'invalid_target'
		);
	});

	it('is refused with invalid_target when no API is named anywhere', async () => {
		const assertion = await valid({ resource: undefined });

		expect(refusal(await present({ assertion })).error).toBe('invalid_target');
	});

	it('is refused with invalid_scope when no scope is named anywhere for an API that declares scopes', async () => {
		const assertion = await valid({ scope: undefined });

		expect(refusal(await present({ assertion })).error).toBe('invalid_scope');
	});

	it('is refused with unauthorized_client when presented by a client that does not authenticate', async () => {
		const assertion = await valid({ client_id: 'spa' });

		const res = await present({ assertion, clientId: 'spa', secret: null });

		expect(refusal(res).error).toBe('unauthorized_client');
	});

	it('is refused with unauthorized_client when presented by a client not allowed the grant', async () => {
		const assertion = await valid({ client_id: 'agent-without-grant' });

		const res = await present({
			assertion,
			clientId: 'agent-without-grant',
			secret: 'agent-without-grant-secret'
		});

		expect(refusal(res).error).toBe('unauthorized_client');
	});

	it('describes an untrusted issuer, an unknown person and a bad signature in the same words', async () => {
		const unknownPerson = refusal(
			await present({ assertion: await valid({ sub: 'nobody-subject' }) })
		);
		const badSignature = refusal(
			await present({
				assertion: await idJag(
					acme.stub,
					{ sub: SUBJECT, resource: TICKETS, scope: 'tickets.read' },
					{ foreignKey: true }
				)
			})
		);
		const untrusted = refusal(
			await present({
				assertion: await valid({ iss: 'https://untrusted.example' })
			})
		);

		expect(unknownPerson.error_description).toBe(
			badSignature.error_description
		);
		expect(untrusted.error_description).toBe(badSignature.error_description);
	});
});

/**
 * @proves A provider is trusted for ID-JAGs only by an explicit choice, only while it is enabled, and only for
 * the organisation it was configured for; a provider whose keys cannot be read is refused rather than trusted,
 * and that outage is not recorded as a defect of this server.
 */
describe('an ID-JAG from a provider the project has not trusted for it', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
		await declareApi(TICKETS, ['tickets.read']);
	});

	it('is refused with invalid_grant when the provider is configured but not trusted for assertions', async () => {
		const acme = await enterprise(
			'untrusted',
			{ acceptsIdentityAssertions: false },
			{ servesKeys: false }
		);
		const assertion = await idJag(acme.stub, {
			resource: TICKETS,
			scope: 'tickets.read'
		});

		const res = await present({ assertion });

		expect(refusal(res).error).toBe('invalid_grant');
	});

	it('is refused with invalid_grant while the trusted provider is disabled', async () => {
		const acme = await enterprise(
			'disabled',
			{ enabled: false },
			{ servesKeys: false }
		);
		const assertion = await idJag(acme.stub, {
			resource: TICKETS,
			scope: 'tickets.read'
		});

		const res = await present({ assertion });

		expect(refusal(res).error).toBe('invalid_grant');
	});

	it('is refused with invalid_grant when it comes from another organisation than the one configured', async () => {
		const acme = await enterprise('tenanted', { tenant: 'acme-tenant' });
		const assertion = await idJag(acme.stub, {
			tenant: 'other-tenant',
			resource: TICKETS,
			scope: 'tickets.read'
		});

		const res = await present({ assertion });

		expect(refusal(res).error).toBe('invalid_grant');
	});

	it('is refused with invalid_grant, and records no defect, when the provider cannot be reached', async () => {
		const origin = uniqueOrigin('unreachable');
		const stub = await idpStub(origin);
		await defaultBucketWith([
			upstreamProvider('unreachable', origin, {
				acceptsGlobalTokenRevocation: undefined,
				acceptsIdentityAssertions: true
			})
		]);
		stub.expectDiscoveryFailure(503);
		const before = (await errorStore.list()).total;
		const assertion = await stub.assertion(
			{ aud: ISSUER, client_id: 'agent', sub: SUBJECT, resource: TICKETS },
			ID_JAG_TYP
		);

		const res = await present({ assertion });

		expect(refusal(res).error).toBe('invalid_grant');
		await flushForTest();
		expect((await errorStore.list()).total).toBe(before);
	});
});
