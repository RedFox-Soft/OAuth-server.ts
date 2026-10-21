import {
	describe,
	beforeAll,
	beforeEach,
	afterEach,
	it,
	expect
} from 'bun:test';
import { createPrivateKey } from 'node:crypto';
import { decodeJwt } from 'jose';

import bootstrap, { agent, seedAccount } from '../test_helper.js';
import { getUserStore } from 'lib/adapters/index.js';
import { DEFAULT_BUCKET_ID } from 'lib/admin/consts.ts';
import { clearDocumentCache } from 'lib/client_metadata_document/cache.ts';
import { resolver } from 'lib/client_metadata_document/fetch.ts';
import { ISSUER } from 'lib/configs/env.js';
import * as JWT from 'lib/helpers/jwt.ts';
import nanoid from 'lib/helpers/nanoid.ts';
import { shaped } from 'test/shape.js';
import clientKey from '../client.sig.key.js';
import { serveDocument, mock } from '../cimd/document_host.js';
import {
	JWT_BEARER,
	TokenBody,
	declareApi,
	dpopKey,
	dpopProof,
	enterprise,
	idJag,
	present,
	type Enterprise
} from '../assertion_grants/helpers.js';

const TICKETS = 'https://mcp.tickets.acme.example/mcp';
const DOCS = 'https://mcp.docs.acme.example/mcp';
const SUBJECT = '00u-linked';

async function linkedPerson(acme: Enterprise, sub = SUBJECT, id = 'person-1') {
	seedAccount(id, {
		email: `${id}@acme.example`,
		federated: [{ providerId: acme.provider.id, sub, linkedAt: new Date() }]
	});
	return id;
}

/**
 * @proves An agent holding an ID-JAG from a provider the project trusts receives an access token for one of
 * the project's APIs — audience-bound, scoped to what both the provider and the API allow, for the person the
 * provider names — with no consent and no refresh token, and may present the same ID-JAG again until it
 * expires.
 */
describe('an ID-JAG presented by the agent the project registered', () => {
	let acme: Enterprise;

	beforeAll(async () => {
		await bootstrap(import.meta.url);
		await declareApi(TICKETS, ['tickets.read', 'tickets.write'], 'jwt');
		await declareApi(DOCS, ['docs.read']);
		acme = await enterprise('acme');
		await linkedPerson(acme);
	});

	it('yields a token for the API, for the linked person, with the granted scope and no refresh token', async () => {
		const assertion = await idJag(acme.stub, {
			sub: SUBJECT,
			resource: TICKETS,
			scope: 'tickets.read'
		});

		const { status, data } = await present({ assertion });

		expect(status).toBe(200);
		const body = shaped(TokenBody, data);
		expect(body).toMatchObject({
			token_type: 'Bearer',
			scope: 'tickets.read',
			resource: TICKETS
		});
		expect(body.refresh_token).toBeUndefined();
		const claims = decodeJwt(body.access_token);
		expect(claims).toMatchObject({
			aud: TICKETS,
			sub: 'person-1',
			iss: ISSUER,
			client_id: 'agent'
		});
	});

	it('yields a new token when the same ID-JAG is presented again before it expires', async () => {
		const assertion = await idJag(acme.stub, {
			sub: SUBJECT,
			resource: TICKETS,
			scope: 'tickets.read'
		});

		const first = shaped(TokenBody, (await present({ assertion })).data);
		const again = await present({ assertion });

		expect(again.status).toBe(200);
		expect(shaped(TokenBody, again.data).access_token).not.toBe(
			first.access_token
		);
	});

	it('grants only the scopes the API declares when the ID-JAG asks for more', async () => {
		const assertion = await idJag(acme.stub, {
			sub: SUBJECT,
			resource: TICKETS,
			scope: 'tickets.read admin.all'
		});

		const { data } = await present({ assertion });

		expect(shaped(TokenBody, data).scope).toBe('tickets.read');
	});

	it('narrows further to the scope the request asks for', async () => {
		const assertion = await idJag(acme.stub, {
			sub: SUBJECT,
			resource: TICKETS,
			scope: 'tickets.read tickets.write'
		});

		const { data } = await present({ assertion, scope: 'tickets.read' });

		expect(shaped(TokenBody, data).scope).toBe('tickets.read');
	});

	it('picks the requested API among the several the ID-JAG names', async () => {
		const assertion = await idJag(acme.stub, {
			sub: SUBJECT,
			resource: [TICKETS, DOCS],
			scope: 'docs.read'
		});

		const { status, data } = await present({ assertion, resource: DOCS });

		expect(status).toBe(200);
		expect(shaped(TokenBody, data).resource).toBe(DOCS);
	});

	it('takes the API from the request when the ID-JAG names none', async () => {
		const assertion = await idJag(acme.stub, {
			sub: SUBJECT,
			scope: 'docs.read'
		});

		const { status, data } = await present({ assertion, resource: DOCS });

		expect(status).toBe(200);
		expect(shaped(TokenBody, data).resource).toBe(DOCS);
	});

	it('binds the token to the key of a DPoP proof sent with an ID-JAG that names no key', async () => {
		const { keypair } = await dpopKey();
		const assertion = await idJag(acme.stub, {
			sub: SUBJECT,
			resource: DOCS,
			scope: 'docs.read'
		});

		const { status, data } = await present({
			assertion,
			dpop: await dpopProof(keypair)
		});

		expect(status).toBe(200);
		expect(shaped(TokenBody, data).token_type).toBe('DPoP');
	});
});

/**
 * @proves A person the project does not know yet is resolved by the rules a browser sign-in through the same
 * provider follows: created and linked where the provider provisions new people, refused where it admits only
 * existing ones.
 */
describe('an ID-JAG naming a subject nobody in the project is linked to', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
		await declareApi(DOCS, ['docs.read']);
	});

	it('creates the person and links them to the subject when the provider provisions new people', async () => {
		const acme = await enterprise('jit', { emailTrusted: true });
		const assertion = await idJag(acme.stub, {
			sub: 'newcomer-subject',
			email: 'newcomer@acme.example',
			email_verified: true,
			resource: DOCS,
			scope: 'docs.read'
		});

		const { status } = await present({ assertion });

		expect(status).toBe(200);
		const person = await getUserStore(
			DEFAULT_BUCKET_ID
		).findByFederatedIdentity(acme.provider.id, 'newcomer-subject');
		expect(person?.email).toBe('newcomer@acme.example');
	});

	it('is refused with invalid_grant when the provider admits only existing people', async () => {
		const acme = await enterprise('existing', {
			emailTrusted: true,
			provisioning: 'existing_only'
		});
		const assertion = await idJag(acme.stub, {
			sub: 'stranger-subject',
			email: 'stranger@acme.example',
			email_verified: true,
			resource: DOCS,
			scope: 'docs.read'
		});

		const { status, error } = await present({ assertion });

		expect(status).toBe(400);
		expect(error?.value).toMatchObject({ error: 'invalid_grant' });
	});
});

/**
 * @proves An MCP client the project never registered, identified by its client ID metadata document and
 * authenticating with the keys that document publishes, can present an ID-JAG naming its URL (MCP
 * enterprise-managed authorization §5).
 */
describe('an ID-JAG presented by a client known by its metadata document', () => {
	const publicAddress = '93.184.216.34';
	let acme: Enterprise;

	beforeAll(async () => {
		await bootstrap(import.meta.url);
		await declareApi(DOCS, ['docs.read']);
		acme = await enterprise('cimd');
		await linkedPerson(acme);
	});

	beforeEach(() => {
		clearDocumentCache();
		resolver.lookup = async () => [publicAddress];
	});

	afterEach(() => {
		mock.restore();
		resolver.lookup = resolver.realLookup;
	});

	it('yields a token when the client authenticates with its published key', async () => {
		const { kty, kid, e, n } = clientKey;
		const { identifier } = serveDocument({
			overrides: {
				grant_types: [JWT_BEARER],
				response_types: [],
				token_endpoint_auth_method: 'private_key_jwt',
				jwks: { keys: [{ kty, kid, e, n }] }
			}
		});
		const clientAssertion = await JWT.sign(
			{ jti: nanoid(), aud: ISSUER, sub: identifier, iss: identifier },
			createPrivateKey({ format: 'jwk', key: clientKey }),
			'RS256',
			{ expiresIn: 60 }
		);
		const assertion = await idJag(acme.stub, {
			sub: SUBJECT,
			client_id: identifier,
			resource: DOCS,
			scope: 'docs.read'
		});

		const { status } = await agent.token.post({
			grant_type: JWT_BEARER,
			assertion,
			client_id: identifier,
			client_assertion: clientAssertion,
			client_assertion_type:
				'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
		});

		expect(status).toBe(200);
	});
});
