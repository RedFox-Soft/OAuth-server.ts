import {
	describe,
	beforeAll,
	beforeEach,
	afterEach,
	it,
	expect
} from 'bun:test';
import { createPrivateKey } from 'node:crypto';
import { Type } from '@sinclair/typebox';

import bootstrap, {
	agent,
	bindClientToBucket,
	changeClient
} from '../test_helper.js';
import { AuthorizationRequest } from 'test/AuthorizationRequest.js';
import {
	getBucketStore,
	getProtectedResourceStore
} from 'lib/adapters/index.ts';
import { ROOT_NAMESPACE } from 'lib/resources/namespace.ts';
import { UNASSIGNED_GROUP_ID } from 'lib/admin/consts.ts';
import { clearDocumentCache } from 'lib/client_metadata_document/cache.ts';
import { resolver } from 'lib/client_metadata_document/fetch.ts';
import { ISSUER } from 'lib/configs/env.js';
import * as JWT from 'lib/helpers/jwt.ts';
import nanoid from 'lib/helpers/nanoid.ts';
import { shaped } from 'test/shape.js';
import clientKey from '../client.sig.key.js';
import { serveDocument, mock } from '../cimd/document_host.js';
import { bucketOf } from './owning_bucket.js';

/*
 * A client credentials token acts for nobody: no end user signs in and nobody consents, so the only
 * thing standing between a client and a resource is who the client is. A declared resource belongs to
 * the bucket that declared it, and a machine token for it goes to the applications an administrator
 * created in that bucket alone. Otherwise any confidential client of any tenant — or one that registered
 * itself, or one that merely hosts a document describing itself — could ask for a token carrying another
 * tenant's resource as its audience and that resource's scopes, which the resource server has no reason
 * to refuse.
 *
 * A token an end user authorizes is a different question, answered by their consent.
 */

/* Its own identifier: two files declaring one identifier would collide. */
const AUDIENCE = 'https://mcp.machine.example/mcp';
const OAuthError = Type.Object({ error: Type.String() });
const publicAddress = '93.184.216.34';

function tokenAs(clientId: string, secret: string) {
	return agent.token.post(
		{
			grant_type: 'client_credentials',
			scope: 'mcp:tools-basic',
			resource: AUDIENCE
		},
		{ headers: AuthorizationRequest.basicAuthHeader(clientId, secret) }
	);
}

/**
 * @proves A machine token for a declared resource is issued only to an administrator-created
 * application of the bucket that declared it.
 */
describe('a client credentials token for a declared resource', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'machine_access' });
		const declaring = await bucketOf('client');

		await bindClientToBucket('self-registered', declaring);
		await changeClient('self-registered', { registeredDynamically: true });

		const elsewhere = await getBucketStore().create({
			name: 'Elsewhere users',
			ownerGroupId: UNASSIGNED_GROUP_ID
		});
		await bindClientToBucket('outsider', elsewhere._id);

		await getProtectedResourceStore().create({
			namespace: ROOT_NAMESPACE,
			identifier: AUDIENCE,
			bucketId: declaring,
			name: 'Acme MCP',
			scopes: ['mcp:tools-basic']
		});
	});

	it('is issued to an application an administrator created in the declaring bucket', async () => {
		const res = await tokenAs('client', 'secret');

		expect(res.status).toBe(200);
	});

	it('is refused to an application that registered itself in the declaring bucket', async () => {
		const res = await tokenAs('self-registered', 'self-registered-secret');

		expect(res.status).toBe(400);
		expect(shaped(OAuthError, res.error?.value).error).toBe('invalid_target');
	});

	it('is refused to an application of another bucket', async () => {
		const res = await tokenAs('outsider', 'outsider-secret');

		expect(res.status).toBe(400);
		expect(shaped(OAuthError, res.error?.value).error).toBe('invalid_target');
	});

	describe('to a client known only by its metadata document', () => {
		beforeEach(() => {
			clearDocumentCache();
			resolver.lookup = async () => [publicAddress];
		});

		afterEach(() => {
			mock.restore();
			resolver.lookup = resolver.realLookup;
		});

		/*
		 * Nothing stores such a client, so nothing can say which bucket it belongs to — and it proves only
		 * that it controls a key, which anybody hosting a document can.
		 */
		it('is refused', async () => {
			const { kty, kid, e, n } = clientKey;
			const { identifier } = serveDocument({
				overrides: {
					grant_types: ['client_credentials'],
					response_types: [],
					token_endpoint_auth_method: 'private_key_jwt',
					jwks: { keys: [{ kty, kid, e, n }] }
				}
			});
			const assertion = await JWT.sign(
				{ jti: nanoid(), aud: ISSUER, sub: identifier, iss: identifier },
				createPrivateKey({ format: 'jwk', key: clientKey }),
				'RS256',
				{ expiresIn: 60 }
			);

			const res = await agent.token.post({
				grant_type: 'client_credentials',
				scope: 'mcp:tools-basic',
				resource: AUDIENCE,
				client_id: identifier,
				client_assertion: assertion,
				client_assertion_type:
					'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
			});

			expect(res.status).toBe(400);
			expect(shaped(OAuthError, res.error?.value).error).toBe('invalid_target');
		});
	});
});
