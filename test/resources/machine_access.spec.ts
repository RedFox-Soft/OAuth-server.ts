import { describe, beforeAll, beforeEach, it, expect } from 'bun:test';

import bootstrap, { agent } from '../test_helper.js';
import { AuthorizationRequest } from 'test/AuthorizationRequest.js';
import { getProtectedResourceStore } from 'lib/adapters/index.ts';
import { ROOT_NAMESPACE } from 'lib/resources/namespace.ts';
import { shaped } from 'test/shape.js';
import { projectOf } from './owning_project.js';
import { Type } from '@sinclair/typebox';

/*
 * A client credentials token acts for nobody: no end user signs in and nobody consents, so the only
 * thing standing between a client and a resource is who the client is. A declared resource belongs to
 * the project that declared it, and a machine token for it goes to that project's clients alone.
 * Before, any confidential client of any project — or one that registered itself — could ask for a
 * token carrying another tenant's resource as its audience and that resource's scopes, which the
 * resource server has no reason to refuse.
 *
 * A token an end user authorizes is a different question, answered by their consent; that is what lets
 * a client belonging to no project reach a declared resource at all.
 */

const AUDIENCE = 'https://mcp.acme.example/mcp';
const OAuthError = Type.Object({ error: Type.String() });

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
 * @proves A machine token for a declared resource is issued only to a client of the project that
 * declared it.
 */
describe('a client credentials token for a declared resource', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'resources' });
		await projectOf('outsider');
	});

	beforeEach(async () => {
		const store = getProtectedResourceStore();
		for (const resource of await store.list()) {
			await store.destroy(resource.namespace, resource.identifier);
		}
		await store.create({
			namespace: ROOT_NAMESPACE,
			identifier: AUDIENCE,
			projectId: await projectOf('client'),
			name: 'Acme MCP',
			scopes: ['mcp:tools-basic']
		});
	});

	it('is issued to a client of the project that declared the resource', async () => {
		const res = await tokenAs('client', 'secret');

		expect(res.status).toBe(200);
	});

	it('is refused to a client of another project', async () => {
		const res = await tokenAs('outsider', 'outsider-secret');

		expect(res.status).toBe(400);
		expect(shaped(OAuthError, res.error?.value).error).toBe('invalid_target');
	});

	it('is refused to a client belonging to no project', async () => {
		const res = await tokenAs('stranger', 'stranger-secret');

		expect(res.status).toBe(400);
		expect(shaped(OAuthError, res.error?.value).error).toBe('invalid_target');
	});
});
