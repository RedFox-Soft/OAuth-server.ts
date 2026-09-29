import { beforeAll, describe, expect, it } from 'bun:test';

import bootstrap from '../test_helper.ts';
import { elysia } from 'lib/index.ts';
import { ISSUER } from 'lib/configs/env.ts';
import {
	getBucketStore,
	getProjectStore,
	getProtectedResourceStore
} from 'lib/adapters/index.ts';
import { forgetBucketAddresses } from 'lib/admin/auth/bucketAddress.ts';
import { UNASSIGNED_GROUP_ID } from 'lib/admin/consts.ts';
import { decode } from 'lib/helpers/jwt.ts';
import { Type } from '@sinclair/typebox';
import { present, shaped } from 'test/shape.ts';

const SHARED = 'https://mcp.shared.example/mcp';
const ONLY_GLOBEX = 'https://mcp.globex-only.example/mcp';
const ACME_SLUG = 'acmens';
const GLOBEX_HOST = 'globexns.e.ly';

const TokenAnswer = Type.Object({
	access_token: Type.Optional(Type.String()),
	error: Type.Optional(Type.String()),
	error_description: Type.Optional(Type.String())
});

async function tenant(
	address: { slug: string } | { host: string },
	clientId: string,
	declarations: Array<{ identifier: string; scopes: string[] }>
) {
	const bucket = await getBucketStore().create({
		ownerGroupId: UNASSIGNED_GROUP_ID,
		name: clientId,
		...address
	});
	const project = await getProjectStore().create({
		ownerGroupId: UNASSIGNED_GROUP_ID,
		name: clientId,
		slug: `${clientId}-${Math.random().toString(36).slice(2)}`
	});
	await getProjectStore().update(project._id, {
		bucketId: bucket._id,
		clientIds: [clientId]
	});
	for (const { identifier, scopes } of declarations) {
		await getProtectedResourceStore().create({
			namespace: bucket._id,
			identifier,
			projectId: project._id,
			name: identifier,
			scopes
		});
	}
}

async function machineToken(
	origin: string,
	clientId: string,
	resource: string,
	scope?: string
) {
	const response = await elysia.handle(
		new Request(`${origin}/token`, {
			method: 'POST',
			headers: {
				'content-type': 'application/x-www-form-urlencoded',
				authorization: `Basic ${btoa(`${clientId}:${clientId}-secret`)}`
			},
			body: new URLSearchParams({
				grant_type: 'client_credentials',
				resource,
				...(scope ? { scope } : {})
			})
		})
	);
	return shaped(TokenAnswer, await response.json());
}

const ACME = `${ISSUER}/${ACME_SLUG}`;
const GLOBEX = `http://${GLOBEX_HOST}`;

/**
 * @proves A resource indicator at a bucket's address resolves to that bucket's own declaration and
 * never to another tenant's, so two tenants may protect the same URL and neither can see or steer the
 * other's.
 */
describe('a resource indicator at a bucket address', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'namespace_resolution' });
		forgetBucketAddresses();
		await tenant({ slug: ACME_SLUG }, 'acme-machine', [
			{ identifier: SHARED, scopes: ['acme:read'] }
		]);
		await tenant({ host: GLOBEX_HOST }, 'globex-machine', [
			{ identifier: SHARED, scopes: ['globex:read'] },
			{ identifier: ONLY_GLOBEX, scopes: ['globex:read'] }
		]);
	});

	it('gets a token with the path bucket own scopes and issuer when two buckets declare the resource', async () => {
		const answer = await machineToken(
			ACME,
			'acme-machine',
			SHARED,
			'acme:read'
		);

		const { payload } = decode(present(answer.access_token, 'an access token'));
		expect(payload).toMatchObject({
			iss: ACME,
			aud: SHARED,
			scope: 'acme:read'
		});
	});

	it('gets a token with the host bucket own scopes and issuer when two buckets declare the resource', async () => {
		const answer = await machineToken(
			GLOBEX,
			'globex-machine',
			SHARED,
			'globex:read'
		);

		const { payload } = decode(present(answer.access_token, 'an access token'));
		expect(payload).toMatchObject({
			iss: GLOBEX,
			aud: SHARED,
			scope: 'globex:read'
		});
	});

	/*
	 * The refusal is the one an identifier nobody declared gets, word for word: answering differently
	 * would tell anyone holding a client of one tenant which identifiers another tenant protects.
	 */
	it('is refused as an undeclared resource when only another bucket declares it', async () => {
		const elsewhere = await machineToken(ACME, 'acme-machine', ONLY_GLOBEX);
		const nowhere = await machineToken(
			ACME,
			'acme-machine',
			'https://mcp.nobody.example/mcp'
		);

		expect(elsewhere.error).toBe('invalid_target');
		expect(elsewhere).toEqual(nowhere);
	});
});
