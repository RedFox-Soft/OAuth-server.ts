import { elysia } from 'lib/index.ts';
import { ISSUER } from 'lib/configs/env.ts';
import {
	getBucketStore,
	getProjectStore,
	getProtectedResourceStore
} from 'lib/adapters/index.ts';
import { UNASSIGNED_GROUP_ID } from 'lib/admin/consts.ts';
import { Type } from '@sinclair/typebox';
import { present, shaped } from 'test/shape.ts';

export const RESOURCE = 'https://mcp.keys.example/mcp';

/* The two addresses a spec file's tenants live at, named for the file so no two files share one. */
export function addresses(prefix: string) {
	const slug = `${prefix}keys`;
	const host = `${prefix}keys.e.ly`;
	return {
		slug,
		host,
		pathOrigin: `${ISSUER}/${slug}`,
		hostOrigin: `http://${host}`,
		pathClient: `${prefix}-path-machine`,
		hostClient: `${prefix}-host-machine`
	};
}

/* A bucket at an address, a project in it holding one machine client, and one declared resource. */
export async function tenant(
	address: { slug: string } | { host: string },
	clientId: string
): Promise<string> {
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
	await getProtectedResourceStore().create({
		namespace: bucket._id,
		identifier: RESOURCE,
		projectId: project._id,
		name: RESOURCE,
		scopes: ['keys:read']
	});
	return bucket._id;
}

export async function machineToken(origin: string, clientId: string) {
	const response = await elysia.handle(
		new Request(`${origin}/token`, {
			method: 'POST',
			headers: {
				'content-type': 'application/x-www-form-urlencoded',
				authorization: `Basic ${btoa(`${clientId}:${clientId}-secret`)}`
			},
			body: new URLSearchParams({
				grant_type: 'client_credentials',
				resource: RESOURCE
			})
		})
	);
	const body = shaped(
		Type.Object({ access_token: Type.Optional(Type.String()) }),
		await response.json()
	);
	return present(body.access_token, 'an access token');
}

const KeySet = Type.Object({
	keys: Type.Array(Type.Record(Type.String(), Type.Unknown()))
});

export async function keySetAt(url: string) {
	const response = await elysia.handle(new Request(url));
	return { status: response.status, body: await response.text() };
}

export async function publishedKeys(url: string) {
	const { status, body } = await keySetAt(url);
	if (status !== 200) throw new Error(`${url} answered ${status}`);
	return shaped(KeySet, JSON.parse(body));
}
