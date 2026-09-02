import {
	getProjectStore,
	getBucketStore,
	getGroupStore,
	adapter
} from '../adapters/index.js';
import { Client } from '../models/client.js';
import { ISSUER } from '../configs/env.js';
import {
	ADMIN_PROJECT_ID,
	ADMIN_BUCKET_ID,
	ADMIN_CLIENT_ID,
	UNASSIGNED_GROUP_ID,
	SYSTEM_GROUP_NAME
} from './consts.js';
import { ADMIN_MCP_CLIENT_ID } from '../mcp/consts.js';

export async function ensureAdminSeed(): Promise<void> {
	/*
	 * The holding group for containers no administrator managed. Seeded before anything that could own
	 * a container, because the reserved admin project and bucket are given it as a formality: they sit
	 * outside the group model and every route touching them refuses before ownership is consulted.
	 *
	 * Kept in step with database/mongodb.ts, which is the real deployment seed — this one is test-only,
	 * and a change to just one of them silently no-ops in production.
	 */
	const groups = getGroupStore();
	if (!(await groups.find(UNASSIGNED_GROUP_ID))) {
		await groups.create({
			_id: UNASSIGNED_GROUP_ID,
			name: SYSTEM_GROUP_NAME,
			kind: 'system',
			members: []
		});
	}

	const buckets = getBucketStore();
	if (!(await buckets.find(ADMIN_BUCKET_ID))) {
		await buckets.create({
			_id: ADMIN_BUCKET_ID,
			name: 'Administrators',
			ownerGroupId: UNASSIGNED_GROUP_ID,
			roles: ['super_admin', 'project_admin'],
			// The reserved admin bucket keeps password login and accepts no providers: the console is a
			// relying party on this server's own issuer, and a second identity source for operators is a
			// separate decision. Both the bucket PATCH and the provider routes refuse it.
			passwordLogin: true,
			// the reserved admin bucket never accepts self-service registration
			registrationOpen: false
		});
	}

	if (!(await buckets.find('redfox'))) {
		await buckets.create({
			_id: 'redfox',
			name: 'Default users',
			ownerGroupId: UNASSIGNED_GROUP_ID,
			roles: []
		});
	}

	const projects = getProjectStore();
	const existingAdminProject = await projects.find(ADMIN_PROJECT_ID);
	if (!existingAdminProject) {
		await projects.create({
			_id: ADMIN_PROJECT_ID,
			name: 'Administration',
			slug: 'admin',
			type: 'admin',
			ownerGroupId: UNASSIGNED_GROUP_ID,
			bucketId: ADMIN_BUCKET_ID,
			clientIds: [ADMIN_CLIENT_ID, ADMIN_MCP_CLIENT_ID]
		});
	} else {
		const existingClientIds = existingAdminProject.clientIds ?? [];
		const missing = [ADMIN_CLIENT_ID, ADMIN_MCP_CLIENT_ID].filter(
			(id) => !existingClientIds.includes(id)
		);
		if (missing.length > 0) {
			await projects.update(ADMIN_PROJECT_ID, {
				clientIds: [...existingClientIds, ...missing]
			});
		}
	}

	/*
	 * The reserved MCP agent client. Public with mandatory PKCE, so nothing secret needs distributing,
	 * and it lives in the admin project because that is what routes it to the administrator bucket:
	 * `resolveBucketForClient` sends a client there only if it is the reserved console client or belongs
	 * to a project whose bucket is the admin bucket. A dynamically registered client falls through to
	 * the default bucket and cannot authenticate an administrator at all.
	 *
	 * Loopback redirect URIs, which is what a local MCP client can actually receive a code on. The port
	 * is unpredictable, so the standard three are registered; OAuth 2.1 allows a loopback port to vary.
	 */
	if (!(await Client.tryFind(ADMIN_MCP_CLIENT_ID))) {
		await adapter('Client').upsert(ADMIN_MCP_CLIENT_ID, {
			clientId: ADMIN_MCP_CLIENT_ID,
			applicationType: 'native',
			grantTypes: ['authorization_code', 'refresh_token'],
			responseTypes: ['code'],
			redirectUris: [
				'http://127.0.0.1:33418/callback',
				'http://localhost:33418/callback',
				'http://127.0.0.1/callback'
			],
			token_endpoint_auth_method: 'none',
			'consent.require': true
		});
	}

	if (!(await Client.tryFind(ADMIN_CLIENT_ID))) {
		await adapter('Client').upsert(ADMIN_CLIENT_ID, {
			clientId: ADMIN_CLIENT_ID,
			applicationType: 'web',
			grantTypes: ['authorization_code'],
			responseTypes: ['code'],
			redirectUris: [`${ISSUER}/admin/callback`],
			token_endpoint_auth_method: 'none',
			'consent.require': false
		});
	}
}
