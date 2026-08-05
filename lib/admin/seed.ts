import { getProjectStore, getBucketStore, adapter } from '../adapters/index.js';
import { Client } from '../models/client.js';
import { ISSUER } from '../configs/env.js';
import {
	ADMIN_PROJECT_ID,
	ADMIN_BUCKET_ID,
	ADMIN_CLIENT_ID
} from './consts.js';

export async function ensureAdminSeed(): Promise<void> {
	const buckets = getBucketStore();
	if (!(await buckets.find(ADMIN_BUCKET_ID))) {
		await buckets.create({
			_id: ADMIN_BUCKET_ID,
			name: 'Administrators',
			managedBy: [],
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
			managedBy: [],
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
			managedBy: [],
			bucketId: ADMIN_BUCKET_ID,
			clientIds: [ADMIN_CLIENT_ID]
		});
	} else {
		const existingClientIds = existingAdminProject.clientIds ?? [];
		if (!existingClientIds.includes(ADMIN_CLIENT_ID)) {
			await projects.update(ADMIN_PROJECT_ID, {
				clientIds: [...existingClientIds, ADMIN_CLIENT_ID]
			});
		}
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
