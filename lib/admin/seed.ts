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
			authMethods: ['password']
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
