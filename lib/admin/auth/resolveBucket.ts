import { getProjectStore } from '../../adapters/index.js';
import { ADMIN_CLIENT_ID, ADMIN_BUCKET_ID } from '../consts.js';

// Resolve which user bucket a client authenticates against at login time.
//   1. the reserved admin client → the admin bucket
//   2. a client assigned to a project → that project's bucket
//   3. otherwise → the default 'redfox' bucket (unassigned/dynamic clients)
export async function resolveBucketForClient(
	clientId: string | undefined
): Promise<string> {
	if (clientId === ADMIN_CLIENT_ID) return ADMIN_BUCKET_ID;
	if (clientId) {
		const project = await getProjectStore().findByClientId(clientId);
		if (project?.bucketId) return project.bucketId;
	}
	return 'redfox';
}
