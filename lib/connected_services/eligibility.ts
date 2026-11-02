import { adapter } from '../adapters/index.js';
import type { UserBucket } from '../adapters/types.js';
import { ADMIN_BUCKET_ID } from '../admin/consts.js';
import { belongsToProject } from '../admin/project_applications.js';
import { TOKEN_EXCHANGE_GRANT } from '../consts/assertion_grants.js';
import { tryFindClient } from '../models/client.js';

/*
 * Whether an application may ever obtain a person's upstream tokens (specs/118 FR-003, FR-019): an application an
 * administrator created in this project, that proves who it is and holds the token exchange grant. Read by the
 * allow-list, by an API's exchanging application and by the exchange itself, so the three cannot disagree. Answers
 * why not, in words an administrator can act on, or undefined.
 */
export async function whyCannotExchange(
	bucket: Pick<UserBucket, '_id'>,
	clientId: string
): Promise<string | undefined> {
	if (bucket._id === ADMIN_BUCKET_ID) {
		return 'applications of the Administrators project only sign administrators in';
	}
	if (!(await belongsToProject(bucket, clientId))) {
		return `application ${clientId} is not an application of this project`;
	}
	const stored = await adapter('Client').find(clientId);
	if (stored?.registeredDynamically === true) {
		return `application ${clientId} registered itself, and nobody vouched for it`;
	}
	const client = await tryFindClient(clientId, { administering: true });
	if (!client) {
		return `application ${clientId} is not an application of this project`;
	}
	if (client.tokenEndpointAuthMethod === 'none') {
		return `application ${clientId} does not authenticate, so it cannot be handed an upstream credential`;
	}
	if (!client.grantTypes.includes(TOKEN_EXCHANGE_GRANT)) {
		return `application ${clientId} does not have the token exchange grant`;
	}
	return undefined;
}
