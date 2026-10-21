import { adapter } from '../adapters/index.js';
import type { UserBucket } from '../adapters/types.js';
import { DEFAULT_BUCKET_ID } from './consts.js';

/*
 * Whether an application is one of this project's own, for a configuration that names it (specs/108): the
 * applications a project lets ask for ID-JAGs, and those a provider's plain assertions may be presented by.
 * An application belongs to the project it was created in; one stored with no project belongs to the default
 * project, which is where every request served at the root signs people in. A client known only by its
 * metadata document has no stored record and so belongs to none — nobody here vouched for it.
 */
export async function belongsToProject(
	bucket: Pick<UserBucket, '_id'>,
	clientId: string
): Promise<boolean> {
	const stored = await adapter('Client').find(clientId);
	if (!stored) return false;
	const owner = stored.bucketId;
	return typeof owner === 'string'
		? owner === bucket._id
		: bucket._id === DEFAULT_BUCKET_ID;
}
