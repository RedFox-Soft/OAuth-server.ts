import { DEFAULT_BUCKET_ID } from 'lib/admin/consts.ts';
import { adapter } from 'lib/adapters/index.ts';

/*
 * The bucket a client belongs to, for a declared resource to belong to as well. A client credentials
 * token for a declared resource goes only to a client of the declaring bucket (specs/099), so a spec
 * minting one binds the client the way creating it in that bucket would. A client that already belongs to
 * a bucket keeps it: a client's bucket never changes.
 */
export async function bucketOf(clientId: string): Promise<string> {
	const stored = await adapter('Client').find(clientId);
	if (!stored) {
		throw new Error(`no client '${clientId}' is seeded in the Client store`);
	}
	if (typeof stored.bucketId === 'string') return stored.bucketId;
	await adapter('Client').upsert(clientId, {
		...stored,
		bucketId: DEFAULT_BUCKET_ID
	});
	return DEFAULT_BUCKET_ID;
}
