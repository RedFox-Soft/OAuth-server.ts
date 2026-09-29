import { getBucketStore } from '../adapters/index.js';
import { isAddressable } from '../admin/auth/bucketAddress.js';
import { ROOT_NAMESPACE } from './declaration_id.js';

export { declarationId, ROOT_NAMESPACE } from './declaration_id.js';

/*
 * The scope within which a declared resource identifier is unique: one per addressable bucket, and one
 * for everything served at the root issuer.
 *
 * Keyed by the bucket's id rather than by its issuer string, because the issuer is what changes when an
 * operator moves a bucket from a path to a hostname or renames its slug, and none of those change which
 * tenant the declarations belong to. Every root-served bucket — the default bucket, the administrators
 * bucket, a legacy bucket with no address, and a project with no bucket at all — maps to the one root
 * namespace, because they share one issuer and a resource's metadata has no way to tell them apart.
 * That is also what makes a context whose bucket was derived rather than addressed harmless here:
 * whichever root-served bucket it names, the namespace is the same.
 */
export function namespaceOf(bucket: {
	_id: string;
	slug?: string;
	host?: string;
}): string {
	return isAddressable(bucket) ? bucket._id : ROOT_NAMESPACE;
}

/* A project with no bucket, or whose bucket record is gone, is served at the root. */
export async function namespaceOfProject(project: {
	bucketId?: string | null;
}): Promise<string> {
	if (!project.bucketId) return ROOT_NAMESPACE;
	const bucket = await getBucketStore().find(project.bucketId);
	return bucket ? namespaceOf(bucket) : ROOT_NAMESPACE;
}
