import { getBucketStore, getProjectStore } from '../adapters/index.js';
import { resolveBucketForRequest } from '../admin/auth/resolveBucket.js';
import type { OIDCContext } from '../helpers/oidc_context.js';

/*
 * Whether this request's client may skip the consent screen for the user signing in.
 *
 * `consent.require: false` is a tenant's decision about its own users, so it is honoured only where they
 * are its own: in a bucket owned by the group that owns the client's project. Any member of a group can
 * create a project and a client in it with consent off, and a project with no bucket signs its clients
 * into the default bucket, which every tenant shares — so honouring the flag there handed a tenant the
 * claims of every default-bucket user with a session, with `prompt=none` and no page shown.
 *
 * A client in no project keeps the flag as stored. Nothing a caller controls can set it on one: dynamic
 * registration and client documents cannot carry it (lib/models/client/wire.ts), so such a client was
 * provisioned by the operator.
 *
 * Decided per request, not at write time, so a project that later loses its bucket stops skipping consent
 * at once. Memoised per context: the consent policy and the grant loader both ask.
 */
const decided = new WeakMap<object, Promise<boolean>>();

export function consentWaived(oidc: OIDCContext): Promise<boolean> {
	let answer = decided.get(oidc);
	if (!answer) {
		answer = decide(oidc);
		decided.set(oidc, answer);
	}
	return answer;
}

async function decide(oidc: OIDCContext): Promise<boolean> {
	const { client } = oidc;
	if (client['consent.require'] !== false) return false;

	const project = await getProjectStore().findByClientId(client.clientId);
	if (!project) return true;

	const bucket = await getBucketStore().find(
		await resolveBucketForRequest(
			client.clientId,
			oidc.params?.resource,
			oidc.bucket
		)
	);
	return bucket?.ownerGroupId === project.ownerGroupId;
}
