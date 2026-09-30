import { recordAdminAudit } from '../audit/record.js';
import { AdminError, type AdminContext } from '../auth/rbac.js';
import * as lifecycle from '../key_lifecycle.js';
import {
	invalidateRootKeys,
	ROOT_KEY_OWNER,
	rootKeys
} from '../../keys/issuer_keys.js';

// The generation allow-list lives in ./schema.ts, so the MCP tool catalogue can describe the same set
// without importing this module (which reaches the adapters, and from there a db module that connects
// at import time). Re-exported here because callers of the service used to read it.
import { SUPPORTED_ALGS, type SupportedAlg } from './schema.js';
export { SUPPORTED_ALGS };

/*
 * The root issuer's keys — the ones the default bucket, the administrators and every bucket without an
 * address of its own sign with — managed through the lifecycle every issuer's keys follow
 * (`../key_lifecycle.ts`): generate publishes, promote signs, retire ends. No step needs a restart:
 * every instance reloads the set from the store within the cache bound, which the publication window is
 * written against.
 *
 * A super administrator's alone, because a mistake here reaches every root-served relying party at once.
 */
function rootOwner(ctx: AdminContext): lifecycle.KeyOwner {
	return {
		id: ROOT_KEY_OWNER,
		audit: async (verb, kid) => {
			await recordAdminAudit(ctx, `jwks.${verb}`, kid);
		},
		/*
		 * Reloaded, not only dropped: the reload is what refreshes the mirror client registration reads the
		 * advertised algorithms from, so this instance accepts a newly signing algorithm on its next request.
		 */
		invalidate: async () => {
			invalidateRootKeys();
			await rootKeys();
		}
	};
}

export async function listKeys(ctx: AdminContext) {
	return {
		...(await lifecycle.listKeys(rootOwner(ctx))),
		supportedAlgorithms: [...SUPPORTED_ALGS]
	};
}

export async function generateKey(ctx: AdminContext, alg: unknown) {
	if (
		typeof alg !== 'string' ||
		!SUPPORTED_ALGS.includes(alg as SupportedAlg)
	) {
		throw new AdminError(
			422,
			`unsupported algorithm; expected one of: ${SUPPORTED_ALGS.join(', ')}`
		);
	}
	return lifecycle.generateKey(rootOwner(ctx), alg as SupportedAlg);
}

export async function promoteKey(ctx: AdminContext, kid: string) {
	return lifecycle.promoteKey(rootOwner(ctx), kid);
}

export async function retireKey(
	ctx: AdminContext,
	kid: string,
	confirm: unknown
) {
	return lifecycle.retireKey(rootOwner(ctx), kid, confirm);
}
