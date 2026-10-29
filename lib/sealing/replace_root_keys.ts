import { recordSystemAudit } from '../admin/audit/record.js';
import { revokeKey, type KeyOwner } from '../admin/key_lifecycle.js';
import { getBucketKeysStore } from '../adapters/index.js';
import { KEYRING_RECOVERY_ACTOR } from '../consts/admin_audit_routes.js';
import {
	invalidateRootKeys,
	ROOT_KEY_OWNER,
	rootKeys
} from '../keys/issuer_keys.js';
import { unreadableFieldsOf } from './decorators.js';
import { activeKeyring } from './keyring.js';

/*
 * The way back when the root signing keys cannot be opened with the keyring in use (specs/116 US5-6): the
 * console's own sign-in is signed with them, so no administrator can reach the console to repair them. Each
 * unreadable root key is revoked the way the console revokes one, which promotes a readable standby or
 * generates a fresh signer, so every algorithm keeps one.
 */
export async function replaceRootKeys(): Promise<{
	revoked: string[];
	signing: string[];
}> {
	if (!activeKeyring()) {
		throw new Error(
			'no keyring is in use: supply the keyring first, so the replacement keys are sealed with it'
		);
	}
	const owner: KeyOwner = {
		id: ROOT_KEY_OWNER,
		audit: async (verb, kid, keys) => {
			await recordSystemAudit(KEYRING_RECOVERY_ACTOR, `jwks.${verb}`, kid, {
				kid,
				...(keys ? { keys } : {})
			});
		},
		invalidate: async () => {
			invalidateRootKeys();
			await rootKeys();
		}
	};
	const revoked: string[] = [];
	const signing: string[] = [];
	for (;;) {
		const unreadable = (
			await getBucketKeysStore().listByBucket(ROOT_KEY_OWNER)
		).find(
			(key) => key.state !== 'revoked' && unreadableFieldsOf(key.jwk).length > 0
		);
		if (!unreadable) break;
		const outcome = await revokeKey(owner, unreadable.kid, unreadable.kid);
		revoked.push(unreadable.kid);
		if (outcome.replacement) signing.push(outcome.replacement);
	}
	return { revoked, signing };
}
