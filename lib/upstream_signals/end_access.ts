import type { User, UserBucket } from '../adapters/types.js';
import { recordUpstreamAudit } from '../admin/audit/record.js';
import { revokeEndUserAccess } from '../end_users/service.js';
import { UpstreamSweepIncomplete } from '../helpers/errors.js';
import type { FederationProvider } from '../federation/types.js';

/*
 * Ends a user's access at a provider's request, through the same operation an administrator's "sign out
 * everywhere" runs (lib/end_users/service.ts), and recorded under the same action — the effect is the same,
 * only the actor differs. The account is left as it was: revocation is not deactivation.
 *
 * Audit-first holds: the entry is written after every refusal and before anything is ended, so a refused
 * request leaves no entry and no access ends without one. The subject identifier the provider sent is not in
 * the entry; the target is the user, which is what an administrator needs and nothing a provider sent.
 */
export async function endAccessForUpstream(
	bucket: UserBucket,
	provider: FederationProvider,
	user: User
): Promise<void> {
	const { revoked } = await revokeEndUserAccess(bucket, user._id, () =>
		recordUpstreamAudit(bucket._id, provider.id, 'enduser.signout', user._id, {
			targetScope: bucket._id,
			ownerGroupId: bucket.ownerGroupId
		})
	);
	if (revoked && revoked.failedAreas.length > 0) {
		throw new UpstreamSweepIncomplete(revoked.failedAreas);
	}
}
