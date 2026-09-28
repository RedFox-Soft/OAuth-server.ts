import { getBucketStore, getUserStore } from '../adapters/index.js';
import type { InteractionPayloadType } from '../models/interaction.js';
import { findEnabledProvider } from './providers.js';
import { linkIdentity } from './resolve.js';

/*
 * Complete or discard the upstream identity a federated sign-in left on the interaction, at the moment
 * the interaction's own sign-in completes.
 *
 * Called with `result.login` already written and before `resume()`, from every door that writes one, so
 * "completes" means every factor the bucket asks for. Linked only to the account the identity matched,
 * in the bucket it matched in: a sign-in as anybody else discards it, because the assertion proved
 * control of that account's address, not of the account now signing in. The provider is re-resolved
 * rather than trusted from the interaction, so one disabled in the meantime links nothing, and the pair
 * is re-checked because another account may have gained it while the person was typing a password.
 */
export async function settlePendingLink(
	payload: InteractionPayloadType,
	bucketId: string
): Promise<void> {
	const pending = payload.pendingLink;
	if (!pending) return;
	delete payload.pendingLink;

	if (
		payload.result?.login?.accountId !== pending.accountId ||
		pending.bucketId !== bucketId
	) {
		return;
	}

	const bucket = await getBucketStore().find(bucketId);
	if (!findEnabledProvider(bucket, pending.providerId)) return;

	const store = getUserStore(bucketId);
	if (await store.findByFederatedIdentity(pending.providerId, pending.sub)) {
		return;
	}
	const account = await store.find(pending.accountId);
	if (!account) return;

	await linkIdentity(store, account, {
		providerId: pending.providerId,
		sub: pending.sub,
		claims: pending.claims
	});
}
