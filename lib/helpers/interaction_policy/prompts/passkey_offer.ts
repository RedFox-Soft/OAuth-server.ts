import { Prompt, type CheckPartial } from '../prompt.js';
import type { OIDCContext } from '../../oidc_context.js';
import type { PipelineParams } from '../../../consts/param_list.js';
import { getBucketStore, getUserStore } from '../../../adapters/index.js';
import { campaignDue, offerable } from '../../../passkeys/offerable.js';

const pendingOffer = new WeakMap<
	object,
	{ kind: 'full' | 'conditional'; mode: 'offer' | 'campaign' }
>();

class PasskeyOfferPrompt extends Prompt {
	name = 'passkey-offer';
	requestable = false;
	defaultError = 'interaction_required';
	checks: CheckPartial[] = [
		{
			reason: 'passkey_offer',
			description: 'a passkey is offered after a password sign-in',
			check: async (oidc: OIDCContext<PipelineParams>) => {
				const kind = oidc.result?.login?.passkeyOffer;
				const { accountId, bucketId } = oidc.session.payload;
				if (kind === undefined || !accountId || !bucketId) return false;
				const bucket = await getBucketStore().find(bucketId);
				const user = bucket
					? await getUserStore(bucketId).find(accountId)
					: null;
				if (!bucket || !user) return false;
				if (await campaignDue(bucket, user)) {
					pendingOffer.set(oidc, { kind, mode: 'campaign' });
					return true;
				}
				if (await offerable(bucket, user)) {
					pendingOffer.set(oidc, { kind, mode: 'offer' });
					return true;
				}
				return false;
			},
			details: (oidc) => pendingOffer.get(oidc) ?? {}
		}
	];
}

export default () => new PasskeyOfferPrompt();
