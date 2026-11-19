import { Prompt, type CheckPartial } from '../prompt.js';
import type { OIDCContext } from '../../oidc_context.js';
import type { PipelineParams } from '../../../consts/param_list.js';
import { getBucketStore, getUserStore } from '../../../adapters/index.js';
import { offerable } from '../../../passkeys/offerable.js';

/*
 * The passkey offer after a sign-in with a password (specs/141 research R1), the third prompt of the base policy.
 *
 * Its position is most of its rule. The policy stops at the first prompt a request fails, so a sign-in that still needs
 * a code goes to the code-required page from the login prompt and never reaches this one; a sign-in that needs consent
 * is asked for it first, and the consent page's own result carries no login, so this does not follow it; and a request
 * that needed no page has no result at all. By the time it shows, `resume` has signed the person in and saved the
 * session, so the passkey it makes can be bound to that browser session, and leaving the page leaves them signed in.
 *
 * Whether a sign-in may lead here was decided at the door that took the password (`passkeyOffer` on the login); whether
 * it does now is `offerable`. Not requestable: no client asks for it.
 */
const pendingKind = new WeakMap<object, 'full' | 'conditional'>();

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
				if (!bucket || !user || !(await offerable(bucket, user))) return false;
				pendingKind.set(oidc, kind);
				return true;
			},
			details: (oidc) => ({ kind: pendingKind.get(oidc) })
		}
	];
}

export default () => new PasskeyOfferPrompt();
