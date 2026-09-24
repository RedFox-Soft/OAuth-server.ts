import * as errors from '../../errors.ts';
import { pairwiseIdentifier } from '../../../addon/index.js';
import { Prompt, type CheckPartial } from '../prompt.js';
import type { OIDCContext } from '../../oidc_context.ts';
import { claimRequest } from '../../claim_request.ts';
import type { PipelineParams } from '../../../consts/param_list.ts';

class LoginPromt extends Prompt {
	name = 'login';
	requestable = true;
	defaultError = 'login_required';

	details(oidc: OIDCContext<PipelineParams>) {
		return {
			...(oidc.params.max_age === undefined
				? undefined
				: { max_age: oidc.params.max_age }),
			...(oidc.params.login_hint === undefined
				? undefined
				: { login_hint: oidc.params.login_hint }),
			...(oidc.params.id_token_hint === undefined
				? undefined
				: { id_token_hint: oidc.params.id_token_hint })
		};
	}

	checks: CheckPartial[] = [
		{
			reason: 'no_session',
			description: 'End-User authentication is required',
			/*
			 * The resolved account, not the identifier the session happens to carry. The two are not the
			 * same question, and reading the identifier answers the wrong one: an account identifier is
			 * only meaningful inside the bucket that issued it, so a session established in one bucket
			 * presents an identifier that resolves to nobody in another.
			 *
			 * Reading it suppressed the sign-in prompt for a request that had no account at all. The
			 * pipeline then carried on without one, `loadGrant` left the grant unset because it only
			 * builds a grant for a known account, and the first consent check to reach inside it faulted —
			 * so an end user who had done nothing wrong was handed `server_error` with nothing to retry.
			 *
			 * `loadAccount` runs before the policy, so the account (`oidc.entities.Account`) is populated by the time this is
			 * asked, and it is set only when the account resolved in the bucket this request belongs to.
			 * That also makes a deleted or deactivated account ask for a sign-in rather than fault, which
			 * the identifier check could never do.
			 */
			check: (oidc) => {
				return !oidc.entities.Account;
			}
		},
		{
			reason: 'max_age',
			description: 'End-User authentication could not be obtained',
			check: (oidc) => {
				const maxAge = oidc.params.max_age;
				if (typeof maxAge !== 'string' && typeof maxAge !== 'number') {
					return false;
				}
				if (!oidc.session.payload.accountId) {
					return true;
				}
				if (oidc.session.past(maxAge) && (!oidc.result || !oidc.result.login)) {
					return true;
				}
				return false;
			}
		},
		{
			reason: 'id_token_hint',
			description: 'id_token_hint and authenticated subject do not match',
			check: async (oidc) => {
				if (oidc.entities.IdTokenHint === undefined) {
					return false;
				}
				const { payload } = oidc.entities.IdTokenHint;
				let sub = oidc.session.payload.accountId;
				if (sub === undefined) {
					return true;
				}
				if (oidc.client.subjectType === 'pairwise') {
					sub = await pairwiseIdentifier(sub, oidc.client);
				}
				if (payload.sub !== sub) {
					return true;
				}
				return false;
			}
		},
		{
			reason: 'claims_id_token_sub_value',
			description: 'requested subject could not be obtained',
			check: async (oidc) => {
				/*
				 * Through `claimRequest`: a member may be any JSON value, and `in` on a primitive threw,
				 * answering a client's `{"sub": true}` with server_error. A non-object requests the subject
				 * with no constraint, like `null`.
				 */
				const request = claimRequest(oidc.claims.id_token?.sub);
				if (!('value' in request)) {
					return false;
				}
				let sub = oidc.session.payload.accountId;
				if (sub === undefined) {
					return true;
				}
				if (oidc.client.subjectType === 'pairwise') {
					sub = await pairwiseIdentifier(sub, oidc.client);
				}
				if (request.value !== sub) {
					return true;
				}
				return false;
			},
			details: (oidc) => ({ sub: oidc.claims.id_token?.sub })
		},
		{
			reason: 'essential_acrs',
			description: 'none of the requested ACRs could not be obtained',
			/*
			 * OIDC Core §5.5.1.1: an essential acr that cannot be met MUST be treated as a failed
			 * authentication attempt. `unmet_authentication_requirements` is the code registered for
			 * exactly that case, so it replaces the prompt's `login_required` default — which said the
			 * end user had not authenticated, when in fact they had.
			 */
			error: 'unmet_authentication_requirements',
			check: (oidc) => {
				const request = claimRequest(oidc.claims.id_token?.acr);
				if (!request?.essential || !request?.values) {
					return false;
				}
				if (!Array.isArray(request.values)) {
					throw new errors.InvalidRequest(
						'invalid claims.id_token.acr.values type'
					);
				}
				if (request.values.includes(oidc.acr)) {
					return false;
				}
				return true;
			},
			details: (oidc) => ({ acr: oidc.claims.id_token?.acr })
		},
		{
			reason: 'essential_acr',
			description: 'requested ACR could not be obtained',
			// The single-valued form of the requirement above, and the same rule applies to it.
			error: 'unmet_authentication_requirements',
			check: (oidc) => {
				const request = claimRequest(oidc.claims.id_token?.acr);
				if (!request?.essential || !request?.value) {
					return false;
				}
				if (request.value === oidc.acr) {
					return false;
				}
				return true;
			},
			details: (oidc) => ({ acr: oidc.claims.id_token?.acr })
		}
	];
}

export default () => new LoginPromt();
