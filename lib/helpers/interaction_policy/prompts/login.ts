import * as errors from '../../errors.ts';
import { pairwiseIdentifier } from '../../../addon/index.js';
import { Prompt } from '../prompt.js';

class LoginPromt extends Prompt {
	name = 'login';
	requestable = true;
	defaultError = 'login_required';

	details(ctx: any) {
		const { oidc } = ctx;

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

	checks = [
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
			 * pipeline then carried on without one, `loadGrant` left `oidc.grant` unset because it only
			 * builds a grant for a known account, and the first consent check to reach inside it faulted —
			 * so an end user who had done nothing wrong was handed `server_error` with nothing to retry.
			 *
			 * `loadAccount` runs before the policy, so `oidc.account` is populated by the time this is
			 * asked, and it is set only when the account resolved in the bucket this request belongs to.
			 * That also makes a deleted or deactivated account ask for a sign-in rather than fault, which
			 * the identifier check could never do.
			 */
			check: (ctx: any) => {
				const { oidc } = ctx;
				return !oidc.account;
			}
		},
		{
			reason: 'max_age',
			description: 'End-User authentication could not be obtained',
			check: (ctx: any) => {
				const { oidc } = ctx;
				if (oidc.params.max_age === undefined) {
					return false;
				}
				if (!oidc.session.payload.accountId) {
					return true;
				}
				if (
					oidc.session.past(oidc.params.max_age) &&
					(!ctx.oidc.result || !ctx.oidc.result.login)
				) {
					return true;
				}
				return false;
			}
		},
		{
			reason: 'id_token_hint',
			description: 'id_token_hint and authenticated subject do not match',
			check: async (ctx: any) => {
				const { oidc } = ctx;
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
			check: async (ctx: any) => {
				const { oidc } = ctx;
				if (
					!oidc.claims.id_token ||
					!oidc.claims.id_token.sub ||
					!('value' in oidc.claims.id_token.sub)
				) {
					return false;
				}
				let sub = oidc.session.payload.accountId;
				if (sub === undefined) {
					return true;
				}
				if (oidc.client.subjectType === 'pairwise') {
					sub = await pairwiseIdentifier(sub, oidc.client);
				}
				if (oidc.claims.id_token.sub.value !== sub) {
					return true;
				}
				return false;
			},
			details: ({ oidc }: any) => ({ sub: oidc.claims.id_token.sub })
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
			check: (ctx: any) => {
				const { oidc } = ctx;
				const request = oidc.claims?.id_token?.acr ?? {};
				if (!request?.essential || !request?.values) {
					return false;
				}
				if (!Array.isArray(oidc.claims.id_token.acr.values)) {
					throw new errors.InvalidRequest(
						'invalid claims.id_token.acr.values type'
					);
				}
				if (request.values.includes(oidc.acr)) {
					return false;
				}
				return true;
			},
			details: ({ oidc }: any) => ({ acr: oidc.claims.id_token.acr })
		},
		{
			reason: 'essential_acr',
			description: 'requested ACR could not be obtained',
			// The single-valued form of the requirement above, and the same rule applies to it.
			error: 'unmet_authentication_requirements',
			check: (ctx: any) => {
				const { oidc } = ctx;
				const request = oidc.claims?.id_token?.acr ?? {};
				if (!request?.essential || !request?.value) {
					return false;
				}
				if (request.value === oidc.acr) {
					return false;
				}
				return true;
			},
			details: ({ oidc }: any) => ({ acr: oidc.claims.id_token.acr })
		}
	];
}

export default () => new LoginPromt();
