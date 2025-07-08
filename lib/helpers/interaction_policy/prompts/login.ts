import * as errors from '../../errors.ts';
import instance from '../../weak_cache.ts';
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
			check: (ctx: any) => {
				const { oidc } = ctx;
				if (oidc.session.accountId) {
					return false;
				}
				return true;
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
				if (!oidc.session.accountId) {
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
				let sub = oidc.session.accountId;
				if (sub === undefined) {
					return true;
				}
				if (oidc.client.subjectType === 'pairwise') {
					sub = await instance(oidc.provider).configuration.pairwiseIdentifier(
						sub,
						oidc.client
					);
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
				let sub = oidc.session.accountId;
				if (sub === undefined) {
					return true;
				}
				if (oidc.client.subjectType === 'pairwise') {
					sub = await instance(oidc.provider).configuration.pairwiseIdentifier(
						sub,
						oidc.client
					);
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
