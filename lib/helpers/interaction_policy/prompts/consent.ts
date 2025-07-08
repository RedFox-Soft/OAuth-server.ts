import { Prompt } from '../prompt.js';

const missingOIDCScope = Symbol();
const missingOIDCClaims = Symbol();
const missingResourceScopes = Symbol();

class ConsentPromt extends Prompt {
	name = 'consent';
	requestable = true;
	defaultError = 'consent_required';
	checks = [
		{
			reason: 'native_client_prompt',
			description: 'native clients require End-User interaction',
			error: 'interaction_required',
			check: (ctx) => {
				const { oidc } = ctx;
				if (
					oidc.client.applicationType === 'native' &&
					oidc.params.response_type !== 'none' &&
					!oidc.result?.consent
				) {
					return true;
				}
				return false;
			}
		},
		{
			reason: 'op_scopes_missing',
			description: 'requested scopes not granted',
			check: (ctx) => {
				const { oidc } = ctx;
				const encounteredScopes = new Set(
					oidc.grant.getOIDCScopeEncountered().split(' ')
				);

				let missing;
				for (const scope of oidc.requestParamOIDCScopes) {
					if (!encounteredScopes.has(scope)) {
						missing ||= [];
						missing.push(scope);
					}
				}

				if (missing?.length) {
					ctx.oidc[missingOIDCScope] = missing;
					return true;
				}

				return false;
			},
			details: ({ oidc }) => ({ missingOIDCScope: oidc[missingOIDCScope] })
		},
		{
			reason: 'op_claims_missing',
			description: 'requested claims not granted',
			check: (ctx) => {
				const { oidc } = ctx;
				const encounteredClaims = new Set(
					oidc.grant.getOIDCClaimsEncountered()
				);

				let missing;
				for (const claim of oidc.requestParamClaims) {
					if (
						!encounteredClaims.has(claim) &&
						!['sub', 'sid', 'auth_time', 'acr', 'amr', 'iss'].includes(claim)
					) {
						missing ||= [];
						missing.push(claim);
					}
				}

				if (missing?.length) {
					ctx.oidc[missingOIDCClaims] = missing;
					return true;
				}

				return false;
			},
			details: ({ oidc }) => ({ missingOIDCClaims: oidc[missingOIDCClaims] })
		},
		{
			reason: 'rs_scopes_missing',
			description: 'requested scopes not granted',
			check: (ctx) => {
				const { oidc } = ctx;

				let missing;

				for (const [indicator, resourceServer] of Object.entries(
					ctx.oidc.resourceServers
				)) {
					const encounteredScopes = new Set(
						oidc.grant.getResourceScopeEncountered(indicator).split(' ')
					);
					const requestedScopes = ctx.oidc.requestParamScopes;
					const availableScopes = resourceServer.scopes;

					for (const scope of requestedScopes) {
						if (availableScopes.has(scope) && !encounteredScopes.has(scope)) {
							missing ||= {};
							missing[indicator] ||= [];
							missing[indicator].push(scope);
						}
					}
				}

				if (missing && Object.keys(missing).length) {
					ctx.oidc[missingResourceScopes] = missing;
					return true;
				}

				return false;
			},
			details: ({ oidc }) => ({
				missingResourceScopes: oidc[missingResourceScopes]
			})
		},
		{
			reason: 'rar_prompt',
			description: 'authorization_details were requested',
			check: (ctx) => {
				const { oidc } = ctx;

				if (oidc.params.authorization_details && !oidc.result?.consent) {
					return true;
				}

				return false;
			},
			details: ({ oidc }) => ({
				rar: JSON.parse(oidc.params.authorization_details)
			})
		}
	];
}

export default () => new ConsentPromt();
