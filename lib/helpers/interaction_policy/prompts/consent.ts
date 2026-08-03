import { Prompt } from '../prompt.js';
import { canonicalKey, canonicalKeySet } from '../../rar_canonical.js';

const missingOIDCScope = Symbol();
const missingOIDCClaims = Symbol();
const missingResourceScopes = Symbol();
const missingRar = Symbol();

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
			/*
			 * One determination, used twice: it decides whether to interrupt and it *is* what the
			 * consent page shows. RFC 9396 §6.1 sanctions comparing against what was already granted —
			 * "an AS can use the same processing techniques as used in granting the request in the first
			 * place to determine if a resource owner needs to authorize the request" — so a repeat
			 * authorization for details already on the grant no longer re-prompts.
			 *
			 * No JSON.parse here: checkRar normalizes the parameter to an array before this runs.
			 */
			check: (ctx) => {
				const { oidc } = ctx;

				if (!oidc.params.authorization_details || oidc.result?.consent) {
					return false;
				}

				const granted = canonicalKeySet(oidc.grant?.payload.rar);
				const missing = (oidc.params.authorization_details as unknown[]).filter(
					(detail: unknown) => !granted.has(canonicalKey(detail))
				);

				if (!missing.length) {
					return false;
				}

				ctx.oidc[missingRar] = missing;
				return true;
			},
			details: ({ oidc }) => ({ rar: oidc[missingRar] })
		}
	];
}

export default () => new ConsentPromt();
