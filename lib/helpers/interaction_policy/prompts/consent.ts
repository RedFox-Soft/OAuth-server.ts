import { Prompt, type CheckPartial } from '../prompt.js';
import { canonicalKey, canonicalKeySet } from '../../rar_canonical.js';

/*
 * What a check found missing, kept for its `details` to report. Beside the request context rather than
 * written onto it, so the context holds only what it declares.
 */
const missingOIDCScope = new WeakMap<object, unknown>();
const missingOIDCClaims = new WeakMap<object, unknown>();
const missingResourceScopes = new WeakMap<object, unknown>();
const missingRar = new WeakMap<object, unknown>();

class ConsentPromt extends Prompt {
	name = 'consent';
	requestable = true;
	defaultError = 'consent_required';
	checks: CheckPartial[] = [
		{
			reason: 'native_client_prompt',
			description: 'native clients require End-User interaction',
			error: 'interaction_required',
			check: (oidc) => {
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
			check: (oidc) => {
				/*
				 * An absent grant means nothing has been granted, so everything requested is missing and
				 * the end user is asked — which is a refusal, and correct. It used to be a fault: reaching
				 * inside an unset grant threw, and the request that got there was one whose account had
				 * not resolved.
				 *
				 * That path is closed upstream now — a request with no account is sent to sign in before
				 * any consent check runs — so this is defence rather than a live branch. It stays because
				 * the failure it prevents is indistinguishable, from outside, from the server being broken.
				 */
				const encounteredScopes = new Set(
					(oidc.entities.Grant?.getOIDCScopeEncountered() ?? '').split(' ')
				);

				let missing: string[] | undefined;
				for (const scope of oidc.requestParamOIDCScopes) {
					if (!encounteredScopes.has(scope)) {
						missing ||= [];
						missing.push(scope);
					}
				}

				if (missing?.length) {
					missingOIDCScope.set(oidc, missing);
					return true;
				}

				return false;
			},
			details: (oidc) => ({ missingOIDCScope: missingOIDCScope.get(oidc) })
		},
		{
			reason: 'op_claims_missing',
			description: 'requested claims not granted',
			check: (oidc) => {
				const encounteredClaims = new Set(
					oidc.entities.Grant?.getOIDCClaimsEncountered() ?? []
				);

				let missing: string[] | undefined;
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
					missingOIDCClaims.set(oidc, missing);
					return true;
				}

				return false;
			},
			details: (oidc) => ({ missingOIDCClaims: missingOIDCClaims.get(oidc) })
		},
		{
			reason: 'rs_scopes_missing',
			description: 'requested scopes not granted',
			check: (oidc) => {
				let missing: Record<string, string[]> | undefined;

				for (const [indicator, resourceServer] of Object.entries(
					oidc.resourceServers
				)) {
					const encounteredScopes = new Set(
						(
							oidc.entities.Grant?.getResourceScopeEncountered(indicator) ?? ''
						).split(' ')
					);
					const requestedScopes = oidc.requestParamScopes;
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
					missingResourceScopes.set(oidc, missing);
					return true;
				}

				return false;
			},
			details: (oidc) => ({
				missingResourceScopes: missingResourceScopes.get(oidc)
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
			check: (oidc) => {
				if (!oidc.params.authorization_details || oidc.result?.consent) {
					return false;
				}

				const granted = canonicalKeySet(oidc.entities.Grant?.payload.rar);
				const missing = (oidc.params.authorization_details as unknown[]).filter(
					(detail: unknown) => !granted.has(canonicalKey(detail))
				);

				if (!missing.length) {
					return false;
				}

				missingRar.set(oidc, missing);
				return true;
			},
			details: (oidc) => ({ rar: missingRar.get(oidc) })
		}
	];
}

export default () => new ConsentPromt();
