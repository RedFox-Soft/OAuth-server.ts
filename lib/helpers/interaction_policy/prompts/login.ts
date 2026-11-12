import { configuration } from '../../../configs/application.ts';
import { satisfiesAcr, sl1, sl1Exempt } from '../../../sl1/rules.ts';
import {
	codeRequiredAndMissing,
	proxyAsksForCode,
	REQUIRE_CODE_DESCRIPTION
} from '../../../client_policy/require_code.ts';
import { API_CODE_DESCRIPTION } from '../../../resources/sign_in_requirement.ts';
import * as errors from '../../errors.ts';
import { pairwiseIdentifier } from '../../../addon/index.js';
import { Prompt, type CheckPartial } from '../prompt.js';
import type { OIDCContext } from '../../oidc_context.ts';
import { claimRequest } from '../../claim_request.ts';
import type { PipelineParams } from '../../../consts/param_list.ts';
import {
	CREATE_PROMPT,
	CREATE_PROMPT_REASON
} from '../../../consts/prompt_create.ts';

/* The first requested API with a sign-in requirement this check is about, and its identifier. */
function requiringApi(
	oidc: OIDCContext<PipelineParams>,
	about: (signIn: { code: boolean; maxAgeSeconds?: number }) => boolean
): string | undefined {
	for (const [identifier, server] of Object.entries(oidc.resourceServers)) {
		if (server.signIn && about(server.signIn)) return identifier;
	}
	return undefined;
}

/* The shortest sign-in age the requested APIs allow, in seconds, with the API that sets it. */
function strictestApiMaxAge(
	oidc: OIDCContext<PipelineParams>
): { maxAge: number; api: string } | undefined {
	let found: { maxAge: number; api: string } | undefined;
	for (const [identifier, server] of Object.entries(oidc.resourceServers)) {
		const maxAge = server.signIn?.maxAgeSeconds;
		if (
			maxAge !== undefined &&
			(found === undefined || maxAge < found.maxAge)
		) {
			found = { maxAge, api: identifier };
		}
	}
	return found;
}

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
		/*
		 * `prompt=create` asks for the account-creation page even when somebody is already signed in, the
		 * way `prompt=login` asks for the sign-in page. It is answered by the interaction that follows —
		 * the new account signs in at the end of it — so once a sign-in result exists it is satisfied.
		 */
		{
			reason: CREATE_PROMPT_REASON,
			description: 'account creation was requested',
			error: 'login_required',
			check: (oidc) => oidc.prompts.has(CREATE_PROMPT) && !oidc.result?.login
		},
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
			reason: 'resource_max_age',
			description: 'End-User authentication could not be obtained',
			/*
			 * A requested API asks its people to sign in again every so often (specs/130 research R4), read from the
			 * declaration, never from the request: the client may not know to ask. Its own reason rather than a written
			 * `max_age`, which would reach the ID token and the proxy's notice; the details carry the age so a provider
			 * sign-in is asked for a fresh one too.
			 */
			check: (oidc) => {
				const strictest = strictestApiMaxAge(oidc);
				if (strictest === undefined) return false;
				if (!oidc.session.payload.accountId) return true;
				return (
					oidc.session.past(strictest.maxAge) &&
					(!oidc.result || !oidc.result.login)
				);
			},
			details: (oidc) => {
				const strictest = strictestApiMaxAge(oidc);
				return strictest === undefined
					? {}
					: { apiMaxAge: strictest.maxAge, api: strictest.api };
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
				const hasValue = 'value' in request;
				const hasValues = 'values' in request;
				if (!hasValue && !hasValues) {
					return false;
				}
				/*
				 * OIDC Core §5.5.1 processes `values` "equivalently to a value request", so a subject named
				 * only among `values` binds the response to that end user too. Reading `value` alone
				 * answered such a request with whoever was signed in, which §3.1.2.2 forbids. A `values`
				 * that is not a list is refused rather than ignored: ignoring it would drop the constraint.
				 */
				if (hasValues && !Array.isArray(request.values)) {
					throw new errors.InvalidRequest(
						'invalid claims.id_token.sub.values type'
					);
				}
				let sub = oidc.session.payload.accountId;
				if (sub === undefined) {
					return true;
				}
				if (oidc.client.subjectType === 'pairwise') {
					sub = await pairwiseIdentifier(sub, oidc.client);
				}
				if (hasValue && request.value !== sub) {
					return true;
				}
				if (Array.isArray(request.values) && !request.values.includes(sub)) {
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
				if (!request.essential || !request.values) {
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
				if (!request.essential || !request.value) {
					return false;
				}
				if (request.value === oidc.acr) {
					return false;
				}
				return true;
			},
			details: (oidc) => ({ acr: oidc.claims.id_token?.acr })
		},
		{
			reason: 'sl1_acr_values',
			description: 'requested ACR could not be obtained',
			/*
			 * IPSIE SL1 §3.2.1: with `acr_values` in the request the provider MUST "either authenticate the user in a
			 * manner that satisfies one of the requested Authentication Context Class values, or return an error".
			 * Departs from OIDC Core §3.1.2.1, where `acr_values` is voluntary, under the profile switch; the essential
			 * checks above are untouched. A client's `default_acr_values` arrive as `acr_values` and bind the same way.
			 */
			error: 'unmet_authentication_requirements',
			check: (oidc) => {
				const values = oidc.params.acr_values;
				if (!sl1() || sl1Exempt(oidc.client) || typeof values !== 'string') {
					return false;
				}
				return !satisfiesAcr(values.split(' '), oidc.acr);
			},
			details: (oidc) => ({ acr_values: oidc.params.acr_values })
		},
		{
			reason: 'second_factor',
			description: REQUIRE_CODE_DESCRIPTION,
			/*
			 * The application's own requirement (specs/127), read from the client, never from the request: a parameter can
			 * be removed by whoever opens the link. Met only by a sign-in in which the person typed a code; a sign-in that
			 * already did, however long ago, is not asked again. A path behind the proxy asks the same through its own client's
			 * request (specs/128), and its `max_age` says how recent the sign-in with a code must be.
			 */
			error: 'unmet_authentication_requirements',
			check: (oidc) =>
				codeRequiredAndMissing(oidc.client, oidc.acr) ||
				proxyAsksForCode(oidc.client, oidc.params.acr_values, oidc.acr),
			details: () => ({ requireCode: true })
		},
		{
			reason: 'resource_code',
			description: API_CODE_DESCRIPTION,
			/*
			 * A requested API requires a sign-in with a code (specs/130 research R4): the same page and the same set-up as
			 * an application's requirement, through CODE_REASONS, with the API named instead of the app.
			 */
			error: 'unmet_authentication_requirements',
			check: (oidc) =>
				requiringApi(
					oidc,
					(signIn) =>
						signIn.code && oidc.acr !== configuration.acrMap.multi_factor
				) !== undefined,
			details: (oidc) => ({
				requireCode: true,
				api: requiringApi(oidc, (signIn) => signIn.code)
			})
		}
	];
}

export default () => new LoginPromt();
