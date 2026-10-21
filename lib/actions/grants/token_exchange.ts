import type { OIDCContext } from 'lib/helpers/oidc_context.js';
import type { TokenParams } from 'lib/actions/token.js';
import { InvalidRequest, UnauthorizedClient } from '../../helpers/errors.js';
import { ID_JAG_TOKEN_TYPE } from '../../consts/assertion_grants.js';
import type { DPoPProof } from 'lib/helpers/validate_dpop.js';
import { issueIdJag } from '../../assertions/id_jag.js';
import { vouchingFor } from '../../assertions/policy.js';
import { subjectOf } from '../../assertions/subject_token.js';
import { noteOutsideServerUse } from '../../assertions/usage.js';

/*
 * OAuth 2.0 Token Exchange (RFC 8693), as the ID-JAG profile uses it (ID-JAG §4.3; specs/108): an application
 * a project allows on an outside authorization server exchanges a person's ID token or refresh token for an
 * Identity Assertion JWT Authorization Grant that server honours. Only that profile is implemented; general
 * exchange of access tokens for delegation or impersonation is not.
 *
 * The person's activity is not counted here: no token for this project's resources is issued, so no Account
 * entity is set on the context, and the grant event carries none.
 */
export async function tokenExchange(
	oidc: OIDCContext<TokenParams>,
	dPoP: DPoPProof
) {
	const { client, params } = oidc;

	/*
	 * ID-JAG §5 and §9.1: confidential clients only, so that the IdP cannot be made to vouch for whichever
	 * client merely names itself. The confidential-only list is not enforced at /token, so each grant checks.
	 */
	if (client.tokenEndpointAuthMethod === 'none') {
		throw new UnauthorizedClient(
			'token exchange requires a client that authenticates'
		);
	}

	/* ID-JAG §4.3 and §9.7 define no processing for an actor, and RFC 8693 §2.1 requires one to be validated. */
	if (
		params.actor_token !== undefined ||
		params.actor_token_type !== undefined
	) {
		throw new InvalidRequest('actor_token is not supported');
	}
	if (params.requested_token_type !== ID_JAG_TOKEN_TYPE) {
		throw new InvalidRequest(
			`requested_token_type must be ${ID_JAG_TOKEN_TYPE}`
		);
	}

	const subject = await subjectOf(oidc, dPoP);
	const vouching = await vouchingFor({
		bucketId: oidc.bucket._id,
		audience: params.audience,
		clientId: client.clientId,
		accountId: subject.account.accountId,
		resource: params.resource,
		scope: params.scope
	});

	const { value, expiresIn } = await issueIdJag({
		bucket: oidc.bucket,
		vouching,
		account: subject.account,
		subject,
		jkt: dPoP?.thumbprint
	});
	noteOutsideServerUse(vouching.connection._id, client.clientId);

	const asked = params.scope?.split(' ').filter(Boolean);
	const narrowed =
		asked === undefined ||
		asked.length !== vouching.scopes.length ||
		asked.some((scope) => !vouching.scopes.includes(scope));
	return {
		issued_token_type: ID_JAG_TOKEN_TYPE,
		access_token: value,
		/* RFC 8693 §2.2.1: the issued token is not an access token, so no token type applies. */
		token_type: 'N_A',
		expires_in: expiresIn,
		/* ID-JAG §4.3.4: REQUIRED when the granted scope differs from the requested one. */
		scope:
			narrowed && vouching.scopes.length ? vouching.scopes.join(' ') : undefined
	};
}
