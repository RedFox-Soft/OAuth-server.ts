import type { OIDCContext } from 'lib/helpers/oidc_context.js';
import type { TokenParams } from 'lib/actions/token.js';
import {
	InvalidGrant,
	InvalidRequest,
	InvalidScope,
	InvalidTarget,
	UnauthorizedClient
} from '../../helpers/errors.js';
import { findAccount } from '../../addon/account.js';
import { JWT_DPOP_GRANT } from '../../consts/assertion_grants.js';
import ResourceServer from '../../helpers/resource_server.js';
import type { DPoPProof } from 'lib/helpers/validate_dpop.js';
import { isMcpResource } from '../../mcp/resource_server.js';
import { AccessToken } from '../../models/access_token.js';
import { isScimResourceOf } from '../../provisioning/token_policy.js';
import { namespaceOf } from '../../resources/namespace.js';
import { resolveDeclaredResource } from '../../resources/registry.js';
import { personNamedBy } from '../../assertions/person.js';
import { noteProviderAssertionUse } from '../../assertions/usage.js';
import {
	verifyAssertion,
	type VerifiedAssertion
} from '../../assertions/verify.js';

/*
 * The JWT bearer authorization grant (RFC 7523 §2.1 as updated by draft-ietf-oauth-rfc7523bis), and its
 * DPoP-bound form `jwt-dpop` — the receiving side of MCP enterprise-managed authorization (specs/108). An
 * agent presents an assertion a provider the project trusts signed about a person, and gets an access token
 * for one of the project's APIs: no browser, no consent (ID-JAG §4.1), no refresh token (ID-JAG §4.4.3).
 */

const GTY = 'jwt_bearer';

function list(value: string | string[] | undefined): string[] {
	if (value === undefined) return [];
	return Array.isArray(value) ? value : [value];
}

/*
 * The one API the token is for (MCP enterprise-managed authorization §5.1: audience-restricted to the MCP
 * server the ID-JAG names). The ID-JAG's `resource` may be one URI or several (ID-JAG §3.1); the request's
 * may pick one of them, or name one where the ID-JAG names none. A token is never minted without an audience.
 */
function chosenResource(
	claimed: unknown,
	requested: string | string[] | undefined
): string {
	let named: string[];
	if (claimed === undefined) named = [];
	else if (typeof claimed === 'string') named = [claimed];
	else if (
		Array.isArray(claimed) &&
		claimed.every((value) => typeof value === 'string')
	) {
		named = claimed;
	} else {
		throw new InvalidGrant('assertion:resource');
	}

	const asked = list(requested);
	if (asked.length > 1) {
		throw new InvalidTarget(
			'only a single resource indicator value is supported for this grant type'
		);
	}
	if (asked.length === 1) {
		const [one] = asked;
		if (named.length > 0 && !named.includes(one)) {
			throw new InvalidTarget('the requested resource is not granted');
		}
		return one;
	}
	if (named.length === 1) return named[0];
	throw new InvalidTarget(
		'a single resource must be named by the assertion or the request'
	);
}

/*
 * The most the assertion grants for this API. An ID-JAG's own `scope`, absent when it named none (ID-JAG
 * §3.1); a plain assertion names no client and no grant, so what the provider's trust allows the API — the
 * "scope originally granted" RFC 7521 §4.1 bounds the token by — and an API the trust does not name is not
 * reachable at all. Answered as a set so that "named none" and "named nothing usable" stay different things.
 */
function ceilingOf(
	assertion: VerifiedAssertion,
	identifier: string
): Set<string> | undefined {
	if (assertion.profile === 'plain') {
		const trusted = assertion.provider.plainAssertions?.resources.find(
			(resource) => resource.identifier === identifier
		);
		if (!trusted) {
			throw new InvalidTarget(
				'the resource is not allowed for these assertions'
			);
		}
		return new Set(trusted.scopes);
	}
	const { scope } = assertion.claims;
	return typeof scope === 'string'
		? new Set(scope.split(' ').filter(Boolean))
		: undefined;
}

export async function jwtBearer(
	oidc: OIDCContext<TokenParams>,
	dPoP: DPoPProof
) {
	const { client } = oidc;

	/*
	 * Deliberately stricter than the MCP profile, which lets a metadata-document client present an ID-JAG
	 * without authenticating (MCP enterprise-managed authorization §5): ID-JAG §9.1 confines the profile to
	 * confidential clients, and the `client_id` an ID-JAG binds is a value anyone can claim when nobody is
	 * authenticated. The confidential-only list is not enforced at /token, so each grant checks.
	 */
	if (client.tokenEndpointAuthMethod === 'none') {
		throw new UnauthorizedClient(
			'the JWT bearer grant requires a client that authenticates'
		);
	}

	const { assertion } = oidc.params;
	if (!assertion) {
		throw new InvalidRequest('missing required parameter assertion');
	}

	const verified = await verifyAssertion(
		oidc.bucket,
		assertion,
		client.clientId
	);

	/*
	 * ID-JAG §9.8.1.2: an assertion bound to a key is redeemable only with a proof by that key, and `jwt-dpop`
	 * exists only for bound assertions (draft-parecki-oauth-jwt-dpop-grant §4). A proof sent with an unbound
	 * assertion still binds the token (ID-JAG §9.8.1.2.3), below.
	 */
	const cnf: unknown = verified.claims.cnf;
	const jkt =
		typeof cnf === 'object' && cnf !== null && 'jkt' in cnf
			? cnf.jkt
			: undefined;
	if (jkt === undefined && oidc.params.grant_type === JWT_DPOP_GRANT) {
		throw new InvalidGrant('assertion:unbound');
	}
	if (jkt !== undefined && (!dPoP || dPoP.thumbprint !== jkt)) {
		throw new InvalidGrant('assertion:proof');
	}

	const identifier = chosenResource(
		verified.claims.resource,
		oidc.params.resource
	);
	/*
	 * This instance's administrative MCP endpoint and a project's SCIM endpoint are built in, never declared,
	 * so the lookup below could not find them anyway; refused by name so that no future arm of resource
	 * resolution can make administrative or provisioning access reachable by assertion.
	 */
	if (isMcpResource(identifier) || isScimResourceOf(oidc.bucket, identifier)) {
		throw new InvalidTarget();
	}
	const declared = await resolveDeclaredResource(
		identifier,
		namespaceOf(oidc.bucket)
	);
	if (!declared) throw new InvalidTarget();
	const resourceServer = new ResourceServer(identifier, declared);

	const offered = [...resourceServer.scopes].filter(Boolean);
	const ceiling = ceilingOf(verified, identifier);
	const asked = oidc.params.scope?.split(' ').filter(Boolean);
	/* RFC 7521 §4.1: the issued scope is at most what was granted out of band; named nowhere, nothing was. */
	const granted =
		ceiling === undefined && asked === undefined
			? []
			: offered.filter(
					(scope) =>
						(ceiling === undefined || ceiling.has(scope)) &&
						(asked === undefined || asked.includes(scope))
				);
	if (offered.length > 0 && granted.length === 0) {
		throw new InvalidScope(
			'no requested scope is granted for this resource',
			oidc.params.scope
		);
	}

	const person = await personNamedBy(verified);
	/*
	 * Read back through findAccount, which every grant uses: it applies `canSignIn` and the scheduled-deletion
	 * rule, and it is what the activity recorder reads. The population it resolves must be the project the
	 * trusted provider belongs to, or the person found is somebody else's.
	 */
	oidc.params.resource = identifier;
	const account = await findAccount(oidc, person._id);
	if (!account || account.bucketId !== verified.bucket._id) {
		throw new InvalidGrant('person:population');
	}
	oidc.entity('Account', account);

	const token = new AccessToken({
		/* The address this request was made to — there is no earlier artifact to inherit from. */
		bucketId: oidc.bucket._id,
		accountId: account.accountId,
		client,
		gty: GTY,
		scope: granted.join(' ') || undefined
	});
	token.resourceServer = resourceServer;

	if (client.tlsClientCertificateBoundAccessTokens) {
		const cert = oidc.getClientCertificate();
		if (!cert) {
			throw new InvalidGrant('mutual TLS client certificate not provided');
		}
		token.setThumbprint('x5t', cert);
	}
	if (dPoP) {
		token.setThumbprint('jkt', dPoP.thumbprint);
	} else if (client.dpopBoundAccessTokens) {
		throw new InvalidGrant('DPoP proof JWT not provided');
	}

	oidc.entity('AccessToken', token);
	const value = await token.save();
	noteProviderAssertionUse(
		verified.bucket._id,
		verified.provider.id,
		client.clientId
	);

	return {
		access_token: value,
		expires_in: token.expiration,
		token_type: token.tokenType,
		scope: token.payload.scope || undefined,
		/*
		 * ID-JAG §4.4.1 says the response "MUST include the granted resource", citing RFC 8707 §2 for the
		 * format — which defines no response member. Sent under the request parameter's name; a client that
		 * does not expect it ignores it (RFC 6749 §5.1).
		 */
		resource: identifier
	};
}
