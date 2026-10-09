import type { OIDCContext } from 'lib/helpers/oidc_context.js';
import type { TokenParams } from 'lib/actions/token.js';
import {
	InvalidGrant,
	InvalidTarget,
	InvalidScope,
	InvalidRequest
} from '../../helpers/errors.js';
import { member } from '../../helpers/_/object.js';
import { configuration } from 'lib/configs/application.js';
import checkResource from '../../shared/check_resource.ts';
import { machineTokenPermitted } from '../../resources/registry.js';
import { namespaceOf } from '../../resources/namespace.js';
import { ClientCredentials } from 'lib/models/client_credentials.js';
import type { DPoPProof } from 'lib/helpers/validate_dpop.js';
import { SCIM_SCOPE } from '../../consts/scim.js';

export async function clientCredentials(
	oidc: OIDCContext<TokenParams>,
	dPoP: DPoPProof
) {
	const { client } = oidc;
	const { scopes: statics } = configuration;

	// Unreachable while the /token schema refuses the parameter: the seam RFC 9396 §7 support plugs
	// into (wiki/concepts/rich-authorization-requests.md), read as the unknown it would then be.
	if (member(oidc.params, 'authorization_details')) {
		throw new InvalidRequest(
			'authorization_details is unsupported for this grant_type'
		);
	}

	await checkResource(oidc);

	let scopes = [...new Set(oidc.params.scope?.split(' '))];

	/*
	 * A provisioning connection's client may hold one token only: `scim`, for its own bucket's SCIM resource
	 * (IPSIE AL SCIM §4.1 — the scope and nothing broader). Neither Entra nor Okta names a scope, so its
	 * absence means `scim`; any other scope is refused rather than silently dropped, so a misconfigured
	 * directory learns why. The resource itself was decided by getResourceServerInfo; its absence here means
	 * the bucket has no SCIM address to give.
	 */
	if (client.provisioningConnectionId) {
		const asked = scopes.filter(Boolean);
		const stray = asked.find((scope) => scope !== SCIM_SCOPE);
		if (stray) {
			throw new InvalidScope('requested scope is not allowed', stray);
		}
		scopes = [SCIM_SCOPE];
		if (Object.keys(oidc.resourceServers).length === 0) {
			throw new InvalidTarget(
				'the client is not permitted to access this resource'
			);
		}
	}

	if (client.scope) {
		const allowList = new Set(client.scope.split(' '));

		for (const scope of scopes.filter(Set.prototype.has.bind(statics))) {
			if (!allowList.has(scope)) {
				throw new InvalidScope('requested scope is not allowed', scope);
			}
		}
	}

	const token = new ClientCredentials({
		/* The address this request was made to — there is no earlier artifact to inherit from. */
		bucketId: oidc.bucket._id,
		client,
		scope: scopes.join(' ') || undefined
	});

	const resourceServers = Object.values(oidc.resourceServers);
	const resourceServer = resourceServers.at(0);
	if (resourceServer) {
		if (resourceServers.length !== 1) {
			throw new InvalidTarget(
				'only a single resource indicator value is supported for this grant type'
			);
		}
		const [indicator] = Object.keys(oidc.resourceServers);
		// This token acts for nobody, so no end user's consent stands behind it — only who the client is.
		if (
			!(await machineTokenPermitted(
				indicator,
				client.clientId,
				namespaceOf(oidc.bucket)
			))
		) {
			throw new InvalidTarget(
				'the client is not permitted to access this resource'
			);
		}
		token.resourceServer = resourceServer;
		token.payload.scope =
			scopes
				.filter(
					Set.prototype.has.bind(new Set(resourceServer.scope.split(' ')))
				)
				.join(' ') || undefined;
	}

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

	oidc.entity('ClientCredentials', token);
	const value = await token.save();

	return {
		access_token: value,
		expires_in: token.expiration,
		token_type: token.tokenType,
		scope: token.payload.scope || undefined
	};
}
