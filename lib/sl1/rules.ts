import { ApplicationConfig, configuration } from '../configs/application.ts';
import { ADMIN_BUCKET_ID } from '../admin/consts.ts';
import { SL1_SIGNING_ALGORITHMS, type Sl1Rule } from '../consts/sl1.ts';
import type { Client, ClientRecord } from '../models/client/types.ts';

/*
 * The IPSIE SL1 profile (`ipsieSl1.enabled`): one switch, read where each rule is enforced, so a grep for `sl1()` finds
 * every place the profile changes what the server does. wiki/concepts/ipsie-sl1-profile.md lists them with the section
 * of the profile each one answers.
 */
export function sl1(): boolean {
	return ApplicationConfig['ipsieSl1.enabled'];
}

type ClientProvenance = {
	readonly bucketId?: string;
	readonly accountPageBucketId?: string;
	readonly provisioningConnectionId?: string;
};

/*
 * The clients the profile's client rules do not reach. The administrators' project holds the console and the
 * administrators' MCP client — the server's own, whose loopback `http` redirect an agent on the operator's machine
 * needs. A project's account page asks `/auth` with `response_type=none` and never receives a token. A SCIM
 * connection's client reaches only the SCIM endpoint, which IPSIE's SCIM profile governs and SL1 does not. The
 * profile's default signing algorithm still applies to all three.
 */
export function sl1Exempt(client: ClientProvenance): boolean {
	return (
		client.bucketId === ADMIN_BUCKET_ID ||
		client.accountPageBucketId !== undefined ||
		client.provisioningConnectionId !== undefined
	);
}

export type Sl1Violation = {
	rule: Sl1Rule;
	attribute: string;
	value?: string;
	cites: 'SL1 §3.2.1' | 'CR §3.3';
};

/* Each signed-response attribute: its name on a resolved client, and its wire name, which a record may also use. */
export const SIGNED_RESPONSES = [
	['idTokenSignedResponseAlg', 'id_token_signed_response_alg'],
	['userinfoSignedResponseAlg', 'userinfo_signed_response_alg'],
	['introspectionSignedResponseAlg', 'introspection_signed_response_alg'],
	['authorizationSignedResponseAlg', 'authorization_signed_response_alg']
] as const;

/* The signed responses whose default is RS256, and so the ones the profile's PS256 default replaces. */
export const DEFAULTED: ReadonlySet<string> = new Set([
	'id_token_signed_response_alg',
	'introspection_signed_response_alg',
	'authorization_signed_response_alg'
]);

const OTHER_ALGORITHMS = [
	['requestObject.signingAlg', 'request_object_signing_alg'],
	[
		'requestObject.backChannelSigningAlg',
		'backchannel_authentication_request_signing_alg'
	],
	['tokenEndpointAuthSigningAlg', 'token_endpoint_auth_signing_alg']
] as const;

/*
 * What in a client the profile refuses, and the PS256 default it would be given. Pure, and silent about whether the
 * profile is on, so readiness can ask while it is off. `record` is the stored registration: only it can say that an
 * algorithm was never registered, since a resolved client carries the default in its place.
 */
export function sl1ClientViolations(
	client: Client,
	record?: ClientRecord
): Sl1Violation[] {
	const found: Sl1Violation[] = [];
	const uris: [string, readonly string[] | undefined][] = [
		['redirect_uris', client.redirectUris],
		['post_logout_redirect_uris', client.postLogoutRedirectUris]
	];
	for (const [attribute, list] of uris) {
		for (const value of list ?? []) {
			if (URL.parse(value)?.protocol === 'http:') {
				found.push({
					rule: 'http_redirect_uri',
					attribute,
					value,
					cites: 'SL1 §3.2.1'
				});
			}
		}
	}
	if (client.responseTypes.includes('none')) {
		found.push({
			rule: 'response_type_none',
			attribute: 'response_types',
			value: 'none',
			cites: 'SL1 §3.2.1'
		});
	}
	if (client.tlsClientCertificateBoundAccessTokens) {
		found.push({
			rule: 'certificate_bound_tokens',
			attribute: 'tls_client_certificate_bound_access_tokens',
			cites: 'SL1 §3.2.1'
		});
	}
	for (const [name, attribute] of [...SIGNED_RESPONSES, ...OTHER_ALGORITHMS]) {
		const value = client[name];
		// RS256 where RS256 is the default is the default a save wrote, served PS256 under the profile (schema.ts).
		if (value === 'RS256' && DEFAULTED.has(attribute)) continue;
		if (typeof value === 'string' && !SL1_SIGNING_ALGORITHMS.has(value)) {
			found.push({
				rule: 'signing_algorithm',
				attribute,
				value,
				cites: 'CR §3.3'
			});
		}
	}
	if (client.tokenEndpointAuthMethod === 'client_secret_jwt') {
		found.push({
			rule: 'client_secret_jwt',
			attribute: 'token_endpoint_auth_method',
			value: 'client_secret_jwt',
			cites: 'CR §3.3'
		});
	}
	if (record) {
		for (const [name, attribute] of SIGNED_RESPONSES) {
			const stored = record[attribute] ?? record[name];
			if (
				client[name] !== undefined &&
				DEFAULTED.has(attribute) &&
				(stored === undefined || stored === 'RS256')
			) {
				found.push({ rule: 'default_algorithm', attribute, cites: 'CR §3.3' });
			}
		}
	}
	return found;
}

/*
 * An algorithm list as the profile lets it be offered or accepted: unchanged while the profile is off, narrowed to
 * PS256, ES256 and EdDSA while it is on (IPSIE Common Requirements §3.3). For what is advertised and what a request is
 * checked against; the schema a stored client is validated with keeps the full lists, so a client the profile refuses
 * still validates and is refused by name (sl1ClientViolations).
 */
export function sl1Algorithms<T extends string>(list: readonly T[]): T[] {
	return sl1()
		? list.filter((alg) => SL1_SIGNING_ALGORITHMS.has(alg))
		: [...list];
}

/*
 * Whether a sign-in that reported `actual` satisfies a request naming any of `requested` (IPSIE SL1 §3.2.1: "authenticate
 * the user in a manner that satisfies one of the requested Authentication Context Class values"). A multi-factor sign-in
 * here is the password plus a second factor, so it satisfies a request for the password class too; Keycloak's levels
 * and Okta's `urn:okta:loa:*` order classes the same way. A federated sign-in satisfies only the federated class, and a
 * value this server does not define is never satisfied.
 */
export function satisfiesAcr(
	requested: readonly string[],
	actual: string | undefined
): boolean {
	if (actual === undefined) return false;
	const { acrMap } = configuration;
	const satisfied = new Set([actual]);
	if (actual === acrMap.multi_factor) satisfied.add(acrMap.password);
	return requested.some((value) => satisfied.has(value));
}
