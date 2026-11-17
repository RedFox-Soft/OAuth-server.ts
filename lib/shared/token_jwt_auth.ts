import { sl1 } from '../sl1/rules.ts';
import { InvalidClientAuth } from '../helpers/errors.js';
import * as JWT from '../helpers/jwt.js';
import { ReplayDetection } from 'lib/models/replay_detection.js';
import { clockTolerance } from 'lib/configs/liveTime.js';
import { issuerFor } from 'lib/configs/issuer.js';
import { routeNames } from 'lib/consts/param_list.js';
import {
	CLIENT_AUTHENTICATION_JWT_TYPE,
	RESERVED_JWT_TYPES
} from 'lib/consts/jwt_types.js';
import { assertJwtClientAuthClaimsAndHeader } from 'lib/addon/index.js';
import { ApplicationConfig as config } from 'lib/configs/application.js';
import { type OIDCContext } from 'lib/helpers/oidc_context.js';
import { type authParamsType } from 'lib/plugins/auth.js';

type Entries<T> = {
	[K in keyof T]: [K, T[K]];
}[keyof T][];
function entriesFromObject<T extends object>(object: T): Entries<T> {
	return Object.entries(object) as Entries<T>;
}

const payloadErrors = entriesFromObject({
	exp: 'expiration must be specified in the client_assertion JWT',
	jti: 'unique jti (JWT ID) must be provided in the client_assertion JWT',
	iss: 'iss (JWT issuer) must be provided in the client_assertion JWT',
	aud: 'aud (JWT audience) must be provided in the client_assertion JWT'
} as const);

function checkPayload(
	payload: Record<string, unknown>
): asserts payload is Record<string, unknown> & {
	exp: number;
	jti: string;
	iss: string;
	aud: string | string[];
} {
	for (const [claim, errorMessage] of payloadErrors) {
		if (!payload[claim]) {
			throw new InvalidClientAuth(errorMessage);
		}
	}
}

/*
 * The path of the endpoint receiving the assertion, which the lenient rule accepts as an audience (RFC 9126
 * §2, CIBA §7.1). A context the auth plugin builds carries the matched path, already bare of a bucket's
 * `/:bucket` prefix; one built directly carries a route *name* (oidc_context.ts), and CIBA's must stay the
 * name because three request-object and scope checks branch on it. Gluing a name onto the issuer gave
 * `<issuer>backchannel_authentication`, which is no URL of this server, and refused the real one.
 */
function endpointPath(route: string): string | undefined {
	if (route.startsWith('/')) return route;
	return Object.hasOwn(routeNames, route)
		? routeNames[route as keyof typeof routeNames]
		: undefined;
}

export async function tokenJwtAuth(
	oidc: OIDCContext<authParamsType>,
	keystore: JWT.KeySet,
	algorithms: readonly string[]
) {
	// Reached only for a request that presented one (token_auth's findClientId).
	const assertion = oidc.params.client_assertion;
	if (assertion === undefined) {
		throw new InvalidClientAuth('client_assertion must be provided');
	}
	/*
	 * The addressed bucket's identifiers, not the instance's: every bucket is its own authorization
	 * server, so `/acme/token` is identified by `<issuer>/acme` and `<issuer>/acme/token`. Built from the
	 * instance's alone, the check refused an assertion that named the bucket it was sent to and accepted
	 * one naming the root — a captured assertion for one issuer spendable at another.
	 */
	const issuer = issuerFor(oidc.bucket);
	const endpoint = endpointPath(oidc.route);
	const auds = new Set([
		issuer,
		`${issuer}${routeNames.token}`,
		...(endpoint === undefined ? [] : [`${issuer}${endpoint}`])
	]);
	const { header, payload } = JWT.decode(assertion);

	if (typeof header.alg !== 'string' || !algorithms.includes(header.alg)) {
		throw new InvalidClientAuth('alg mismatch');
	}
	/*
	 * A JWT typed for another job — a DPoP proof, an access token, an ID-JAG — is never a client credential
	 * (RFC 8725 §3.11). An untyped assertion is accepted: RFC 10070 §4.2 (new RFC 7523 §3.2) has clients
	 * SHOULD type theirs and calls refusing an untyped one NOT RECOMMENDED.
	 */
	const typ = JWT.normalisedType(header.typ);
	if (
		typ !== undefined &&
		typ !== CLIENT_AUTHENTICATION_JWT_TYPE &&
		RESERVED_JWT_TYPES.has(typ)
	) {
		throw new InvalidClientAuth(
			'client assertion typ must be client-authentication+jwt or absent'
		);
	}
	checkPayload(payload);

	if (payload.iss !== oidc.client.clientId) {
		throw new InvalidClientAuth('iss (JWT issuer) must be the client_id');
	}

	/*
	 * Two rules, and each departs from a text in force, so which one applies is isolated behind a named
	 * setting, as the constitution requires.
	 *
	 * The issuer-only rule, the default, is RFC 10070 §4 (RFC 7523 §3 item 3, client authentication) and §5
	 * (RFC 9126 §2): the issuer identifier "as its sole value", the token endpoint URL "MUST NOT be used",
	 * and "MUST reject any JWT that does not contain its issuer identifier as its sole audience value". It
	 * answers the audience-injection attack (CVE-2025-27370, CVE-2025-27371): a malicious server can make a
	 * client write an assertion audienced at this server's token endpoint and spend it here. RFC 10070 does
	 * not restrict the claim's type, so a one-element array is still one value. It departs from CIBA Core
	 * §7.1, which RFC 10070 does not update and which still says the OP "MUST accept" its Backchannel
	 * Authentication Endpoint URL and token endpoint URL: a CIBA client audiencing either is refused.
	 *
	 * The lenient rule, with the setting off, is the compatibility answer for clients that cannot yet
	 * change: it accepts the issuer, the token endpoint URL and the receiving endpoint's URL, as RFC 9126
	 * §2 did before RFC 10070 and CIBA §7.1 still does, and so departs from RFC 10070.
	 *
	 * FAPI 2.0 Security Profile §5.3.2.1 cl. 8 implies the issuer-only rule and §5.3.3.1 cl. 5 adds "as a
	 * string not as an item in an array", which the strict equality enforces: a one-element array is not
	 * `=== issuer`. IPSIE SL1 §3.2.1 asks the same — "its issuer identifier value … as a string" — so the
	 * profile switch selects this rule too.
	 */
	if (config['fapi.enabled'] || sl1()) {
		if (payload.aud !== issuer) {
			throw new InvalidClientAuth(
				'audience (aud) must equal the issuer identifier url'
			);
		}
	} else if (config['clientAuth.issuerOnlyAudience']) {
		if (JWT.soleAudience(payload.aud) !== issuer) {
			throw new InvalidClientAuth(
				'audience (aud) must be the issuer identifier as its sole value'
			);
		}
	} else if (Array.isArray(payload.aud)) {
		if (!payload.aud.some((aud) => auds.has(aud))) {
			throw new InvalidClientAuth(
				'list of audience (aud) must include the endpoint url, issuer identifier or token endpoint url'
			);
		}
	} else if (payload.aud && !auds.has(payload.aud)) {
		throw new InvalidClientAuth(
			'audience (aud) must equal the endpoint url, issuer identifier or token endpoint url'
		);
	}

	try {
		await JWT.verify(assertion, keystore, {
			clockTolerance
		});
	} catch (err) {
		const message = err instanceof Error ? err.message : String(err);
		throw new InvalidClientAuth(message);
	}

	await assertJwtClientAuthClaimsAndHeader(oidc.client, payload, header);

	const unique = await ReplayDetection.unique(
		payload.iss,
		payload.jti,
		payload.exp + clockTolerance
	);

	if (!unique) {
		throw new InvalidClientAuth(
			'client assertion tokens must only be used once'
		);
	}
}
