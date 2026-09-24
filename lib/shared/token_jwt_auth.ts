import { InvalidClientAuth } from '../helpers/errors.js';
import * as JWT from '../helpers/jwt.js';
import { ReplayDetection } from 'lib/models/replay_detection.js';
import { clockTolerance } from 'lib/configs/liveTime.js';
import { ISSUER } from 'lib/configs/env.js';
import { routeNames } from 'lib/consts/param_list.js';
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
	const auds = new Set([
		ISSUER,
		`${ISSUER}${routeNames.token}`,
		`${ISSUER}${oidc.route}`
	]);
	const { header, payload } = JWT.decode(assertion);

	if (typeof header.alg !== 'string' || !algorithms.includes(header.alg)) {
		throw new InvalidClientAuth('alg mismatch');
	}
	checkPayload(payload);

	if (payload.iss !== oidc.client.clientId) {
		throw new InvalidClientAuth('iss (JWT issuer) must be the client_id');
	}
	if (Array.isArray(payload.aud)) {
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

	/*
	 * A deliberate departure from RFC 9126 §2.1, isolated behind a named flag as the constitution
	 * requires. That section says an authorization server "MUST accept its issuer identifier, token
	 * endpoint URL, or pushed authorization request endpoint URL as values that identify it as an
	 * intended audience" — which is what the check above implements, and narrowing it by default would
	 * make this server non-conforming.
	 *
	 * FAPI 2.0 Security Profile §5.3.2.1 cl. 8 requires the opposite for deployments that opt into the
	 * profile: the server "shall only accept its issuer identifier value (as defined in RFC 8414) as a
	 * string in the `aud` claim received in client authentication assertions". §5.3.3.1 cl. 5 adds that
	 * it is sent "as a string not as an item in an array", which the strict equality below enforces
	 * without a separate check — a one-element array is not `=== ISSUER`.
	 */
	const isFapi = config['fapi.enabled'];
	if (isFapi) {
		if (payload.aud !== ISSUER) {
			throw new InvalidClientAuth(
				'audience (aud) must equal the issuer identifier url'
			);
		}
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
