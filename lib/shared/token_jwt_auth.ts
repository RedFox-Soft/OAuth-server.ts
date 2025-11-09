import { InvalidClientAuth } from '../helpers/errors.js';
import * as JWT from '../helpers/jwt.js';
import { ReplayDetection } from 'lib/models/replay_detection.js';
import { clockTolerance } from 'lib/configs/liveTime.js';
import { ISSUER } from 'lib/configs/env.js';
import { routeNames } from 'lib/consts/param_list.js';
import { assertJwtClientAuthClaimsAndHeader } from 'lib/addon/index.js';
import { ApplicationConfig as config } from 'lib/configs/application.js';

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

export async function tokenJwtAuth(ctx, keystore, algorithms) {
	const auds = new Set([
		ISSUER,
		`${ISSUER}${routeNames.token}`,
		`${ISSUER}${ctx.oidc.route}`
	]);
	const { header, payload } = JWT.decode(ctx.oidc.params.client_assertion);

	if (!algorithms.includes(header.alg)) {
		throw new InvalidClientAuth('alg mismatch');
	}
	checkPayload(payload);

	if (payload.iss !== ctx.oidc.client.clientId) {
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
		await JWT.verify(ctx.oidc.params.client_assertion, keystore, {
			clockTolerance
		});
	} catch (err) {
		const message = err instanceof Error ? err.message : String(err);
		throw new InvalidClientAuth(message);
	}

	const isFapi = config['fapi.enabled'];
	if (isFapi) {
		if (payload.aud !== ISSUER) {
			throw new InvalidClientAuth(
				'audience (aud) must equal the issuer identifier url'
			);
		}
	}

	await assertJwtClientAuthClaimsAndHeader(ctx.oidc.client, payload, header);

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
