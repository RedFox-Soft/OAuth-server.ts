import { SignJWT, importPKCS8 } from 'jose';

/*
 * The credential Apple requires, signed from the key an administrator stored.
 *
 * Apple is the one recognised provider that issues no client secret. It issues a signing key, and the
 * value presented at its token endpoint is an assertion derived from that key which Apple **refuses if it
 * is valid for more than six months**. So any stored credential is an outage with a date on it: sign-in
 * keeps working until one morning it does not, the failure appears on Apple's page as a bare
 * `invalid_client`, nothing on this server changed, and there is nothing local to diagnose it by.
 *
 * Minting per exchange rather than caching is deliberate. It costs one signature on a path that already
 * makes a network round trip, and a cache would reintroduce the same expiry in miniature — a staleness
 * window, a clock dependency and a renewal to get wrong.
 *
 * `jose` is already a dependency for verifying upstream assertions, so the signing half costs nothing new.
 */

/*
 * Far below the six-month ceiling, because nothing needs it to live longer than the exchange it is minted
 * for. A short life means a captured assertion is worth almost nothing, and the ceiling stops being a
 * number this code has to know.
 */
const LIFETIME_SECONDS = 300;

export type AppleSecretFailure = 'unusable_key' | 'incomplete';

export class AppleSecretError extends Error {
	readonly reason: AppleSecretFailure;

	constructor(reason: AppleSecretFailure, detail?: string) {
		super(`apple credential: ${reason}${detail ? ` (${detail})` : ''}`);
		this.reason = reason;
	}
}

export interface AppleCredentialInput {
	/* The service identifier, which is also the `client_id` sent to Apple. */
	clientId: string;
	teamId: string;
	keyId: string;
	signingKey: string;
}

/*
 * Signed with the algorithm Apple's keys are, which is not negotiable: Apple issues elliptic-curve keys and
 * rejects an assertion signed any other way. Stated by the catalogue entry as well, so the two cannot
 * disagree silently.
 */
export async function appleClientSecret(
	input: AppleCredentialInput,
	options: { audience: string; algorithm: 'ES256'; maxLifetimeSeconds: number }
): Promise<string> {
	if (!input.teamId || !input.keyId || !input.signingKey) {
		throw new AppleSecretError('incomplete');
	}

	let key: CryptoKey;
	try {
		key = await importPKCS8(input.signingKey, options.algorithm);
	} catch (err) {
		/*
		 * The message is deliberately dropped rather than wrapped: it is produced by a library reading key
		 * material, and a refusal that quotes it risks putting part of that material in front of a reader.
		 */
		throw new AppleSecretError(
			'unusable_key',
			err instanceof Error ? err.name : undefined
		);
	}

	const now = Math.floor(Date.now() / 1000);
	const lifetime = Math.min(LIFETIME_SECONDS, options.maxLifetimeSeconds);

	return (
		new SignJWT({})
			.setProtectedHeader({ alg: options.algorithm, kid: input.keyId })
			// Apple reads the developer account from `iss` and the service identifier from `sub`, which is the
			// reverse of the arrangement most providers use and the most common way this is built wrongly.
			.setIssuer(input.teamId)
			.setSubject(input.clientId)
			.setAudience(options.audience)
			.setIssuedAt(now)
			.setExpirationTime(now + lifetime)
			.sign(key)
	);
}
