import { type Client } from './types.ts';
import epochTime from '../../helpers/epoch_time.ts';
import constantEquals from '../../helpers/constant_equals.ts';
import { InvalidClient } from '../../helpers/errors.ts';
import { clockTolerance } from '../../configs/liveTime.ts';

const nonSecretAuthMethods = new Set([
	'private_key_jwt',
	'none',
	'tls_client_auth',
	'self_signed_tls_client_auth'
]);
const clientEncryptions = [
	'id_token_encrypted_response_alg',
	'request_object_encryption_alg',
	'userinfo_encrypted_response_alg',
	'introspection_encrypted_response_alg',
	'authorization_encrypted_response_alg'
];
const signAlgAttributes = [
	'id_token_signed_response_alg',
	// canonical (Model B) dotted key; the snake `request_object_signing_alg` no longer exists internally
	'requestObject.signingAlg',
	'token_endpoint_auth_signing_alg',
	'userinfo_signed_response_alg',
	'introspection_signed_response_alg',
	'authorization_signed_response_alg'
];

// String() is what RegExp#test does to a non-string anyway; it is spelled out for the type checker.
function isSymmetricAlg(this: Readonly<Record<string, unknown>>, prop: string) {
	return /^(A|dir$)/.test(String(this[prop]));
}

function isHmac(this: Readonly<Record<string, unknown>>, prop: string) {
	return /^HS/.test(String(this[prop]));
}

// Constant-time compare with the preserved 1000ms floor.
export function compareClientSecret(
	client: Pick<Client, 'clientSecret'>,
	actual: string
): boolean {
	return constantEquals(client.clientSecret, actual, 1000);
}

// Throw InvalidClient if clientSecretExpiresAt has passed (clockTolerance + optional errorOverride).
export function checkClientSecretExpiration(
	client: Pick<Client, 'clientId' | 'clientSecretExpiresAt'>,
	message: string,
	errorOverride?: string
): void {
	if (!client.clientSecretExpiresAt) {
		return;
	}

	if (epochTime() - clockTolerance >= client.clientSecretExpiresAt) {
		const err = new InvalidClient(
			message,
			`client_id ${client.clientId} client_secret expired at ${client.clientSecretExpiresAt}`
		);
		if (errorOverride) {
			err.error = errorOverride;
			err.message = errorOverride;
		}
		throw err;
	}
}

// Auth-method / HMAC / symmetric-encryption derivation. Operates on recognized
// snake_case metadata plus the canonical dotted `requestObject.signingAlg` key
// (callers must make that key readable on the passed object — see schema.ts).
export function needsSecret(submitted: object): boolean {
	// Read by name: the validator hands in its own instance, which carries the attributes as own
	// properties but has no index signature.
	const metadata = submitted as Readonly<Record<string, unknown>>;
	const method = metadata.token_endpoint_auth_method;
	if (typeof method !== 'string' || !nonSecretAuthMethods.has(method)) {
		return true;
	}

	if (signAlgAttributes.some(isHmac, metadata)) {
		return true;
	}

	if (clientEncryptions.some(isSymmetricAlg, metadata)) {
		return true;
	}

	return false;
}
