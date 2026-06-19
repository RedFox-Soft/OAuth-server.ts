import { type ClientSchemaType } from '../../configs/clientSchema.ts';
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
	'request_object_signing_alg',
	'token_endpoint_auth_signing_alg',
	'userinfo_signed_response_alg',
	'introspection_signed_response_alg',
	'authorization_signed_response_alg'
];

function isSymmetricAlg(prop) {
	const value = this[prop];
	return /^(A|dir$)/.test(value);
}

function isHmac(prop) {
	const value = this[prop];
	return /^HS/.test(value);
}

// Constant-time compare with the preserved 1000ms floor.
export function compareClientSecret(
	client: ClientSchemaType,
	actual: string
): boolean {
	return constantEquals(client.clientSecret, actual, 1000);
}

// Throw InvalidClient if clientSecretExpiresAt has passed (clockTolerance + optional errorOverride).
export function checkClientSecretExpiration(
	client: ClientSchemaType,
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

// Auth-method / HMAC / symmetric-encryption derivation. Operates on raw
// snake_case metadata (as the former static Client.needsSecret did).
export function needsSecret(metadata): boolean {
	if (!nonSecretAuthMethods.has(metadata.token_endpoint_auth_method)) {
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
