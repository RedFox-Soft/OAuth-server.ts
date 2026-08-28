import { type Client } from 'lib/models/client.js';

/**
 * Validates a JWT Client Authentication Assertion beyond what its specification
 * mandates — which is why the default accepts everything: there is nothing to add
 * until a deployment says so. An override seam, not an unimplemented stub.
 *
 * The server invokes it from lib/shared/token_jwt_auth.ts on every JWT client
 * authentication, after the spec-mandated checks have already passed. Replace it
 * with addons.override({ assertJwtClientAuthClaimsAndHeader }). Throw to reject
 * the assertion; resolve to accept it.
 */
export async function assertJwtClientAuthClaimsAndHeader(
	_client: Client,
	_claims: Record<string, unknown> & {
		exp: number;
		jti: string;
		iss: string;
		aud: string | string[];
	},
	_header: Record<string, unknown>
): Promise<void> {}
