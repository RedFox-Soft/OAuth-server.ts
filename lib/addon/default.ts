import { type Client } from 'lib/models/client.js';

/**
 * assertJwtClientAuthClaimsAndHeader
 *
 * description: Helper function used to validate the JWT Client Authentication Assertion Claims Set and Header beyond
 * what its specification mandates.
 *
 * client - the Client instance
 * claims - parsed JWT Client Authentication Assertion Claims Set as object
 * header - parsed JWT Client Authentication Assertion Headers as object
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
