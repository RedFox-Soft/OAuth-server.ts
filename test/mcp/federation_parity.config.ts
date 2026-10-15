import getConfig from '../default.config.js';
import { ADMIN_MCP_CLIENT_ID } from 'lib/mcp/consts.ts';
import { ADMIN_BUCKET_ID } from 'lib/admin/consts.ts';

/*
 * Harness for the administrative MCP control plane.
 *
 * `mcp.enabled` is on here and off by default everywhere else, which is deliberate on both sides: the
 * capability hands an agent administrative authority, so a deployment opts in — and so does a spec.
 */
export const ApplicationConfig = {
	...getConfig(),
	'mcp.enabled': true
};

/*
 * The reserved client an MCP agent authenticates as. Public with mandatory PKCE, and it belongs to the
 * administrators bucket, as its provisioned seed does: a sign-in through it resolves to that bucket
 * because the stored client names it. A spec seeds it here, before `ensureAdminSeed` runs, so this
 * registration has to carry the binding the seed would otherwise have written.
 */
export const clients = [
	{
		clientId: ADMIN_MCP_CLIENT_ID,
		bucketId: ADMIN_BUCKET_ID,
		token_endpoint_auth_method: 'none',
		grantTypes: ['authorization_code', 'refresh_token'],
		responseTypes: ['code'],
		redirectUris: ['http://127.0.0.1:33418/callback']
	}
];

export default { config: getConfig() };
