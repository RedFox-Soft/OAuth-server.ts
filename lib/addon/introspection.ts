import { shouldChange } from './_warn.ts';
import type { OIDCContext } from '../helpers/oidc_context.ts';
import type { Client } from '../models/client.ts';

export async function introspectionAllowedPolicy(
	oidc: OIDCContext,
	client: Client,
	// The token being introspected; all the default reads is whose it is.
	token: { payload: { clientId?: string } }
) {
	shouldChange(
		'features.introspection.allowedPolicy',
		'to check whether the caller is authorized to receive the introspection response'
	);

	// `token.payload.clientId`, not `token.clientId`: the top-level accessors went away when model
	// fields moved into the payload, so this read was always undefined and the comparison was always
	// true — meaning a public client was refused introspection of its own token. Found by the first
	// test to introspect as a `none`-auth client.
	if (
		client.tokenEndpointAuthMethod === 'none' &&
		token.payload.clientId !== oidc.client.clientId
	) {
		return false;
	}

	return true;
}
