import { shouldChange } from './_warn.ts';

export async function introspectionAllowedPolicy(ctx, client, token) {
	shouldChange(
		'features.introspection.allowedPolicy',
		'to check whether the caller is authorized to receive the introspection response'
	);

	// `token.payload.clientId`, not `token.clientId`: the top-level accessors went away when model
	// fields moved into the payload, so this read was always undefined and the comparison was always
	// true — meaning a public client was refused introspection of its own token. Found by the first
	// test to introspect as a `none`-auth client.
	if (
		client.clientAuthMethod === 'none' &&
		token.payload.clientId !== ctx.oidc.client.clientId
	) {
		return false;
	}

	return true;
}
