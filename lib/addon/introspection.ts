import { shouldChange } from './_warn.ts';

export async function introspectionAllowedPolicy(ctx, client, token) {
	shouldChange(
		'features.introspection.allowedPolicy',
		'to check whether the caller is authorized to receive the introspection response'
	);

	if (
		client.clientAuthMethod === 'none' &&
		token.clientId !== ctx.oidc.client.clientId
	) {
		return false;
	}

	return true;
}
