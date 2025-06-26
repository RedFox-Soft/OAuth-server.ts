import { DeviceCode } from 'lib/models/device_code.js';
import instance from './weak_cache.ts';
import { RefreshToken } from 'lib/models/refresh_token.js';

export default async function revoke(ctx, grantId) {
	const {
		oidc: { client, provider }
	} = ctx;
	const { grantTypes, revokeGrantPolicy } = instance(provider).configuration;
	const refreshToken = client
		? client.grantTypeAllowed('refresh_token')
		: grantTypes.has('refresh_token');
	const authorizationCode = client
		? client.grantTypeAllowed('authorization_code')
		: grantTypes.has('authorization_code');
	const deviceCode = client
		? client.grantTypeAllowed('urn:ietf:params:oauth:grant-type:device_code')
		: grantTypes.has('urn:ietf:params:oauth:grant-type:device_code');
	const backchannelAuthenticationRequest = client
		? client.grantTypeAllowed('urn:openid:params:grant-type:ciba')
		: grantTypes.has('urn:openid:params:grant-type:ciba');

	const revokeGrant = await revokeGrantPolicy(ctx);

	await Promise.all(
		[
			provider.AccessToken,
			refreshToken ? RefreshToken : undefined,
			authorizationCode ? provider.AuthorizationCode : undefined,
			deviceCode ? DeviceCode : undefined,
			backchannelAuthenticationRequest
				? provider.BackchannelAuthenticationRequest
				: undefined
		]
			.map((model) => model && model.revokeByGrantId(grantId))
			.concat(revokeGrant ? provider.Grant.adapter.destroy(grantId) : undefined)
	);
	if (revokeGrant) {
		ctx.oidc.provider.emit('grant.revoked', ctx, grantId);
	}
}
