import { DeviceCode } from 'lib/models/device_code.js';
import { RefreshToken } from 'lib/models/refresh_token.js';
import { AuthorizationCode } from 'lib/models/authorization_code.js';
import { AccessToken } from 'lib/models/access_token.js';
import { provider } from 'lib/provider.js';

export default async function revoke(ctx, grantId) {
	const {
		oidc: { client }
	} = ctx;
	const refreshToken = client?.grantTypeAllowed('refresh_token');
	const authorizationCode = client?.grantTypeAllowed('authorization_code');
	const deviceCode = client?.grantTypeAllowed(
		'urn:ietf:params:oauth:grant-type:device_code'
	);
	const backchannelAuthenticationRequest = client?.grantTypeAllowed(
		'urn:openid:params:grant-type:ciba'
	);

	await Promise.all(
		[
			AccessToken,
			refreshToken ? RefreshToken : undefined,
			authorizationCode ? AuthorizationCode : undefined,
			deviceCode ? DeviceCode : undefined,
			backchannelAuthenticationRequest
				? provider.BackchannelAuthenticationRequest
				: undefined
		].map((model) => model?.revokeByGrantId(grantId))
	);
	provider.emit('grant.revoked', grantId);
}
