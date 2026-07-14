import { DeviceCode } from 'lib/models/device_code.js';
import { RefreshToken } from 'lib/models/refresh_token.js';
import { AuthorizationCode } from 'lib/models/authorization_code.js';
import { AccessToken } from 'lib/models/access_token.js';
import { BackchannelAuthenticationRequest } from 'lib/models/backchannel_authentication_request.js';
import { provider } from 'lib/provider.js';
import type { OIDCContext } from './oidc_context.ts';

export default async function revoke(
	oidc: OIDCContext<Record<string, unknown>>,
	grantId: string
) {
	const { client } = oidc;
	const refreshToken = client?.grantTypeAllowed('refresh_token');
	const authorizationCode = client?.grantTypeAllowed('authorization_code');
	const deviceCode = client?.grantTypeAllowed(
		'urn:ietf:params:oauth:grant-type:device_code'
	);
	const backchannelAuthenticationRequest = client?.grantTypeAllowed(
		'urn:openid:params:grant-type:ciba'
	);

	const models = [
		AccessToken,
		refreshToken ? RefreshToken : undefined,
		authorizationCode ? AuthorizationCode : undefined,
		deviceCode ? DeviceCode : undefined,
		backchannelAuthenticationRequest
			? BackchannelAuthenticationRequest
			: undefined
	];

	await Promise.all(models.map((model) => model?.revokeByGrantId(grantId)));
	provider.emit('grant.revoked', grantId);
}
