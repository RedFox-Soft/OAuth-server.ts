import { ISSUER } from 'lib/configs/env.js';
import { generate, normalize } from '../../helpers/user_codes.ts';
import { ApplicationConfig } from 'lib/configs/application.js';
import { DeviceCode } from 'lib/models/device_code.js';

export default async function deviceAuthorizationResponse(oidc, deviceInfo) {
	const charset = ApplicationConfig['deviceFlow.charset'];
	const mask = ApplicationConfig['deviceFlow.mask'];
	const userCode = generate(charset, mask);

	const dc = new DeviceCode({
		client: oidc.client,
		deviceInfo,
		params: oidc.params,
		userCode: normalize(userCode)
	});

	oidc.entity('DeviceCode', dc);
	const body = {
		device_code: await dc.save(),
		user_code: userCode,
		verification_uri: ISSUER + '/device',
		verification_uri_complete: ISSUER + '/device' + `?user_code=${userCode}`,
		expires_in: dc.expiration
	};

	// event payload kept `{ oidc }`-shaped (was `ctx`)
	oidc.provider.emit('device_authorization.success', { oidc }, body);
	return body;
}
