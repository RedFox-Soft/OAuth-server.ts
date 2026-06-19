import { ISSUER } from 'lib/configs/env.js';
import { generate, normalize } from '../../helpers/user_codes.ts';
import instance from '../../helpers/weak_cache.ts';
import { DeviceCode } from 'lib/models/device_code.js';

export default async function deviceAuthorizationResponse(oidc, deviceInfo) {
	const { charset, mask } = instance(oidc.provider).features.deviceFlow;
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
