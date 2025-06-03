import { ISSUER } from 'lib/configs/env.js';
import { generate, normalize } from '../../helpers/user_codes.ts';
import instance from '../../helpers/weak_cache.ts';

export default async function deviceAuthorizationResponse(ctx, deviceInfo) {
	const { charset, mask } = instance(ctx.oidc.provider).features.deviceFlow;
	const userCode = generate(charset, mask);

	const dc = new ctx.oidc.provider.DeviceCode({
		client: ctx.oidc.client,
		deviceInfo,
		params: ctx.oidc.params,
		userCode: normalize(userCode)
	});

	ctx.oidc.entity('DeviceCode', dc);
	ctx.body = {
		device_code: await dc.save(),
		user_code: userCode,
		verification_uri: ISSUER + '/device',
		verification_uri_complete: ISSUER + '/device' + `?user_code=${userCode}`,
		expires_in: dc.expiration
	};

	ctx.oidc.provider.emit('device_authorization.success', ctx, ctx.body);
	return ctx.body;
}
