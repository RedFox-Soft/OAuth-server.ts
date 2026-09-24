import type { OIDCContext } from 'lib/helpers/oidc_context.js';
import type { PipelineParams } from 'lib/consts/param_list.js';
import { generate, normalize } from '../../helpers/user_codes.ts';
import { ApplicationConfig } from 'lib/configs/application.js';
import { DeviceCode } from 'lib/models/device_code.js';
import { eventBus } from '../../event_bus.js';

export default async function deviceAuthorizationResponse(
	oidc: OIDCContext<PipelineParams>,
	deviceInfo
) {
	const charset = ApplicationConfig['deviceFlow.charset'];
	const mask = ApplicationConfig['deviceFlow.mask'];
	const userCode = generate(charset, mask);

	const dc = new DeviceCode({
		/* The address the device flow was started at. */
		bucketId: oidc.bucket._id,
		client: oidc.client,
		deviceInfo,
		params: oidc.params,
		userCode: normalize(userCode)
	});

	oidc.entity('DeviceCode', dc);
	/* The page of the bucket the flow was started at: its session is the one the sign-in belongs in. */
	const verificationUri = oidc.urlFor('code_verification');
	const body = {
		device_code: await dc.save(),
		user_code: userCode,
		verification_uri: verificationUri,
		verification_uri_complete: `${verificationUri}?user_code=${userCode}`,
		expires_in: dc.expiration
	};

	eventBus.emit('device_authorization.success', oidc, body);
	return body;
}
