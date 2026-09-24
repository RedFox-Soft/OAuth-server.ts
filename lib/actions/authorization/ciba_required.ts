import type { OIDCContext } from 'lib/helpers/oidc_context.js';
import type { PipelineParams } from 'lib/consts/param_list.js';
import presence from '../../helpers/validate_presence.ts';
import { InvalidRequest } from '../../helpers/errors.ts';

export default function cibaRequired(oidc: OIDCContext<PipelineParams>) {
	const required = new Set<keyof PipelineParams>(['scope']);

	if (oidc.client.backchannelTokenDeliveryMode !== 'poll') {
		required.add('client_notification_token');
	}

	presence(oidc, ...required);

	if (
		oidc.params.requested_expiry !== undefined &&
		!(Number(oidc.params.requested_expiry) > 0)
	) {
		throw new InvalidRequest('invalid requested_expiry parameter value');
	}
}
