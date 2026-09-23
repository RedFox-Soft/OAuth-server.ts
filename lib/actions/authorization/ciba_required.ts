import type { OIDCContext } from 'lib/helpers/oidc_context.js';
import presence from '../../helpers/validate_presence.ts';
import { InvalidRequest } from '../../helpers/errors.ts';

export default function cibaRequired(oidc: OIDCContext) {
	const required = new Set(['scope']);

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
