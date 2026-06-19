import presence from '../../helpers/validate_presence.ts';

export default function oidcRequired(oidc, next) {
	const required = new Set(['scope']);

	if (oidc.client.backchannelTokenDeliveryMode !== 'poll') {
		required.add('client_notification_token');
	}

	presence(oidc, ...required);

	return next();
}
