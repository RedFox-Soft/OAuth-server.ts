import instance from '../../helpers/weak_cache.ts';
import combinedScope from '../../helpers/combined_scope.ts';
import { deviceSuccessPage } from '../../html/device.js';

export default async function deviceVerificationResponse(oidc) {
	const { configuration } = instance(oidc.provider);
	const code = oidc.deviceCode;

	const scopeSet = combinedScope(
		oidc.grant,
		oidc.requestParamScopes,
		oidc.resourceServers
	);

	Object.assign(code.payload, {
		accountId: oidc.session.payload.accountId,
		acr: oidc.acr,
		amr: oidc.amr,
		authTime: oidc.session.authTime(),
		claims: oidc.claims,
		grantId: oidc.session.grantIdFor(oidc.client.clientId),
		scope: [...scopeSet].join(' '),
		sessionUid: oidc.session.payload.uid,
		resource: Object.keys(oidc.resourceServers)
	});

	if (Object.keys(code.payload.claims).length === 0) {
		delete code.payload.claims;
	}

	switch (code.payload.resource.length) {
		case 0:
			delete code.payload.resource;
			break;
		case 1:
			[code.payload.resource] = code.payload.resource;
			break;
	}

	if (await configuration.expiresWithSession({ oidc }, code)) {
		code.payload.expiresWithSession = true;
	} else {
		oidc.session.authorizationFor(oidc.client.clientId).persistsLogout = true;
	}

	if (
		oidc.client.includeSid() ||
		(oidc.claims.id_token && 'sid' in oidc.claims.id_token)
	) {
		code.payload.sid = oidc.session.sidFor(oidc.client.clientId);
	}

	await code.save();

	oidc.provider.emit('authorization.success', { oidc });

	return deviceSuccessPage({ client: oidc.client });
}
