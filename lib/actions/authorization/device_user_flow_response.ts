import instance from '../../helpers/weak_cache.ts';
import combinedScope from '../../helpers/combined_scope.ts';

export default async function deviceVerificationResponse(oidc) {
	const { configuration, features } = instance(oidc.provider);
	const code = oidc.deviceCode;

	const scopeSet = combinedScope(
		oidc.grant,
		oidc.requestParamScopes,
		oidc.resourceServers
	);

	Object.assign(code, {
		accountId: oidc.session.accountId,
		acr: oidc.acr,
		amr: oidc.amr,
		authTime: oidc.session.authTime(),
		claims: oidc.claims,
		grantId: oidc.session.grantIdFor(oidc.client.clientId),
		scope: [...scopeSet].join(' '),
		sessionUid: oidc.session.uid,
		resource: Object.keys(oidc.resourceServers)
	});

	if (Object.keys(code.claims).length === 0) {
		delete code.claims;
	}

	switch (code.resource.length) {
		case 0:
			delete code.resource;
			break;
		case 1:
			[code.resource] = code.resource;
			break;
	}

	if (await configuration.expiresWithSession({ oidc }, code)) {
		code.expiresWithSession = true;
	} else {
		oidc.session.authorizationFor(oidc.client.clientId).persistsLogout = true;
	}

	if (
		oidc.client.includeSid() ||
		(oidc.claims.id_token && 'sid' in oidc.claims.id_token)
	) {
		code.sid = oidc.session.sidFor(oidc.client.clientId);
	}

	await code.save();

	await features.deviceFlow.successSource({ oidc });

	oidc.provider.emit('authorization.success', { oidc });
}
