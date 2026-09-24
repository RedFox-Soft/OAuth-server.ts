import type { OIDCContext } from 'lib/helpers/oidc_context.js';
import type { PipelineParams } from 'lib/consts/param_list.js';
import combinedScope from '../../helpers/combined_scope.ts';
import { deviceSuccessPage } from '../../html/device.js';
import { expiresWithSession } from '../../addon/index.js';
import { eventBus } from '../../event_bus.js';
import { includeSid } from 'lib/models/client.js';

export default async function deviceVerificationResponse(
	oidc: OIDCContext<PipelineParams>
) {
	const code = oidc.require('DeviceCode');

	const scopeSet = combinedScope(
		oidc.require('Grant'),
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

	if (await expiresWithSession(oidc, code)) {
		code.payload.expiresWithSession = true;
	} else {
		oidc.session.authorizationFor(oidc.client.clientId).persistsLogout = true;
	}

	if (
		includeSid(oidc.client) ||
		(oidc.claims.id_token && 'sid' in oidc.claims.id_token)
	) {
		code.payload.sid = oidc.session.sidFor(oidc.client.clientId);
	}

	await code.save();

	eventBus.emit('authorization.success', oidc);

	return deviceSuccessPage({ client: oidc.client });
}
