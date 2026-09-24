import { Grant } from 'lib/models/grant.js';
import { backchannelResult } from 'lib/actions/authorization/backchannel_result.js';
import type { BackchannelAuthenticationRequest } from 'lib/models/backchannel_authentication_request.js';
import type { AddonImplementations } from 'lib/addon/types.js';

/*
 * The flows that start somewhere other than the authorization endpoint — device authorization,
 * backchannel authentication, registration — each on its own address. Kept apart from the area's main
 * config because switching these on changes what every other spec here sees in the metadata.
 */

const DEVICE = 'urn:ietf:params:oauth:grant-type:device_code';
const CIBA = 'urn:openid:params:grant-type:ciba';

export const ApplicationConfig = {
	'deviceFlow.enabled': true,
	'ciba.enabled': true,
	'ciba.deliveryModes': ['poll'],
	'registration.enabled': true
};

export const clients = [
	{
		clientId: 'default-device',
		clientSecret: 'default-secret',
		token_endpoint_auth_method: 'client_secret_basic',
		grantTypes: [DEVICE, CIBA],
		responseTypes: [],
		redirectUris: [],
		applicationType: 'native',
		backchannel_token_delivery_mode: 'poll'
	}
];

/* The bucket's own client, declared here and seeded into the bucket by the spec. */
export const acmeClient = {
	clientSecret: 'acme-secret',
	token_endpoint_auth_method: 'client_secret_basic',
	grantTypes: [DEVICE, CIBA],
	responseTypes: [],
	redirectUris: [],
	applicationType: 'native',
	backchannel_token_delivery_mode: 'poll',
	'consent.require': false
};

/*
 * The backchannel request is approved the moment it is made, so a spec can go straight to redeeming
 * it: what is under test is which issuer the redemption answers with, not the approval.
 */
export const addons: Partial<AddonImplementations> = {
	processLoginHint(_oidc: unknown, loginHint: string) {
		return loginHint;
	},
	validateBindingMessage() {},
	validateRequestContext() {},
	verifyUserCode() {},
	async triggerAuthenticationDevice(
		_oidc: unknown,
		request: BackchannelAuthenticationRequest
	) {
		const grant = new Grant({
			clientId: request.payload.clientId,
			accountId: request.payload.accountId
		});
		grant.addOIDCScope('openid');
		await grant.save();
		return backchannelResult(request, grant.jti);
	}
};
