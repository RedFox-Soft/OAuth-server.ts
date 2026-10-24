import * as profile from './profile.config.ts';
import {
	addons as backchannelAddons,
	clients as backchannelClients
} from '../acr/backchannel.config.ts';

/* The IPSIE SL1 profile with test/acr's backchannel harness: CIBA on, and its poll-mode application. */
export { CIBA_CLIENT_SECRET } from '../acr/backchannel.config.ts';

export const jwks = profile.jwks;
export const addons = backchannelAddons;

export const ApplicationConfig = {
	...profile.ApplicationConfig,
	'ciba.enabled': true,
	'ciba.deliveryModes': ['poll'],
	acrValues: {
		password: 'urn:example:acr:pwd',
		multi_factor: 'urn:example:acr:mfa',
		federated: 'urn:example:acr:federated'
	}
};

export const clients = backchannelClients.filter(
	(client) => client.clientId === 'ciba-poll'
);

export default profile.default;
