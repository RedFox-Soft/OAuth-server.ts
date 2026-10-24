import * as profile from './profile.config.ts';
import { clients as issuing } from '../id_jag_issuing/id_jag_issuing.config.ts';

/* The IPSIE SL1 profile on an instance that issues ID-JAGs, with test/id_jag_issuing's applications. */
export const jwks = profile.jwks;

export const ApplicationConfig = {
	...profile.ApplicationConfig,
	'tokenExchange.enabled': true,
	'revocation.enabled': true,
	scopes: ['openid', 'offline_access']
};

export const clients = issuing.filter(
	(client) => client.clientId === 'globex-agent'
);

export default profile.default;
