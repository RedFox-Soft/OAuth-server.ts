import { ApplicationConfig as passkeys, clients } from './passkeys.config.ts';

/*
 * The passkey projects of passkeys.config.ts with the caller's address read from the connection, as
 * test/sign_in_alerts/ runs it: a case about how a passkey sign-in is recorded and mailed about needs to sign in from
 * an address of its choosing. The rate limit is off because the cases sign one person in several times.
 */
export const ApplicationConfig = {
	...passkeys,
	'rateLimit.enabled': false,
	'clientAddress.source': 'direct'
};

export { clients };
