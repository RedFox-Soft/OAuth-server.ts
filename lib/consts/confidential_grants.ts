import {
	JWT_BEARER_GRANT,
	JWT_DPOP_GRANT,
	TOKEN_EXCHANGE_GRANT
} from './assertion_grants.ts';

/*
 * Grants only a client that can authenticate may use. With no authentication of its own (`none`), the
 * client_id is the whole credential, and a client_id is public: it sits in every authorization URL a browser
 * shows. RFC 6749 §4.4.2 and OAuth 2.1 §4.2 confine client_credentials to confidential clients; CIBA Core
 * §7.1 has the client authenticate at the backchannel endpoint, which `none` does not do.
 *
 * The assertion grants join them (specs/108): ID-JAG §9.1 confines the profile to confidential clients, and
 * without authentication the `client_id` an ID-JAG is bound to is a value anyone can claim.
 *
 * Refused where tokens are issued, for every client already stored, and where the console and agents write
 * a client. Not yet in the registration validator: every lookup re-validates, so a rule there would stop
 * existing clients resolving for their other grants too.
 */
export const CONFIDENTIAL_ONLY_GRANTS: readonly string[] = [
	'client_credentials',
	'urn:openid:params:grant-type:ciba',
	TOKEN_EXCHANGE_GRANT,
	JWT_BEARER_GRANT,
	JWT_DPOP_GRANT
];

// The first grant a client authenticating with `authMethod` may not hold, or undefined.
export function grantRefusedToPublicClient(
	authMethod: unknown,
	grantTypes: readonly string[]
): string | undefined {
	if (authMethod !== 'none') return undefined;
	return grantTypes.find((grant) => CONFIDENTIAL_ONLY_GRANTS.includes(grant));
}
