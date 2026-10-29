/*
 * How the server is reached, as the operator declares it in `clientAddress.source`. Import-free, so the
 * settings module and the address resolver can both read it without depending on each other.
 */
export const CLIENT_ADDRESS_SOURCES = [
	'automatic',
	'direct',
	'fly',
	'cloudflare',
	'listed'
] as const;

export type ClientAddressSource = (typeof CLIENT_ADDRESS_SOURCES)[number];

/* How many proxy addresses or ranges an operator may list for `listed`. */
export const MAX_TRUSTED_PROXIES = 64;

/* The bounds of `mail.requestsPerCallerPerHour`. */
export const MAIL_REQUESTS_PER_HOUR_MAX = 10_000;
