import type { FederationProvider } from './types.js';

/*
 * Case-insensitive on the domain part, against entries stored as bare lowercase domains. No subdomain
 * wildcarding: `acme.com` does not admit `eu.acme.com`, and — the case that matters — a suffix comparison
 * would have admitted `acme.com.evil.test`.
 *
 * Its own module so the console's reachability check (lib/admin/federation/reachability.ts) asks the same
 * question the sign-in does without importing the resolver.
 */
export function domainAllowed(
	email: string,
	provider: Pick<FederationProvider, 'allowedEmailDomains'>
): boolean {
	if (provider.allowedEmailDomains.length === 0) return true;
	const at = email.lastIndexOf('@');
	if (at === -1) return false;
	const domain = email.slice(at + 1).toLowerCase();
	return provider.allowedEmailDomains.includes(domain);
}
