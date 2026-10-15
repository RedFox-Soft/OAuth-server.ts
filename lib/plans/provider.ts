import {
	KNOWN_PROVIDERS,
	MICROSOFT_SHARED_TENANTS,
	knownProviderByIssuer
} from '../consts/known_providers.js';

export interface ProviderInput {
	catalogueId?: string;
	issuer?: string;
	tenant?: string;
}

/*
 * Whether a federation provider is social sign-in or enterprise sign-in (specs/102, clarification Q2).
 *
 * Social: a recognised provider — and, for Microsoft, one of its directories open to more than one organisation.
 * Enterprise: an issuer this server does not recognise, or Microsoft bound to one organisation's directory, which
 * is a company's single sign-on under a familiar name.
 *
 * Classified from what the request says, because the plan is checked before the audit write and the service's own
 * resolution comes after it. A request too incomplete to classify answers `social`, so the service's validation —
 * not a plan — is what refuses it.
 */
export function classifyProvider(
	input: ProviderInput
): 'social' | 'enterprise' {
	const entry =
		input.catalogueId !== undefined
			? KNOWN_PROVIDERS.find((known) => known.catalogueId === input.catalogueId)
			: input.issuer !== undefined
				? knownProviderByIssuer(input.issuer)
				: undefined;
	if (!entry) {
		return input.catalogueId === undefined && input.issuer === undefined
			? 'social'
			: 'enterprise';
	}
	if (entry.issuerRule.kind === 'fixed') return 'social';
	const tenant = input.tenant ?? tenantOf(input.issuer);
	if (tenant === undefined) return 'social';
	return MICROSOFT_SHARED_TENANTS.includes(tenant.toLowerCase())
		? 'social'
		: 'enterprise';
}

/* The organisation segment of a templated issuer: https://login.microsoftonline.com/{tenant}/v2.0. */
function tenantOf(issuer: string | undefined): string | undefined {
	if (issuer === undefined) return undefined;
	try {
		const segment = new URL(issuer).pathname.split('/').at(1);
		return segment === undefined || segment === ''
			? undefined
			: decodeURIComponent(segment);
	} catch {
		return undefined;
	}
}
