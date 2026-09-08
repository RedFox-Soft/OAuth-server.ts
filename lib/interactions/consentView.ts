import { isLoopbackRedirect } from '../client_metadata_document/identifier.js';

// Derived, non-persisted view model for the consent screen. The consent prompt
// stores the permissions the End-User must approve on the interaction session
// (interaction.payload.prompt.details); this module turns that raw shape into a
// human-readable structure the ConsentPage renders both server-side and after
// client hydration.

export interface PermissionItem {
	token: string;
	label: string;
}

export interface PermissionGroup {
	kind: 'oidc-scope' | 'oidc-claim' | 'resource-scope' | 'rar-detail';
	resourceIndicator?: string;
	// 'rar-detail' only: the raw RFC 9396 type identifier.
	type?: string;
	// Every group carries a heading. Required, not optional: a group the End-User cannot name is a list
	// of tokens they are being asked to approve on trust.
	label: string;
	items: PermissionItem[];
}

export interface ConsentView {
	uid: string;
	clientName: string;
	account?: string;
	permissions: PermissionGroup[];
	/*
	 * Where the client's identity comes from, when it comes from a document the client hosts itself
	 * rather than from a registration an operator made.
	 *
	 * The name above is then whatever that document claims, which is exactly why the hostnames matter:
	 * the document proves control of a domain, so the domain is the part the End-User can actually
	 * weigh. Both are required by the governing draft (§6.4) and the MCP security considerations —
	 * show the `client_id` hostname, and show the redirect target's.
	 */
	clientIdHostname?: string;
	redirectHostname?: string;
	/*
	 * Set when every redirect target the document offers is a loopback address. Such a document cannot
	 * prove *which local process* will receive the authorization code — the specification says so
	 * outright, and calls the warning a SHOULD. The End-User is the only party in a position to notice
	 * that they did not just start the application being named.
	 */
	loopbackOnly?: boolean;
}

/*
 * The identity facts a consent screen shows about a client identified by its own document. Returns
 * nothing for an ordinary registered client: those were vouched for by an operator, so there is no
 * domain for the End-User to weigh and a hostname line would be noise.
 */
export function documentIdentityFor(args: {
	clientId?: string;
	redirectUri?: string;
	redirectUris?: string[];
}): Pick<
	ConsentView,
	'clientIdHostname' | 'redirectHostname' | 'loopbackOnly'
> {
	const identifier = args.clientId ? URL.parse(args.clientId) : null;
	if (!identifier || identifier.protocol !== 'https:') return {};

	const redirect = args.redirectUri ? URL.parse(args.redirectUri) : null;
	const offered = args.redirectUris ?? [];

	return {
		clientIdHostname: identifier.hostname,
		...(redirect ? { redirectHostname: redirect.hostname } : {}),
		...(offered.length > 0 && offered.every(isLoopbackRedirect)
			? { loopbackOnly: true }
			: {})
	};
}

// The subset of the consent prompt's `details` this view consumes.
export interface PromptDetails {
	missingOIDCScope?: string[];
	missingOIDCClaims?: string[];
	missingResourceScopes?: Record<string, string[]>;
	// The requested authorization details that are not already granted — the same subset the prompt
	// computed to decide whether to interrupt at all, so the End-User is never asked to re-approve
	// something they have already approved.
	rar?: unknown[];
}

// Friendly labels for the standard OIDC scopes. Unknown/custom tokens fall back
// to the raw token, so nothing a client requests is ever hidden.
const OIDC_SCOPE_LABELS: Record<string, string> = {
	openid: 'Confirm your identity',
	profile: 'Your basic profile information',
	email: 'Your email address',
	address: 'Your postal address',
	phone: 'Your phone number',
	offline_access: 'Offline access (stay signed in)'
};

function scopeItems(tokens: string[]): PermissionItem[] {
	return tokens.map((token) => ({
		token,
		label: OIDC_SCOPE_LABELS[token] ?? token
	}));
}

/*
 * Group headings, in the same spirit as the scope labels above: presentation vocabulary, not
 * configuration. Without them the four kinds arrive as one undifferentiated bullet list, and "who I am"
 * reads the same as "what an API may do on my behalf".
 */
const GROUP_HEADINGS = {
	'oidc-scope': 'Your identity information',
	'oidc-claim': 'Specific details about you'
} as const;

const resourceHeading = (indicator: string) => `Access to ${indicator}`;

// The five common data fields are fixed by RFC 9396 §2, so these labels are presentation vocabulary
// like OIDC_SCOPE_LABELS above — not configuration, and not something an operator declares.
const RAR_FIELD_LABELS: Record<string, string> = {
	actions: 'Actions',
	locations: 'Locations',
	datatypes: 'Data types',
	privileges: 'Privileges',
	identifier: 'Identifier'
};

function rarDetailItems(detail: Record<string, unknown>): PermissionItem[] {
	const items: PermissionItem[] = [];
	for (const field of Object.keys(RAR_FIELD_LABELS)) {
		const value = detail[field];
		if (value === undefined) {
			continue;
		}
		const rendered = Array.isArray(value) ? value.join(', ') : String(value);
		// `token` stays the machine field name so it is a stable key; the label carries the whole
		// readable line, because a field and its values are one statement rather than a token plus an
		// explanation of it.
		items.push({
			token: field,
			label: `${RAR_FIELD_LABELS[field]}: ${rendered}`
		});
	}
	return items;
}

export function buildConsentView(args: {
	uid: string;
	clientName: string;
	account?: string;
	details: PromptDetails;
	// Type identifier → operator label. Passed in by the caller so this module stays a pure view-model
	// builder with no configuration reads, testable without a live config.
	rarLabels?: Record<string, string>;
	/* Present only for a client identified by a document it hosts; see `documentIdentityFor`. */
	identity?: Pick<
		ConsentView,
		'clientIdHostname' | 'redirectHostname' | 'loopbackOnly'
	>;
}): ConsentView {
	const { uid, clientName, account, details, rarLabels, identity } = args;
	const permissions: PermissionGroup[] = [];

	if (details.missingOIDCScope?.length) {
		permissions.push({
			kind: 'oidc-scope',
			label: GROUP_HEADINGS['oidc-scope'],
			items: scopeItems(details.missingOIDCScope)
		});
	}

	if (details.missingOIDCClaims?.length) {
		permissions.push({
			kind: 'oidc-claim',
			label: GROUP_HEADINGS['oidc-claim'],
			items: details.missingOIDCClaims.map((token) => ({ token, label: token }))
		});
	}

	if (details.missingResourceScopes) {
		for (const [indicator, scopes] of Object.entries(
			details.missingResourceScopes
		)) {
			if (scopes?.length) {
				permissions.push({
					kind: 'resource-scope',
					resourceIndicator: indicator,
					// The heading names the resource, so the page no longer prints the indicator on a
					// line of its own above it.
					label: resourceHeading(indicator),
					items: scopes.map((token) => ({ token, label: token }))
				});
			}
		}
	}

	if (details.rar?.length) {
		for (const entry of details.rar) {
			if (entry === null || typeof entry !== 'object') {
				continue;
			}
			const detail = entry as Record<string, unknown>;
			const type = typeof detail.type === 'string' ? detail.type : '';
			permissions.push({
				kind: 'rar-detail',
				type,
				// An unlabelled type is reachable only if the configured map changed while an
				// interaction was in flight; the raw identifier is shown rather than the detail hidden,
				// following this module's rule that nothing a client requests is ever hidden.
				label: rarLabels?.[type] ?? type,
				items: rarDetailItems(detail)
			});
		}
	}

	return { uid, clientName, account, permissions, ...(identity ?? {}) };
}
