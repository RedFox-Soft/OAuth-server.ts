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
	// 'rar-detail' only: the raw RFC 9396 type identifier and the operator's label for it.
	type?: string;
	label?: string;
	items: PermissionItem[];
}

export interface ConsentView {
	uid: string;
	clientName: string;
	account?: string;
	permissions: PermissionGroup[];
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
}): ConsentView {
	const { uid, clientName, account, details, rarLabels } = args;
	const permissions: PermissionGroup[] = [];

	if (details.missingOIDCScope?.length) {
		permissions.push({
			kind: 'oidc-scope',
			items: scopeItems(details.missingOIDCScope)
		});
	}

	if (details.missingOIDCClaims?.length) {
		permissions.push({
			kind: 'oidc-claim',
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

	return { uid, clientName, account, permissions };
}
