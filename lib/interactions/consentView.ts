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
	kind: 'oidc-scope' | 'oidc-claim' | 'resource-scope';
	resourceIndicator?: string;
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

export function buildConsentView(args: {
	uid: string;
	clientName: string;
	account?: string;
	details: PromptDetails;
}): ConsentView {
	const { uid, clientName, account, details } = args;
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

	return { uid, clientName, account, permissions };
}
