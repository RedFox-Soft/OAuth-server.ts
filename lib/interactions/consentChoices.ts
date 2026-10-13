import type { DataCategory, PromptDetails } from './consentView.js';

/*
 * What the person may leave unticked on the consent page, and what they may not (specs/093).
 *
 * One function, called by the page to draw its checkboxes and by the form's handler to judge what came back:
 * the handler never learns from the submission what was on offer, so a value the page did not draw is
 * recognisably foreign. It reads only the prompt's details and two facts about the request — never the
 * person's claims — so the page and the handler cannot disagree because data changed in between.
 */

export const NAME_CLAIMS = [
	'name',
	'given_name',
	'family_name',
	'middle_name',
	'nickname',
	'preferred_username'
];
export const PROFILE_DETAIL_CLAIMS = [
	'profile',
	'website',
	'gender',
	'birthdate',
	'zoneinfo',
	'locale',
	'updated_at'
];

// Claims every sign-in carries; asking for one by name adds nothing a person would read or could refuse.
export const PROTOCOL_CLAIMS = new Set([
	'sub',
	'acr',
	'amr',
	'sid',
	'auth_time',
	'iss'
]);

/* The category an individually requested claim belongs to, or undefined for one nobody worded. */
export function claimCategory(claim: string): DataCategory | undefined {
	if (NAME_CLAIMS.includes(claim)) return 'profileName';
	if (claim === 'picture') return 'profilePhoto';
	if (PROFILE_DETAIL_CLAIMS.includes(claim)) return 'profileDetails';
	if (claim === 'email' || claim === 'email_verified') return 'email';
	if (claim === 'address') return 'address';
	if (claim === 'phone_number' || claim === 'phone_number_verified')
		return 'phone';
	if (claim === 'groups') return 'groups';
	return undefined;
}

/*
 * The price of signing in: who the person is and how to reach them. Refusing these would leave an
 * application that asked to sign someone in not knowing whom it signed in.
 */
const FIXED_SCOPES = new Set(['openid', 'profile', 'email']);
const FIXED_CATEGORIES = new Set<DataCategory>([
	'profile',
	'profileName',
	'profilePhoto',
	'profileDetails',
	'email'
]);

/* The standard scopes a person may refuse, each with the category its claims fall under. */
export const SELECTABLE_STANDARD: Partial<Record<string, DataCategory>> = {
	address: 'address',
	phone: 'phone',
	groups: 'groups'
};

export interface SelectableItem {
	/* What the page posts back for a ticked row; content, not position, so a forged one names itself. */
	key: string;
	scopes: string[];
	claims: string[];
	/* The resource indicator, for a resource's scope. */
	resource?: string;
}

export interface ConsentChoices {
	/* Whether the page offers checkboxes at all; when false the page and its outcome are all-or-nothing. */
	active: boolean;
	fixed: {
		scopes: string[];
		claims: string[];
		resourceScopes: Record<string, string[]>;
	};
	selectable: SelectableItem[];
	rar: unknown[];
}

export const OFFLINE_KEY = 'oidc:offline';

export function categoryKey(category: DataCategory): string {
	return `oidc:${category}`;
}

export function resourceKey(indicator: string, scope: string): string {
	// An indicator carries no space or fragment (RFC 8707 §2) and a scope token no space (RFC 6749 §3.3).
	return `resource:${indicator} ${scope}`;
}

export function consentChoices({
	details,
	partial,
	device
}: {
	details: PromptDetails;
	partial: boolean;
	device: boolean;
}): ConsentChoices {
	const fixed: ConsentChoices['fixed'] = {
		scopes: [],
		claims: [],
		resourceScopes: {}
	};
	const selectable: SelectableItem[] = [];
	const byKey = new Map<string, SelectableItem>();
	const item = (key: string): SelectableItem => {
		let found = byKey.get(key);
		if (!found) {
			found = { key, scopes: [], claims: [] };
			byKey.set(key, found);
			selectable.push(found);
		}
		return found;
	};

	for (const scope of details.missingOIDCScope ?? []) {
		if (FIXED_SCOPES.has(scope)) {
			fixed.scopes.push(scope);
			continue;
		}
		const category = SELECTABLE_STANDARD[scope];
		if (category) item(categoryKey(category)).scopes.push(scope);
		else if (scope === 'offline_access') item(OFFLINE_KEY).scopes.push(scope);
		else item(`scope:${scope}`).scopes.push(scope);
	}

	for (const claim of details.missingOIDCClaims ?? []) {
		const category = claimCategory(claim);
		if (
			PROTOCOL_CLAIMS.has(claim) ||
			(category && FIXED_CATEGORIES.has(category))
		) {
			fixed.claims.push(claim);
		} else if (category) {
			item(categoryKey(category)).claims.push(claim);
		} else {
			item(`claim:${claim}`).claims.push(claim);
		}
	}

	for (const [indicator, scopes] of Object.entries(
		details.missingResourceScopes ?? {}
	)) {
		for (const scope of scopes) {
			// The administrative MCP's only scope: it is the sign-in to that resource, not a permission within it.
			if (scope === 'openid') {
				(fixed.resourceScopes[indicator] ??= []).push(scope);
				continue;
			}
			const entry = item(resourceKey(indicator, scope));
			entry.resource = indicator;
			entry.scopes.push(scope);
		}
	}

	return {
		active: partial && !device && selectable.length >= 2,
		fixed,
		selectable,
		rar: details.rar ?? []
	};
}
