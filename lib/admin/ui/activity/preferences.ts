/*
 * How the usage dashboard was last arranged in this browser (specs/077, FR-016): a convenience, never state
 * anything depends on. Browser storage can be absent, full or refused — a private window, blocked site data —
 * so every access is guarded and any failure means the defaults. The month is deliberately not kept: the
 * page always opens on the current month, where an operator expects to start.
 */

export interface UsagePreferences {
	view: 'bucket' | 'customer';
	hideInactive: boolean;
	hideReserved: boolean;
	hideDeleted: boolean;
	sort: { column: string; order: 'ascend' | 'descend' } | null;
}

const KEY = 'oauth-admin.usage.v1';

export const DEFAULT_PREFERENCES: UsagePreferences = {
	view: 'bucket',
	hideInactive: false,
	hideReserved: false,
	hideDeleted: false,
	sort: null
};

function isPreferences(value: unknown): value is UsagePreferences {
	if (typeof value !== 'object' || value === null) return false;
	// A non-null object read as a bag of unknowns; every field is narrowed below before it is trusted.
	const v = value as Record<string, unknown>;
	return (
		(v.view === 'bucket' || v.view === 'customer') &&
		typeof v.hideInactive === 'boolean' &&
		typeof v.hideReserved === 'boolean' &&
		typeof v.hideDeleted === 'boolean'
	);
}

export function loadPreferences(): UsagePreferences {
	try {
		const raw = window.localStorage.getItem(KEY);
		if (raw === null) return DEFAULT_PREFERENCES;
		const parsed: unknown = JSON.parse(raw);
		return isPreferences(parsed)
			? { ...DEFAULT_PREFERENCES, ...parsed }
			: DEFAULT_PREFERENCES;
	} catch {
		return DEFAULT_PREFERENCES;
	}
}

export function savePreferences(preferences: UsagePreferences): void {
	try {
		window.localStorage.setItem(KEY, JSON.stringify(preferences));
	} catch {
		/* Not remembered this time; the page works the same. */
	}
}
