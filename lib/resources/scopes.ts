/*
 * What a declared resource may say it recognises.
 *
 * Single-sourced here because two consumers must agree: the route refuses these values, and the
 * console warns about them at the point of entry. A console that warned about a different set than the
 * route enforces would teach an operator the wrong rule.
 *
 * The reason any of this is checked at all is that a scope list is not a menu. A client given no scope
 * guidance requests every scope the resource advertises — the MCP specification says so explicitly, and
 * says it is deliberate, because a general-purpose agent has no way to choose among names it does not
 * understand. So an omnibus scope is not shorthand for "everything is available"; it is a grant of
 * everything to every client that ever arrives.
 */

/*
 * Refused outright rather than warned about. These names mean "all of it" in every scope vocabulary
 * anyone has published, and the specification's own list of common mistakes names wildcard and omnibus
 * scopes first.
 */
export const OMNIBUS_SCOPES: readonly string[] = [
	'*',
	'all',
	'any',
	'full',
	'full-access',
	'full_access',
	'everything'
];

export type ScopeFailure =
	'empty' | 'blank_value' | 'contains_space' | 'omnibus' | 'duplicate';

export type ScopeValidation =
	| { readonly ok: true; readonly scopes: string[] }
	| {
			readonly ok: false;
			readonly reason: ScopeFailure;
			readonly value?: string;
	  };

/*
 * A result rather than a throw, and the offending value carried with the reason — an operator who
 * submitted twelve scopes needs to know which one was refused, not that "scopes are invalid".
 */
export function validateScopes(scopes: readonly string[]): ScopeValidation {
	if (scopes.length === 0) return { ok: false, reason: 'empty' };

	const seen = new Set<string>();
	for (const scope of scopes) {
		if (scope.trim().length === 0) {
			return { ok: false, reason: 'blank_value', value: scope };
		}
		/*
		 * A scope carrying a space would be two scopes the moment the list is joined for the wire, so a
		 * resource could declare one name and advertise two. Refused here, at the only place the array
		 * form is ever accepted.
		 */
		if (scope.includes(' ')) {
			return { ok: false, reason: 'contains_space', value: scope };
		}
		if (OMNIBUS_SCOPES.includes(scope.toLowerCase())) {
			return { ok: false, reason: 'omnibus', value: scope };
		}
		if (seen.has(scope)) {
			return { ok: false, reason: 'duplicate', value: scope };
		}
		seen.add(scope);
	}

	return { ok: true, scopes: [...scopes] };
}

/* What the operator reads. Held beside the rule so the two cannot drift. */
export function scopeFailureMessage(
	reason: ScopeFailure,
	value?: string
): string {
	switch (reason) {
		case 'empty':
			return 'a resource must recognise at least one scope';
		case 'blank_value':
			return 'a scope cannot be blank';
		case 'contains_space':
			return `a scope cannot contain a space: ${JSON.stringify(value)}`;
		case 'omnibus':
			return `${JSON.stringify(value)} grants everything to every client that arrives, because a client given no scope guidance requests the whole list; name the scopes the resource actually distinguishes`;
		case 'duplicate':
			return `scope listed twice: ${JSON.stringify(value)}`;
	}
}
