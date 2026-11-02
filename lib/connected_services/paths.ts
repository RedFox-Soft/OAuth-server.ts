/*
 * The one way a connected service locates a value in a provider's JSON (specs/117 R6): a dotted path, with
 * `a|b` taking the first alternative that is present. Two shapes were observed (`authed_user.id`,
 * `team.id|enterprise.id`); anything richer would be an expression language with no requirement behind it.
 */

function at(document: unknown, path: string): unknown {
	let current: unknown = document;
	for (const part of path.split('.')) {
		if (
			typeof current !== 'object' ||
			current === null ||
			Array.isArray(current)
		) {
			return undefined;
		}
		current = (current as Record<string, unknown>)[part];
	}
	return current;
}

export function valueAt(document: unknown, path: string): unknown {
	for (const alternative of path.split('|')) {
		const value = at(document, alternative.trim());
		if (value !== undefined && value !== null && value !== '') return value;
	}
	return undefined;
}

/* A scalar as text, or undefined: an id or a label is never an object. */
export function textAt(document: unknown, path: string): string | undefined {
	const value = valueAt(document, path);
	if (typeof value === 'string') return value;
	if (typeof value === 'number' && Number.isFinite(value)) return String(value);
	return undefined;
}
