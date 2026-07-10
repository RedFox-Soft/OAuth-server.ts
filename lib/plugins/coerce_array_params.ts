import { Elysia } from 'elysia';

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === 'object' && value !== null;
}

/**
 * Elysia plugin: coerce the named single-valued parameters to arrays before schema validation.
 *
 * Form-encoded bodies (and single query values) deliver a bare string even when the route schema
 * types the field as an array — e.g. `resource`, `ui_locales`. This normalizes each such value to a
 * one-element array so a strict schema accepts it. Values already parsed as arrays (repeated form
 * fields / query keys) are left untouched.
 *
 * Runs at the `transform` lifecycle stage (before validation) and is scoped so it applies to the
 * routes of the instance that mounts it:
 *
 *   new Elysia().use(coerceArrayParams('resource', 'ui_locales')).post(...)
 */
export function coerceArrayParams(...keys: string[]) {
	const coerce = (target: unknown) => {
		if (!isRecord(target)) return;
		for (const key of keys) {
			if (typeof target[key] === 'string') {
				target[key] = [target[key]];
			}
		}
	};

	return new Elysia().onTransform({ as: 'scoped' }, ({ body, query }) => {
		coerce(body);
		coerce(query);
	});
}
