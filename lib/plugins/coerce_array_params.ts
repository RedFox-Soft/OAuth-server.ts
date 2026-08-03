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

/**
 * Elysia plugin: parse the named parameters from a JSON string to their real value before schema
 * validation.
 *
 * The sibling of coerceArrayParams for a parameter whose wire form is a JSON *document* rather than a
 * repeated field — `authorization_details` (RFC 9396 §2). A query value is coerced by Elysia's own
 * parser, but a form-encoded body is not: the string is walked character by character and arrives as
 * one object per character, with no error, so a strict array schema accepts complete nonsense. Since
 * PAR is form-encoded, that silently corrupted every pushed rich authorization request.
 *
 * A value that is already parsed (PAR replay, a request object) is left untouched, and a string that
 * is not valid JSON is left as-is so the route's own validation reports it rather than this plugin.
 */
export function parseJsonParams(...keys: string[]) {
	const parse = (target: unknown) => {
		if (!isRecord(target)) return;
		for (const key of keys) {
			const value = target[key];
			if (typeof value !== 'string') continue;
			try {
				target[key] = JSON.parse(value);
			} catch {
				// Left as a string: the schema refuses it and the error handler maps that to
				// invalid_request, which is the right answer for an unparseable request parameter.
			}
		}
	};

	return new Elysia().onTransform({ as: 'scoped' }, ({ body, query }) => {
		parse(body);
		parse(query);
	});
}
