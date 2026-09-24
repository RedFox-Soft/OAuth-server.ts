import { isPlainObject } from './object.js';

// Fills each member of `target` still undefined from the sources, in order; deep into plain objects.
function defaults(
	deep: boolean,
	target: Record<string, unknown>,
	...sources: unknown[]
): Record<string, unknown> {
	for (const source of sources) {
		if (!isPlainObject(source)) {
			continue;
		}
		for (const [key, value] of Object.entries(source)) {
			if (key === '__proto__' || key === 'constructor') {
				continue;
			}
			if (typeof target[key] === 'undefined' && typeof value !== 'undefined') {
				target[key] = value;
			}

			if (deep && isPlainObject(target[key]) && isPlainObject(value)) {
				defaults(true, target[key], value);
			}
		}
	}

	return target;
}

export default defaults.bind(undefined, false);
export const deep = defaults.bind(undefined, true);
