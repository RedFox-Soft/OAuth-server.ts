export function pick<T extends unknown>(
	object: Record<string, T> = {},
	...properties: string[]
) {
	return properties.reduce<Record<string, T>>((obj, prop) => {
		if (Object.hasOwn(object, prop)) {
			obj[prop] = object[prop];
		}
		return obj;
	}, {});
}

export function isPlainObject(
	value: unknown
): value is Record<string, unknown> {
	return !!value && value.constructor === Object;
}

/*
 * An object read by member name, whatever its prototype. Request parameters are one: a parsed form
 * body may have no prototype, which isPlainObject (constructor === Object) refuses.
 */
export function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/* A member read off a value that may not be an object at all — a thrown error, a driver's row. */
export function member(value: unknown, name: string): unknown {
	return isRecord(value) ? value[name] : undefined;
}

export function merge(
	target: Record<string, unknown>,
	...sources: Record<string, unknown>[]
) {
	for (const source of sources) {
		if (!isPlainObject(source)) {
			continue;
		}
		for (const [key, value] of Object.entries(source)) {
			if (key === '__proto__' || key === 'constructor') {
				continue;
			}
			if (isPlainObject(target[key]) && isPlainObject(value)) {
				target[key] = merge(target[key], value);
			} else if (typeof value !== 'undefined') {
				target[key] = value;
			}
		}
	}

	return target;
}
