export function pick<T>(
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

/*
 * Object.entries typed the way the values really read. TypeScript's own declaration drops `undefined`
 * from an optional member, so a loop treating a present-but-undefined member as "remove this field" —
 * the stores' patch contract — looks to the checker like a test that can never pass.
 */
export function entriesOf(object: object): [string, unknown][] {
	return Object.entries(object);
}

/*
 * Array.isArray, typed the way its answer is meant: TypeScript's own declaration narrows to `any[]`, which
 * turns an unknown value into one nothing checks, and a readonly array into one that loses its element
 * type. From a union this keeps the array member; from an unknown it gives readonly unknown[].
 */
export function isList(value: unknown): value is readonly unknown[] {
	return Array.isArray(value);
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
