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
