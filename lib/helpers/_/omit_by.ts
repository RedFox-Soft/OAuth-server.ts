export default (
	object: Record<string, unknown>,
	predicate: (value: unknown, key: string) => boolean
) => {
	Object.entries(object).forEach(([key, value]) => {
		if (predicate(value, key)) {
			delete object[key];
		}
	});

	return object;
};
