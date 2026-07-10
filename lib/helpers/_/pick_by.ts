export default (
	object: Record<string, unknown>,
	predicate: (value: unknown, key: string) => boolean
) => {
	const result: Record<string, unknown> = {};
	Object.entries(object).forEach(([key, value]) => {
		if (predicate(value, key)) {
			result[key] = value;
		}
	});

	return result;
};
