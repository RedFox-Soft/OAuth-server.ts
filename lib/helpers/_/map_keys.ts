export default (
	object: Record<string, unknown>,
	iteratee: (value: unknown, key: string, object: Record<string, unknown>) => string
) => {
	const result: Record<string, unknown> = {};

	Object.entries(object).forEach(([key, value]) => {
		result[iteratee(value, key, object)] = value;
	});

	return result;
};
