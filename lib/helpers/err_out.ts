export default (
	{
		expose,
		message,
		error_description: description,
		scope
	}: {
		expose?: boolean;
		message?: string;
		error_description?: string;
		scope?: string;
	},
	state?: unknown
) => {
	if (expose) {
		return {
			error: message,
			...(description !== undefined
				? { error_description: description }
				: undefined),
			...(scope !== undefined ? { scope } : undefined),
			...(state !== undefined ? { state } : undefined)
		};
	}
	return {
		error: 'server_error',
		error_description: 'oops! something went wrong',
		...(state ? { state } : undefined)
	};
};
