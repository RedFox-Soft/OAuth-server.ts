import { InvalidRequest } from 'lib/helpers/errors.js';
import type { Context } from 'elysia';

export const contentType = (allowType = 'application/json') => {
	return ({ request }: Context) => {
		const contentType = request.headers.get('content-type') || '';
		if (!contentType.includes(allowType)) {
			const error = new InvalidRequest(
				`Only ${allowType} content-type bodies are supported`
			);
			error.allow_redirect = false;
			error.status = 415;
			throw error;
		}
	};
};
