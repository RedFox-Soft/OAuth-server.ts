import type { Context } from 'elysia';
import { InvalidRequest } from 'lib/helpers/errors.js';

export const noQueryDup = (allowList: string[] = []) => {
	const allowListSet = new Set<string>(allowList);

	return ({ request, query }: Context) => {
		const url = new URL(request.url);
		const params = new URLSearchParams(url.search);
		const keys = new Set<string>();

		for (const [key] of params) {
			if (allowListSet.has(key)) {
				continue;
			}
			if (params.getAll(key).length > 1) {
				keys.add(key);
				delete query[key];
			}
		}

		if (keys.size > 0) {
			throw new InvalidRequest(
				`Duplicate query parameter "${Array.from(keys).join(', ')}" detected`
			);
		}
	};
};
