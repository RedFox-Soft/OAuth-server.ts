import type { Elysia } from 'elysia';

export const nocache = (app: Elysia) => {
	return app.onRequest(({ set }) => {
		set.headers['Surrogate-Control'] = 'no-store';
		set.headers['Cache-Control'] = 'no-store';
	});
};
