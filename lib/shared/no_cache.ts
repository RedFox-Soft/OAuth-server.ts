import type { Elysia } from 'elysia';

export default async function noCache(ctx, next) {
	ctx.set('cache-control', 'no-store');
	await next();
}

export const nocache = (app: Elysia) => {
	return app.onRequest(({ set }) => {
		set.headers['Surrogate-Control'] = 'no-store';
		set.headers['Cache-Control'] =
			'no-store, no-cache, must-revalidate, proxy-revalidate';
		set.headers['Expires'] = '0';
	});
};
