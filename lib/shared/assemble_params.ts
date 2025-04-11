import Params from '../helpers/params.ts';

export default function assembleParams(allowList, ctx, next) {
	const params = ctx.method === 'POST' ? ctx.oidc.body : ctx.query;
	ctx.oidc.params = new (Params(allowList))(params);
	return next();
}

export function assembleParamsMidddleware(endpointName: string) {
	return async (ctx, next) => {
		const params = ctx.method === 'POST' ? ctx.oidc.body : ctx.query;
		ctx.oidc.params = new (Params(endpointName))(params);
		return next();
	};
}
