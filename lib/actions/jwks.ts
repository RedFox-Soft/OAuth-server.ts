import instance from '../helpers/weak_cache.ts';

export default function renderJWKS(ctx) {
	const { keys } = instance(ctx.oidc.provider).jwks;
	ctx.body = { keys };
	ctx.type = 'application/jwk-set+json; charset=utf-8';
}
