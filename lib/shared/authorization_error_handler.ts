import Debug from 'debug';

import { InvalidRedirectUri } from '../helpers/errors.ts';
import instance from '../helpers/weak_cache.ts';
import errOut from '../helpers/err_out.ts';
import oneRedirectUriClients from '../actions/authorization/one_redirect_uri_clients.ts';

const debug = new Debug('oidc-provider:authentication:error');
const serverError = new Debug('oidc-provider:server_error');
const serverErrorTrace = new Debug('oidc-provider:server_error:trace');

export default (provider) => {
	const AD_ACTA_CHECKS = Object.entries({
		redirect_uri: {
			Err: InvalidRedirectUri,
			method: 'redirectUriAllowed',
			check: 'redirectUriCheckPerformed',
			recovery: oneRedirectUriClients
		}
	});

	function getOutAndEmit(ctx, err, state) {
		const out = { ...errOut(err, state), iss: ctx.oidc.provider.issuer };

		if (err.expose) {
			provider.emit('authorization.error', ctx, err);
			debug('%o', out);
		} else {
			provider.emit('server_error', ctx, err);
			serverError('path=%s method=%s error=%o', ctx.path, ctx.method, err);
			serverErrorTrace(err);
		}

		return out;
	}

	function safe(param) {
		if (param && typeof param === 'string') {
			return param;
		}
		return undefined;
	}

	return async function authorizationErrorHandler(ctx, next) {
		try {
			await next();
		} catch (caught) {
			let err = caught;
			ctx.status = err.statusCode || 500;
			const { oidc } = ctx;

			const { params = (ctx.method === 'POST' ? oidc.body : ctx.query) || {} } =
				oidc;

			if (!oidc.client && safe(params.client_id) && !ctx.oidc.noclient) {
				try {
					oidc.entity(
						'Client',
						await provider.Client.find(safe(params.client_id))
					);
				} catch (e) {}
			}

			for (const [
				param,
				{ Err, check, flag, method, recovery }
			] of AD_ACTA_CHECKS) {
				if (
					(!flag || instance(provider).configuration[flag]) &&
					!(err instanceof Err) &&
					oidc.client &&
					!oidc[check]
				) {
					if (recovery && !safe(params[param])) {
						recovery(ctx, () => {});
					}

					if (safe(params[param]) && !oidc.client[method](params[param])) {
						getOutAndEmit(ctx, caught, safe(params.state));
						err = new Err();
						ctx.status = err.statusCode;
						break;
					}
				}
			}

			const out = getOutAndEmit(ctx, err, safe(params.state));

			// in case redirect_uri or client could not be verified no successful
			// response should happen, render instead
			if (
				!safe(params.client_id) ||
				(safe(params.client_id) && !oidc.client) ||
				!safe(params.redirect_uri) ||
				!err.allow_redirect
			) {
				const { renderError } = instance(provider).configuration;
				await renderError(ctx, out, err);
			} else {
				let mode = safe(params.response_mode);
				if (!instance(provider).responseModes.has(mode)) {
					mode = 'query';
				}
				const handler = instance(provider).responseModes.get(mode);
				await handler(ctx, safe(params.redirect_uri), out);
			}
		}
	};
};
