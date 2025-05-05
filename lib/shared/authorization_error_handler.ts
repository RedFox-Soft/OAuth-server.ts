import { provider } from 'lib/provider.js';
import instance from '../helpers/weak_cache.ts';
import errOut from '../helpers/err_out.ts';
import oneRedirectUriClients from '../actions/authorization/one_redirect_uri_clients.ts';
import { OIDCProviderError } from '../helpers/errors.ts';
import { getErrorHtmlResponse } from '../html/error.tsx';
import { routeNames } from 'lib/consts/param_list.js';
import { mapValueError } from 'elysia';

async function isAllowRedirectUri(params) {
	const ctx = {};
	const OIDCContext = provider.OIDCContext;
	ctx.oidc = new OIDCContext(ctx);
	ctx.oidc.params = params;

	if (!params.client_id) {
		return null;
	}
	const client = await provider.Client.find(params.client_id);
	if (!client) {
		return null;
	}
	ctx.oidc.entity('Client', client);

	let redirect_uri = params.redirect_uri;
	if (!redirect_uri) {
		oneRedirectUriClients(ctx);
		redirect_uri = params.redirect_uri;
	}
	if (!redirect_uri || !client.redirectUriAllowed(redirect_uri)) {
		return null;
	}

	const state = params.state;

	return { redirect_uri, state };
}

const mapErrorCode = {
	[routeNames.token]: 'grant.error',
	[routeNames.authorization]: 'authorization.error'
};

export async function errorHandler(obj) {
	const { error, set, route, code, request } = obj;
	if (set.status === 500) {
		provider.emit('server_error', error);
	} else {
		const key = mapErrorCode[route] ?? 'server_error';
		provider.emit(key, error);
	}

	if (route === routeNames.authorization) {
		const redirect = await authorizationErrorHandler(obj);
		if (redirect) {
			return redirect;
		}
	}

	let errorObj = {
		error: 'server_error',
		error_description: 'An unexpected error occurred'
	};
	const isOIDError = error instanceof OIDCProviderError;
	if (isOIDError) {
		set.status = error.status;
		errorObj = {
			error: error.error,
			error_description: error.error_description,
			error_detail: error.error_detail
		};
	}
	if (code === 'VALIDATION') {
		const firstError = error.validator.Errors(error.value).First();
		const error_description =
			mapValueError(firstError).summary || 'Validation error';
		errorObj = {
			error: 'invalid_request',
			error_description
		};
	}
	if (code === 'UNKNOWN' && !isOIDError) {
		console.error('Unknown error', error);
	}

	const accept = request.headers.get('accept') || '';
	if (accept.includes('text/html')) {
		return getErrorHtmlResponse(
			set.status,
			errorObj.error,
			errorObj.error_description
		);
	}
	return errorObj;
}

async function authorizationErrorHandler({
	error,
	query,
	body,
	redirect,
	request
}) {
	const params = request.method === 'POST' ? body : query;

	let redirectObj;
	try {
		redirectObj = await isAllowRedirectUri(params);
	} catch (e) {}

	if (redirectObj) {
		const out = { ...errOut(error, params.state), iss: provider.issuer };
		let mode = params.response_mode;
		if (!instance(provider).responseModes.has(mode)) {
			mode = 'query';
		}
		const handler = instance(provider).responseModes.get(mode);
		const url = await handler({}, params.redirect_uri, out);
		return redirect(url, 303);
	}
}
