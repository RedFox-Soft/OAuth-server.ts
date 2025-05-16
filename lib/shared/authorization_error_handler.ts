import { provider } from 'lib/provider.js';
import instance from '../helpers/weak_cache.ts';
import oneRedirectUriClients from '../actions/authorization/one_redirect_uri_clients.ts';
import {
	InvalidClient,
	InvalidRedirectUri,
	OIDCProviderError
} from '../helpers/errors.ts';
import { getErrorHtmlResponse } from '../html/error.tsx';
import { routeNames } from 'lib/consts/param_list.js';
import { type Context, mapValueError, ValidationError } from 'elysia';

async function isAllowRedirectUri(params) {
	const ctx = {};
	const OIDCContext = provider.OIDCContext;
	ctx.oidc = new OIDCContext(ctx);
	ctx.oidc.params = params;

	if (!params.client_id) {
		throw new InvalidClient('client_id is required', 'client not found');
	}
	if (typeof params.client_id !== 'string') {
		throw new InvalidClient('client is invalid', 'client not found');
	}
	const client = await provider.Client.find(params.client_id);
	if (!client) {
		throw new InvalidClient('client is invalid', 'client not found');
	}
	ctx.oidc.entity('Client', client);

	let redirect_uri = params.redirect_uri;
	if (redirect_uri === undefined) {
		oneRedirectUriClients(ctx);
		redirect_uri = params.redirect_uri;
	}
	if (typeof redirect_uri !== 'string') {
		throw new InvalidRedirectUri();
	}
	if (!client.redirectUriAllowed(redirect_uri)) {
		throw new InvalidRedirectUri();
	}

	const state = typeof params.state !== 'string' ? undefined : params.state;

	return { redirect_uri, state };
}

function getObjFromError(code: string, errorObj: any) {
	if (errorObj instanceof OIDCProviderError) {
		const { error, error_description } = errorObj;
		return { error, ...(error_description ? { error_description } : {}) };
	}
	if (code === 'VALIDATION') {
		const validator = errorObj.validator ?? errorObj.error.validator;
		const firstError =
			'Errors' in validator
				? validator.Errors(errorObj.value).First()
				: errorObj;
		if (firstError.schema.error) {
			return {
				error: 'invalid_request',
				error_description: firstError.schema.error
			};
		}
		const error_description =
			mapValueError(firstError).summary || 'Validation error';
		return {
			error: 'invalid_request',
			error_description
		};
	}
	return {
		error: 'server_error',
		error_description: 'An unexpected error occurred'
	};
}

const mapErrorCode = {
	[routeNames.token]: 'grant.error',
	[routeNames.authorization]: 'authorization.error'
};

export async function errorHandler(obj) {
	const { set, route, code, request } = obj;
	let { error } = obj;
	if (set.status === 500) {
		provider.emit('server_error', error);
	} else {
		const key = mapErrorCode[route] ?? 'server_error';
		provider.emit(key, error);
	}

	if (route === routeNames.authorization && error.allow_redirect !== false) {
		try {
			return await authorizationErrorHandler(obj);
		} catch (e) {
			if (e instanceof OIDCProviderError) {
				error = e;
				const key = mapErrorCode[route] ?? 'server_error';
				provider.emit(key, error);
			} else {
				provider.emit('server_error', e);
			}
		}
	}

	const isOIDError = error instanceof OIDCProviderError;
	if (isOIDError) {
		set.status = error.status;
	}
	if (code === 'UNKNOWN' && !isOIDError) {
		console.error('Unknown error', error);
	}

	const accept = request.headers.get('accept') || '';
	let errorObj = getObjFromError(code, error);
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
	code,
	error,
	query,
	body,
	request
}: Context) {
	const params = request.method === 'POST' ? body : query;
	const redirectObj = await isAllowRedirectUri(params);

	const state = redirectObj.state;
	const out = {
		...getObjFromError(code, error),
		...(state ? { state } : {}),
		iss: provider.issuer
	};
	let mode = params.response_mode;
	if (!instance(provider).responseModes.has(mode)) {
		mode = 'query';
	}
	console.log('mode', mode);
	const handler = instance(provider).responseModes.get(mode);
	return await handler({}, redirectObj.redirect_uri, out);
}
