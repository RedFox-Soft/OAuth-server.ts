import { provider } from 'lib/provider.js';
import instance, { get } from '../helpers/weak_cache.ts';
import { OIDCProviderError } from '../helpers/errors.ts';
import { getErrorHtmlResponse } from '../html/error.tsx';
import { routeNames } from 'lib/consts/param_list.js';
import {
	type Context,
	ErrorContext,
	mapValueError,
	ValidationError
} from 'elysia';
import { isAllowRedirectUri } from 'lib/actions/authorization/authorization.js';
import { ISSUER } from 'lib/configs/env.js';

function getFirstError(error: ValidationError) {
	const validator = error.validator ?? error.error.validator;
	const firstError =
		'Errors' in validator ? validator.Errors(error.value).First() : error;
	return firstError;
}

export default function getWWWAuthenticate(
	authorization: string,
	isDpop: boolean,
	errorObj: { error: string; error_description?: string }
) {
	let scheme = '';
	if (authorization.startsWith('dpop') || isDpop) {
		scheme = 'DPoP';
	} else if (authorization.startsWith('bearer')) {
		scheme = 'Bearer';
	} else {
		return;
	}
	const obj = {
		realm: ISSUER,
		...errorObj,
		...(scheme === 'DPoP'
			? {
					algs: instance(provider).configuration.dPoPSigningAlgValues.join(' ')
				}
			: undefined)
	};

	const wwwAuth = Object.entries(obj)
		.map(([key, val]) => `${key}="${val.replace(/"/g, '\\"')}"`)
		.join(', ');

	return `${scheme} ${wwwAuth}`;
}

function getObjFromError(code: string, errorObj: any) {
	if (errorObj instanceof OIDCProviderError) {
		const { error, error_description } = errorObj;
		return { error, ...(error_description ? { error_description } : {}) };
	}
	if (code === 'VALIDATION') {
		const firstError = getFirstError(errorObj);
		if (firstError.schema.error) {
			const schemaError = firstError.schema.error;
			if (typeof schemaError === 'string') {
				return {
					error: 'invalid_request',
					error_description: firstError.schema.error
				};
			}
			return schemaError;
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
	[routeNames.authorization]: 'authorization.error',
	[routeNames.device_authorization]: 'device_authorization.error',
	[routeNames.introspect]: 'introspection.error'
};

export async function errorHandler(obj: ErrorContext) {
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
	if (isOIDError && error.status === 401) {
		const auth = request.headers.get('authorization')?.toLowerCase() ?? '';
		const isDpop = !!request.headers.get('dpop');
		const authError = getWWWAuthenticate(auth, isDpop, errorObj);
		if (authError) {
			set.headers['WWW-Authenticate'] = authError;
		}
	}

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
	if (error instanceof ValidationError) {
		const firstError = getFirstError(error);
		if (
			firstError.path === '/redirect_uri' ||
			firstError.path === '/client_id'
		) {
			throw error;
		}
	}

	const params = request.method === 'POST' ? body : query;
	const redirectObj = await isAllowRedirectUri(params);

	const state = redirectObj.state;
	const out = {
		...getObjFromError(code, error),
		...(state ? { state } : {}),
		iss: ISSUER
	};
	let mode = params.response_mode;
	if (!instance(provider).responseModes.has(mode)) {
		mode = 'query';
	}
	const handler = instance(provider).responseModes.get(mode);
	return await handler(redirectObj.ctx, redirectObj.redirect_uri, out);
}
