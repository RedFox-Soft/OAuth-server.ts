import { mapValueError, ValidationError } from 'elysia';
import { TransformDecodeCheckError } from '@sinclair/typebox/value';
import { OIDCProviderError } from '../helpers/errors.ts';
import { isPlainObject } from 'lib/helpers/_/object.js';
import { responseModes } from 'lib/response_modes/index.js';
import { send } from 'lib/response_modes/describe.js';
import { redirectUrisVouchedFor } from 'lib/models/client.js';
import { confirmationPage } from 'lib/interactions/confirmationPage.js';
import { captureFault } from 'lib/error_store/capture.js';
import type { OIDCContext } from 'lib/helpers/oidc_context.js';
import type { PipelineParams } from 'lib/consts/param_list.js';
import type { ErrorSurface } from 'lib/adapters/types.js';

/*
 * Returning an authorization error to the client, wherever the request ended.
 *
 * RFC 6749 §4.1.2.1 and OIDC Core §3.1.2.6 deliver a failed authorization request to the client's
 * redirect URI, and a request can end in two places: at the authorization endpoint, or after the end
 * user has been handed to the interaction pages and the stored request is resumed. Each of those used
 * to carry its own copy of this — and the two copies already disagreed about the response mode — while
 * every other way a resumed request could end was rendered to the browser and never reached the
 * client. The callers differ only in where the request comes from; everything below is the same rule.
 *
 * Deliberately free of the interaction pages and of the shared error handler: both import this, and
 * the handler is loaded by the root app before the interaction routes are mounted.
 */

/*
 * The first schema violation behind a VALIDATION code, if there is one. Elysia reports two kinds under
 * that code: its own ValidationError, and TypeBox's TransformDecodeCheckError when a member fails to
 * decode (a query value that is not the JSON its schema expects), which carries the violation inside.
 */
export function getFirstError(
	error: unknown
): { path: string; schemaError: unknown; summary?: string } | undefined {
	if (error instanceof ValidationError) {
		const first = mapValueError(error.valueError);
		return (
			first && {
				path: first.path,
				schemaError: first.schema.error,
				summary: first.summary
			}
		);
	}
	if (error instanceof TransformDecodeCheckError) {
		const { path, schema, message } = error.error;
		return { path, schemaError: schema.error, summary: message };
	}
	return undefined;
}

export function getObjFromError(
	code: string | number,
	errorObj: unknown
): { error: string; error_description?: string } {
	if (errorObj instanceof OIDCProviderError) {
		const { error, error_description } = errorObj;
		return { error, ...(error_description ? { error_description } : {}) };
	}
	if (code === 'VALIDATION') {
		const firstError = getFirstError(errorObj);
		/*
		 * A schema names the refusal for a member in one of two shapes (lib/consts/param_list.ts): a
		 * description, answered as invalid_request, or the whole `{ error, error_description }`.
		 */
		const schemaError = firstError?.schemaError;
		if (typeof schemaError === 'string' && schemaError) {
			return {
				error: 'invalid_request',
				error_description: schemaError
			};
		}
		if (isPlainObject(schemaError) && typeof schemaError.error === 'string') {
			const { error, error_description } = schemaError;
			return {
				error,
				...(typeof error_description === 'string' ? { error_description } : {})
			};
		}
		const error_description = firstError?.summary || 'Validation error';
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

/*
 * RFC 6749 §4.1.2.1: `error_description` MUST NOT hold characters outside %x20-21 / %x23-5B / %x5D-7E.
 *
 * Enforced here rather than at each message, because the descriptions are partly made of what the
 * request sent — a duplicated parameter's own name, a schema's summary of a value — so no review of
 * today's messages can keep it true. Each run of refused characters becomes one space, so words they
 * separated stay apart; a description with nothing printable left is omitted rather than sent empty.
 * Only the redirect parameter is restricted: a JSON body or an error page has no such grammar.
 */
export function restrictDescription(description: string): string | undefined {
	const restricted = description
		.replace(/[^\x20\x21\x23-\x5b\x5d-\x7e]+/g, ' ')
		.trim();
	return restricted || undefined;
}

/*
 * An error that has opted out of ever being redirected — a rate-limit refusal, the refusal of the
 * redirect URI itself — is answered where it was raised, whichever step raised it.
 */
export function refusesRedirect(error: unknown): boolean {
	return (
		typeof error === 'object' &&
		error !== null &&
		'allow_redirect' in error &&
		error.allow_redirect === false
	);
}

export type DeliveryCapture = {
	surface: ErrorSurface;
	/* The route pattern, never the concrete path: a uid in it would make every occurrence its own group. */
	route: string;
	request: Request;
	submittedFields?: string[];
};

/*
 * Delivers an error to `redirectUri`, in the response mode the request asked for.
 *
 * The caller has already established that the redirect URI is one this client registered; nothing
 * here re-checks it, because the two callers know it in different ways.
 */
export async function deliverAuthorizationError(
	oidc: OIDCContext<PipelineParams>,
	redirectUri: string,
	code: string | number,
	error: unknown,
	capture: DeliveryCapture
): Promise<Response> {
	const body = getObjFromError(code, error);
	const description =
		body.error_description === undefined
			? undefined
			: restrictDescription(body.error_description);
	const state = oidc.params.state;
	const out = {
		error: body.error,
		...(description ? { error_description: description } : {}),
		...(typeof state === 'string' && state ? { state } : {}),
		// The issuer of the bucket the request began at, which is the one the client discovered (RFC 9207).
		iss: oidc.issuer
	};

	const requested = oidc.responseMode;
	const describe =
		(requested !== undefined && responseModes.describe(requested)) ||
		responseModes.describe('query');
	if (!describe) {
		throw new Error('the query response mode is always available');
	}
	const answer = await describe(oidc, redirectUri, out);

	/*
	 * RFC 9700 §4.11.2: the server "SHOULD only automatically redirect the user agent if it trusts the
	 * redirection URI", and otherwise "MAY inform the user and rely on the user". Trust is read as the
	 * section's editors state it — by how the redirect URI was registered — so an error for a client an
	 * operator created is redirected at once, before sign-in or after, as OAuth 2.1 §4.1.2.1 delivers it;
	 * an error for a self-registered or document-described client is offered, never sent. Without this,
	 * such a client is three ways of sending anyone to its site from this server's address: a malformed
	 * request, a request the user declines, and a silent one.
	 */
	const response = (await redirectUrisVouchedFor(oidc.client))
		? send(oidc, answer)
		: confirmationPage({ answer, error: body.error, redirectUri });

	/*
	 * A fault reported to the client still has to be findable by the operator, and the shared handler's
	 * record is never reached once the error has been answered by redirect. Recorded only now that the
	 * delivery has succeeded: a delivery that fails goes back to the shared handler, which records the
	 * fault itself — so it is one record either way, never two.
	 *
	 * Filed at 500, the status the fault carries, not the redirect's 303: the store's whole criterion is
	 * "5xx", and a fault filed under a redirect status would vanish from every view an operator filters.
	 * The reference `captureFault` returns is not added to the response — a diagnostic handle in a URL
	 * reaches browser history and the client.
	 */
	if (body.error === 'server_error') {
		captureFault({
			surface: capture.surface,
			route: capture.route,
			method: capture.request.method,
			status: 500,
			errorCode: 'server_error',
			error,
			headers: capture.request.headers,
			submittedFields: capture.submittedFields
		});
	}

	return response;
}
