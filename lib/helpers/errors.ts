import upperFirst from './_/upper_first.ts';
import camelCase from './_/camel_case.ts';

export class OIDCProviderError extends Error {
	allow_redirect = true;
	error: string;
	error_description = '';
	error_detail?: string;
	status = 400;

	constructor(status: number, message: string) {
		super(message);
		this.name = this.constructor.name;
		this.message = message;
		this.error = message;
		this.status = status;
	}
}

export class CustomOIDCProviderError extends OIDCProviderError {
	constructor(message: string, description: string) {
		super(400, message);
		Error.captureStackTrace(this, this.constructor);
		Object.assign(this, { error_description: description });
	}
}

export class InvalidToken extends OIDCProviderError {
	error_description = 'invalid token provided';

	constructor(detail?: string) {
		super(401, 'invalid_token');
		Error.captureStackTrace(this, this.constructor);
		Object.assign(this, { error_detail: detail });
	}
}

export class InvalidClientMetadata extends OIDCProviderError {
	constructor(description: string, detail?: string) {
		const message = description.startsWith('redirectUris')
			? 'invalid_redirect_uri'
			: 'invalid_client_metadata';
		super(400, message);
		Error.captureStackTrace(this, this.constructor);
		Object.assign(this, {
			error_description: description,
			error_detail: detail
		});
	}
}

export class InvalidScope extends OIDCProviderError {
	constructor(description: string, scope: unknown, detail?: string) {
		super(400, 'invalid_scope');
		Error.captureStackTrace(this, this.constructor);
		Object.assign(this, {
			scope,
			error_description: description,
			error_detail: detail
		});
	}
}

export class InsufficientScope extends OIDCProviderError {
	constructor(description: string, scope: string, detail?: string) {
		super(403, 'insufficient_scope');
		Error.captureStackTrace(this, this.constructor);
		Object.assign(this, {
			scope,
			error_description: description,
			error_detail: detail
		});
	}
}

export class InvalidRequest extends OIDCProviderError {
	constructor(description?: string, code = 400, detail?: string) {
		super(code, 'invalid_request');
		Error.captureStackTrace(this, this.constructor);
		Object.assign(this, {
			error_description: description || 'request is invalid',
			error_detail: detail,
			expose: true
		});
	}
}

export class InvalidHeaderAuthorization extends OIDCProviderError {
	constructor(description = 'invalid header authorization', detail?: string) {
		super(401, 'invalid_header_authorization');
		Error.captureStackTrace(this, this.constructor);
		Object.assign(this, {
			error_description: description,
			error_detail: detail,
			expose: true
		});
	}
}

export class NotSupportedError extends OIDCProviderError {
	constructor(message = 'request is not supported') {
		super(400, 'not_supported');
		Error.captureStackTrace(this, this.constructor);
		Object.assign(this, {
			error_description: message
		});
	}
}

export class SessionNotFound extends InvalidRequest {}

export class InvalidClientAuth extends OIDCProviderError {
	error_description = 'client authentication failed';

	constructor(detail?: string) {
		super(401, 'invalid_client');
		Error.captureStackTrace(this, this.constructor);
		Object.assign(this, { error_detail: detail });
	}
}

export class InvalidGrant extends OIDCProviderError {
	error_description = 'grant request is invalid';

	constructor(detail?: string) {
		super(400, 'invalid_grant');
		Error.captureStackTrace(this, this.constructor);
		Object.assign(this, { error_detail: detail });
	}
}

export class InvalidRedirectUri extends OIDCProviderError {
	error_description =
		"redirect_uri did not match any of the client's registered redirectUris";

	allow_redirect = false;

	constructor() {
		super(400, 'invalid_redirect_uri');
		Error.captureStackTrace(this, this.constructor);
	}
}

function E(message: string, errorDescription?: string) {
	const klassName = upperFirst(camelCase(message));
	const klass = class extends OIDCProviderError {
		error_description = errorDescription;

		constructor(description?: string, detail?: string) {
			super(400, message);
			Error.captureStackTrace(this, this.constructor);

			if (description) {
				this.error_description = description;
			}

			if (detail) {
				this.error_detail = detail;
			}
		}
	};
	Object.defineProperty(klass, 'name', { value: klassName });
	return klass;
}

export const AccessDenied = E('access_denied');
export const AuthorizationPending = E(
	'authorization_pending',
	"authorization request is still pending as the end-user hasn't yet completed the user interaction steps"
);
export const ConsentRequired = E('consent_required');
export const ExpiredLoginHintToken = E('expired_login_hint_token');
export const ExpiredToken = E('expired_token');
export const InteractionRequired = E('interaction_required');
export const InvalidBindingMessage = E('invalid_binding_message');
export const InvalidAuthorizationDetails = E('invalid_authorization_details');
export const InvalidClient = E('invalid_client');
export const InvalidRequestObject = E('invalid_request_object');
export const InvalidRequestUri = E('invalid_request_uri');
export const InvalidSoftwareStatement = E('invalid_software_statement');
export const InvalidTarget = E(
	'invalid_target',
	'resource indicator is missing, or unknown'
);
export const InvalidUserCode = E('invalid_user_code');
export const LoginRequired = E('login_required');
export const MissingUserCode = E('missing_user_code');
export const RegistrationNotSupported = E('registration_not_supported');
export const RequestNotSupported = E('request_not_supported');
export const RequestUriNotSupported = E('request_uri_not_supported');
export const SlowDown = E(
	'slow_down',
	'you are polling too quickly and should back off at a reasonable rate'
);
export const TemporarilyUnavailable = E('temporarily_unavailable');
export const TransactionFailed = E('transaction_failed');
export const UnapprovedSoftwareStatement = E('unapproved_software_statement');
export const UnauthorizedClient = E('unauthorized_client');
export const UnknownUserId = E('unknown_user_id');
export const UnmetAuthenticationRequirements = E(
	'unmet_authentication_requirements'
);
export const UnsupportedGrantType = E(
	'unsupported_grant_type',
	'unsupported grant_type requested'
);
export const UnsupportedResponseMode = E(
	'unsupported_response_mode',
	'unsupported response_mode requested'
);

/*
 * A per-origin rate-limit refusal, raised from the onRequest hook (lib/plugins/rateLimit.ts) before
 * routing, client authentication or body parsing.
 *
 * WHY `temporarily_unavailable`. It is the closest registered OAuth code (RFC 6749 4.1.2.1). The
 * closed code list in 5.2 governs the 400 error response, not a 429 transport-level refusal, so
 * reusing it here is not a conformance deviation — and inventing an unregistered code would be.
 *
 * WHY `allow_redirect = false`, which is the load-bearing line in this class. The base class defaults
 * it to true, and lib/shared/authorization_error_handler.ts turns any redirectable error raised on
 * /auth into a redirect back to the client. For a rate-limit refusal that would be wrong twice over:
 * building the redirect means resolving and validating redirect_uri first, which is exactly the work
 * the refusal exists to avoid doing, and it would hand an attacker a redirect for free on an endpoint
 * they have already been told to stop calling.
 *
 * `retryAfterSeconds` and `rateClass` are carried for the handler and the log. Nothing else is: no
 * counter value, no allowance, no account or client identity — a refusal discloses that a limit was
 * reached and nothing further.
 */
export class RateLimited extends OIDCProviderError {
	allow_redirect = false;
	readonly retryAfterSeconds: number;
	readonly rateClass: string;

	constructor(
		retryAfterSeconds: number,
		rateClass: string,
		adminPlane = false
	) {
		super(429, 'temporarily_unavailable');
		Error.captureStackTrace(this, this.constructor);
		this.retryAfterSeconds = retryAfterSeconds;
		this.rateClass = rateClass;
		Object.assign(this, {
			error_description: `too many requests, retry after ${retryAfterSeconds} seconds`
		});
		/*
		 * Assigned only when true, never as `adminPlane = false`. The root handler stands aside on the
		 * *presence* of the property (`'adminPlane' in error`), so a field declared and left false would
		 * route every refusal on every surface into the admin plane's handler — which answers for none of
		 * them but /admin.
		 */
		if (adminPlane) {
			Object.assign(this, { adminPlane: true });
		}
	}
}
