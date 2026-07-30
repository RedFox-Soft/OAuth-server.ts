import { type Elysia, NotFoundError } from 'elysia';

import { ApplicationConfig } from 'lib/configs/application.js';
import { eventBus } from 'lib/event_bus.js';
import {
	type FeatureFlagKey,
	gatedFlagForRequest
} from 'lib/consts/route_classification.js';

/*
 * Carries the governing flag so the global error handler can tell a deliberate refusal from a genuine
 * unrouted request, without re-deriving the gate's decision from the request path. Extends
 * NotFoundError so it inherits `code = 'NOT_FOUND'` and flows through exactly the code path an
 * unserved path takes — which is what makes the two responses identical rather than merely similar.
 */
export class FeatureDisabled extends NotFoundError {
	readonly flag: FeatureFlagKey;

	constructor(flag: FeatureFlagKey) {
		super();
		this.flag = flag;
	}
}

/*
 * Avoids constructing a URL object on every request to the server. `Request.url` is always an
 * absolute http(s) URL, so the path begins at the first '/' after the scheme separator; fragments are
 * never transmitted, so only the query needs trimming.
 */
function pathnameOf(url: string): string {
	const start = url.indexOf('/', url.indexOf('://') + 3);
	if (start === -1) {
		return '/';
	}
	const query = url.indexOf('?', start);
	return query === -1 ? url.slice(start) : url.slice(start, query);
}

/*
 * Refuses requests to endpoints whose governing capability is switched off, answering exactly as the
 * server answers for a path it does not serve.
 *
 * Mounted on onRequest, which is the only lifecycle stage ahead of client authentication, body
 * parsing and schema validation — so a switched-off endpoint cannot leak a 401 challenge or a 422
 * describing its own request contract. It must be mounted AFTER the nocache plugin: onRequest hooks
 * run in registration order and a throw short-circuits the rest of the chain, so gating first would
 * omit the `Cache-Control: no-store` that every other response on the server carries, leaving a
 * one-header fingerprint that distinguishes "disabled" from "absent".
 *
 * The flag is read flat off ApplicationConfig per request rather than captured at boot: settings are
 * applied by restart in a deployment, but the test suite drives one long-lived instance and flips
 * them between cases.
 */
export const featureGate = (app: Elysia) =>
	app.onRequest(({ request }) => {
		const path = pathnameOf(request.url);
		const flag = gatedFlagForRequest(request.method, path);

		if (flag === undefined || ApplicationConfig[flag]) {
			return;
		}

		// The operator's only way to diagnose an unexpected 404, since the response deliberately
		// says nothing. Carries no headers, body or credentials: a disabled endpoint is still
		// probed with real secrets, and this is the one place they could reach a log.
		eventBus.emit('feature_disabled', { method: request.method, path, flag });

		throw new FeatureDisabled(flag);
	});
