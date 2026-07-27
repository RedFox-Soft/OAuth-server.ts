import EventEmitter from 'node:events';

import Configuration from './helpers/configuration.ts';
import * as instance from './helpers/weak_cache.ts';
// Side-effect import: reading the key store is asynchronous, so this module resolves the keys and
// populates configs/keystore.ts (which the models import for signing) behind a top-level await.
// The provider does not own the keys — it is the server's boot point, and every entry path
// constructs it, which is what makes it the reliable place to guarantee they are loaded.
import './configs/keys.js';
// Load-order anchor, not a dependency of this module. The models and the provider are mutually
// cyclic (base_token -> base_model -> this module), and id_token happens to pull that graph in an
// order where base_token finishes evaluating before grant.ts reads BaseTokenPayload from it.
// provider.ts used to get this for free by importing initialize_app (-> response_modes/jwt ->
// id_token) at this position; that import is gone, so the anchor is now explicit. Remove it only
// together with the underlying model/provider cycle.
import './models/id_token.js';
import { OIDCProviderError } from './helpers/errors.ts';
import { BackchannelAuthenticationRequest } from './models/backchannel_authentication_request.js';
import { Client } from './models/client.js';
import { Grant } from './models/grant.js';

class ProviderClass extends EventEmitter {
	#int = {};

	constructor() {
		super();
		this.init();
	}

	// No configuration argument: every option lives on ApplicationConfig, ClientDefaults, or the
	// addon registry. Signing keys are not part of this either — the keystore and the published
	// JWKS are module state on configs/keys.ts, single-sourced from the jwksStore adapter and
	// rebuilt by reloadJWKSKeys(), the same way ApplicationConfig is module state.
	init() {
		const configuration = new Configuration();

		instance.set(this, this.#int);

		this.#int.configuration = configuration;

		return this;
	}

	urlFor(name, opt) {
		return new URL(this.pathFor(name, opt), this.issuer).href;
	}

	pathFor(name, { mountPath = '', ...opts } = {}) {
		const routerUrl = this.#int.router.url(name, opts);

		if (routerUrl instanceof Error) {
			throw routerUrl;
		}

		return [mountPath, routerUrl].join('');
	}

	async backchannelResult(
		request,
		result,
		{ acr, amr, authTime, sessionUid, expiresWithSession, sid } = {}
	) {
		if (typeof request === 'string' && request) {
			request = await BackchannelAuthenticationRequest.find(request, {
				ignoreExpiration: true,
				error: new Error('BackchannelAuthenticationRequest not found')
			});
		} else if (!(request instanceof BackchannelAuthenticationRequest)) {
			throw new TypeError('invalid "request" argument');
		}

		const client = await Client.find(request.payload.clientId, {
			error: new Error('Client not found')
		});

		if (typeof result === 'string' && result) {
			result = await Grant.find(result, {
				error: new Error('Grant not found')
			});
		}

		switch (true) {
			case result instanceof Grant:
				if (request.payload.clientId !== result.payload.clientId) {
					throw new Error('client mismatch');
				}

				if (request.payload.accountId !== result.payload.accountId) {
					throw new Error('accountId mismatch');
				}

				Object.assign(request.payload, {
					grantId: result.jti,
					acr,
					amr,
					authTime,
					sessionUid,
					expiresWithSession,
					sid
				});
				break;
			case result instanceof OIDCProviderError:
				Object.assign(request.payload, {
					error: result.error,
					errorDescription: result.error_description
				});
				break;
			default:
				throw new TypeError('invalid "result" argument');
		}

		await request.save();

		if (client.backchannelTokenDeliveryMode === 'ping') {
			await client.backchannelPing(request);
		}
	}
}

export const provider = new ProviderClass();
