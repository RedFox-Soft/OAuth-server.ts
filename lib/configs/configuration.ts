import { isPlainObject, merge } from '../helpers/_/object.js';
import * as formatters from '../helpers/formatters.ts';
// Type-only, so it adds no runtime edge back to the module that calls this one. ApplicationConfig
// declares every setting, which makes `typeof` it the exact type of what is being validated — a
// misspelled flag read below is a compile error rather than a silently-undefined lookup.
import type { ApplicationConfigType } from './application.js';
// A value import, but of a module that pulls in nothing but node:crypto and a type — so it adds no
// runtime edge back to application.js either.
import { isUsableNonceSecret } from './nonceSecret.js';

/*
 * The server settings that cannot be read straight off ApplicationConfig: collections turned into
 * Sets, and the values derived by cross-referencing scopes against claims. Everything else — every
 * feature flag and sub-option — is read flat from ApplicationConfig at its use site.
 */
export interface Configuration {
	scopes: Set<string>;
	acrValues: Set<string>;
	clientAuthMethods: Set<string>;
	claims: ClaimsConfig;
	grantTypes: Set<string>;
	claimsSupported: Set<string>;
}

/*
 * A configuration to validate: the live ApplicationConfig, or a candidate one destined for it.
 *
 * Deliberately ApplicationConfigType itself, with no index signature bolted on. An index signature
 * would let this file read a setting that does not exist and get `undefined` — a check that silently
 * never fires. Every static read below is therefore key-checked against the declared settings.
 */
export type ConfigurationInput = ApplicationConfigType;

/*
 * The claims map: claim name -> null for a standalone claim, and scope name -> either a list of
 * claim names or a map of them. The list form is unpacked into the map form during validation, so
 * entries are read back more loosely than they are written.
 */
type ClaimsConfig = Record<string, unknown>;

function toSet(name: string, value: unknown): Set<string> {
	if (value instanceof Set) {
		return new Set(value);
	}
	if (!Array.isArray(value)) {
		throw new TypeError(`${name} must be an Array or Set`);
	}
	return new Set(value);
}

function collectScopes(scopes: Set<string>, claims: ClaimsConfig) {
	const claimDefinedScopes: string[] = [];
	Object.entries(claims).forEach(([key, value]) => {
		if (isPlainObject(value) || Array.isArray(value)) {
			claimDefinedScopes.push(key);
		}
	});
	claimDefinedScopes.forEach((scope) => {
		if (typeof scope === 'string' && !scopes.has(scope)) {
			scopes.add(scope);
		}
	});
}

function unpackArrayClaims(claims: ClaimsConfig) {
	Object.entries(claims).forEach(([key, value]) => {
		if (Array.isArray(value)) {
			claims[key] = value.reduce<Record<string, null>>((accumulator, claim) => {
				const scope = accumulator;
				scope[claim] = null;
				return scope;
			}, {});
		}
	});
}

function ensureOpenIdSub(claims: ClaimsConfig) {
	const { openid } = claims;
	if (!isPlainObject(openid)) {
		// Previously an incidental "Cannot convert undefined or null to object" from Object.keys.
		// Same TypeError, but it names the setting at fault.
		throw new TypeError(
			'claims.openid must be an object or an array of claim names'
		);
	}
	if (!Object.keys(openid).includes('sub')) {
		openid.sub = null;
	}
}

function removeAcrIfEmpty(acrValues: Set<string>, claims: ClaimsConfig) {
	if (!acrValues.size) {
		delete claims.acr;
	}
}

function collectClaims(scopes: Set<string>, claims: ClaimsConfig): Set<string> {
	const claimsSupported = new Set<string>();
	scopes.forEach((scope) => {
		// Only the scopes that define claims contribute names. A scope whose entry is `null` is a
		// standalone claim, picked up by the pass below.
		const defined = claims[scope];
		if (isPlainObject(defined)) {
			Object.keys(defined).forEach(Set.prototype.add.bind(claimsSupported));
		}
	});

	Object.entries(claims).forEach(([key, value]) => {
		if (value === null) claimsSupported.add(key);
	});

	return claimsSupported;
}

function collectGrantTypes(
	config: ConfigurationInput,
	scopes: Set<string>
): Set<string> {
	const grantTypes = new Set(['authorization_code']);

	if (scopes.has('offline_access') || config['refreshToken.enabled']) {
		grantTypes.add('refresh_token');
	}

	if (config['clientCredentials.enabled']) {
		grantTypes.add('client_credentials');
	}

	if (config['deviceFlow.enabled']) {
		grantTypes.add('urn:ietf:params:oauth:grant-type:device_code');
	}

	if (config['ciba.enabled']) {
		grantTypes.add('urn:openid:params:grant-type:ciba');
	}

	return grantTypes;
}

// The five common data fields RFC 9396 §2 defines. `identifier` is single-valued, so a descriptor
// can only mark it required — fixing a permitted set of per-resource identifiers restricts nothing.
const RAR_LIST_FIELDS = ['actions', 'locations', 'datatypes', 'privileges'];
const RAR_COMMON_FIELDS = [...RAR_LIST_FIELDS, 'identifier'];

/*
 * A type descriptor is pure JSON so the whole map round-trips through configStore and the admin PUT;
 * the former shape was `{ validate: fn }`, which a catalog entry can never carry, and that is why the
 * feature was unconfigurable. A code-registered `validate` survives as an optional escape hatch for
 * semantics data cannot express.
 */
function checkRichAuthorizationRequests(config: ConfigurationInput) {
	if (config['richAuthorizationRequests.enabled']) {
		const types = config['richAuthorizationRequests.types'];
		if (!isPlainObject(types)) {
			throw new TypeError(
				'features.richAuthorizationRequests.types must be an object'
			);
		}

		// With no types every authorization_details value is rejected before any hook runs, so the
		// combination is never what an operator meant.
		if (!Object.keys(types).length) {
			throw new TypeError(
				'features.richAuthorizationRequests.types must declare at least one type when richAuthorizationRequests is enabled'
			);
		}

		for (const [k, v] of Object.entries(types)) {
			if (!isPlainObject(v)) {
				throw new TypeError(
					'features.richAuthorizationRequests.types attribute values must be objects'
				);
			}

			if (typeof v.label !== 'string' || !v.label.length) {
				throw new TypeError(
					`features.richAuthorizationRequests.types['${k}'].label must be a non-empty string`
				);
			}

			if (v.fields !== undefined) {
				if (!isPlainObject(v.fields)) {
					throw new TypeError(
						`features.richAuthorizationRequests.types['${k}'].fields must be an object`
					);
				}

				for (const [field, constraint] of Object.entries(v.fields)) {
					if (!RAR_COMMON_FIELDS.includes(field)) {
						throw new TypeError(
							`features.richAuthorizationRequests.types['${k}'].fields must only constrain ${RAR_COMMON_FIELDS.join(', ')}`
						);
					}
					if (!isPlainObject(constraint)) {
						throw new TypeError(
							`features.richAuthorizationRequests.types['${k}'].fields['${field}'] must be an object`
						);
					}
					if (
						constraint.required !== undefined &&
						typeof constraint.required !== 'boolean'
					) {
						throw new TypeError(
							`features.richAuthorizationRequests.types['${k}'].fields['${field}'].required must be a boolean`
						);
					}
					if (constraint.allowed !== undefined) {
						if (!RAR_LIST_FIELDS.includes(field)) {
							throw new TypeError(
								`features.richAuthorizationRequests.types['${k}'].fields['${field}'] must not declare allowed values`
							);
						}
						if (
							!Array.isArray(constraint.allowed) ||
							!constraint.allowed.length ||
							constraint.allowed.some(
								(value) => typeof value !== 'string' || !value.length
							)
						) {
							throw new TypeError(
								`features.richAuthorizationRequests.types['${k}'].fields['${field}'].allowed must be a non-empty array of non-empty strings`
							);
						}
					}
				}
			}

			if (
				v.allowUnknownFields !== undefined &&
				typeof v.allowUnknownFields !== 'boolean'
			) {
				throw new TypeError(
					`features.richAuthorizationRequests.types['${k}'].allowUnknownFields must be a boolean`
				);
			}

			const { validate } = v;
			if (
				validate !== undefined &&
				(typeof validate !== 'function' ||
					!['Function', 'AsyncFunction'].includes(validate.constructor.name))
			) {
				throw new TypeError(
					`features.richAuthorizationRequests.types['${k}'].validate must be a function`
				);
			}
		}
	}
}

function checkCibaDeliveryModes(config: ConfigurationInput) {
	const modes = config['ciba.deliveryModes'];
	if (!modes.length) {
		throw new TypeError('features.ciba.deliveryModes must not be empty');
	}

	for (const mode of modes) {
		if (!['ping', 'poll'].includes(mode)) {
			throw new TypeError(
				'only poll and ping CIBA delivery modes are supported'
			);
		}
	}
}

/*
 * The rate limiter's numbers, checked at boot because both ways of getting them wrong fail silently at
 * runtime: a non-positive allowance refuses every request, and a non-positive window makes every
 * request look like the first of a new one. Neither throws and neither logs, so a server misconfigured
 * either way looks healthy until someone reads the traffic.
 *
 * Checked even when the limiter is switched off. Skipping them for a disabled limiter would accept a
 * value at the moment it is written and refuse to boot months later, when an operator turns the
 * capability on and has no reason to connect the two events.
 */
function checkRateLimit(config: ConfigurationInput) {
	const positiveIntegers = [
		'rateLimit.maxTrackedOrigins',
		'rateLimit.strict.max',
		'rateLimit.strict.windowSeconds',
		'rateLimit.ordinary.max',
		'rateLimit.ordinary.windowSeconds',
		'rateLimit.public.max',
		'rateLimit.public.windowSeconds'
	] as const;

	for (const key of positiveIntegers) {
		const value = config[key];
		if (!Number.isSafeInteger(value) || (value as number) < 1) {
			// The key is named because an operator reading a failed boot has seven of these to choose from.
			throw new TypeError(`${key} must be a positive integer`);
		}
	}
}

function checkDependantFeatures(config: ConfigurationInput) {
	if (config['jwtIntrospection.enabled'] && !config['introspection.enabled']) {
		throw new TypeError(
			'jwtIntrospection is only available in conjuction with introspection'
		);
	}

	if (config['jwtUserinfo.enabled'] && !config['userinfo.enabled']) {
		throw new TypeError(
			'jwtUserinfo is only available in conjuction with userinfo'
		);
	}

	if (
		config['registrationManagement.enabled'] &&
		!config['registration.enabled']
	) {
		throw new TypeError(
			'registrationManagement is only available in conjuction with registration'
		);
	}

	if (
		config['registration.enabled'] &&
		config['registration.policies'] &&
		!config['registration.initialAccessToken']
	) {
		throw new TypeError(
			'registration policies are only available in conjuction with adapter-backed initial access tokens'
		);
	}

	if (
		config['richAuthorizationRequests.enabled'] &&
		!config['resourceIndicators.enabled']
	) {
		throw new TypeError(
			'richAuthorizationRequests is only available in conjuction with enabled resourceIndicators'
		);
	}

	checkDpopNonces(config);
}

/*
 * The two DPoP nonce invariants.
 *
 * Neither can fire during a healthy boot: configs/application.ts provisions a usable secret before it
 * calls this function, so by the time a configuration is validated the secret is already there. They
 * are here so the guarantee does not rest on that ordering holding forever. This is a pure function of
 * its argument, which means a test can hand it the state a running server cannot reach — and if
 * provisioning is ever reordered, moved, or made conditional, the boot fails here with a message
 * naming the setting instead of every DPoP request failing with an internal error.
 *
 * That was the defect: `dpop.requireNonce` was reachable from the admin UI, nothing cross-checked it
 * against the secret, and the result was a 500 on every request carrying a DPoP proof.
 *
 * Deliberately absent: a rule against requiring a nonce while `dpop.enabled` is false. With DPoP off
 * no proof is examined, so the requirement is inert and cannot fail.
 */
function checkDpopNonces(config: ConfigurationInput) {
	const secret = config['dpop.nonceSecret'];

	if (config['dpop.requireNonce'] && config['dpop.enabled'] && !secret) {
		throw new TypeError(
			'dpop.requireNonce needs a dpop.nonceSecret: the server cannot demand a nonce it has no ' +
				'secret to derive one from'
		);
	}

	// Checked whether or not a nonce is required, because the nonce generator is built for every
	// DPoP-bearing request: an unusable secret breaks all DPoP traffic, not only the nonce path.
	if (secret !== undefined && !isUsableNonceSecret(secret)) {
		throw new TypeError('dpop.nonceSecret must be a 32-byte Buffer instance');
	}
}

function checkAuthMethods(
	config: ConfigurationInput,
	clientAuthMethods: Set<string>
) {
	const authMethods = new Set([
		'none',
		'client_secret_basic',
		'client_secret_jwt',
		'client_secret_post',
		'private_key_jwt'
	]);

	if (config['mTLS.enabled'] && config['mTLS.tlsClientAuth']) {
		authMethods.add('tls_client_auth');
	}

	if (config['mTLS.enabled'] && config['mTLS.selfSignedTlsClientAuth']) {
		authMethods.add('self_signed_tls_client_auth');
	}

	clientAuthMethods.forEach((method) => {
		if (!authMethods.has(method)) {
			throw new TypeError(
				`only supported clientAuthMethods are ${formatters.formatList([...authMethods])}`
			);
		}
	});
}

const ORIGIN_CAPTURE_LEVELS = ['omitted', 'anonymized', 'full'];

/*
 * The error store's bounds, checked whether or not the capability is on.
 *
 * Unconditional deliberately, unlike checkDeviceFlow below: the bounds are what stop a switched-on
 * store from growing without limit, so a deployment must not be able to persist a nonsensical one
 * while the feature is off and have it take effect on the restart that enables it.
 */
function checkErrorStore(config: ConfigurationInput) {
	const bounds = [
		'errorStore.retentionDays',
		'errorStore.maxGroups',
		'errorStore.samplesPerGroup',
		'errorStore.queueDepth'
	] as const;

	for (const key of bounds) {
		const value = config[key];
		if (!Number.isInteger(value) || value < 1) {
			throw new TypeError(`${key} must be a positive integer`);
		}
	}

	if (
		!ORIGIN_CAPTURE_LEVELS.includes(config['errorStore.originCaptureLevel'])
	) {
		throw new TypeError(
			`errorStore.originCaptureLevel must be one of ${formatters.formatList([...ORIGIN_CAPTURE_LEVELS])}`
		);
	}
}

function checkDeviceFlow(config: ConfigurationInput) {
	if (config['deviceFlow.enabled']) {
		if (config['deviceFlow.charset'] !== undefined) {
			if (!['base-20', 'digits'].includes(config['deviceFlow.charset'])) {
				throw new TypeError(
					'only supported charsets are "base-20" and "digits"'
				);
			}
		}
		if (!/^[-* ]*$/.test(config['deviceFlow.mask'])) {
			throw new TypeError(
				'mask can only contain asterisk("*"), hyphen-minus("-") and space(" ") characters'
			);
		}
	}
}

/*
 * validateConfiguration
 *
 * Check a server configuration and return the values derived from it. Throws a TypeError on any
 * combination the server cannot run with — an unsupported client auth method, or a feature enabled
 * without the one it depends on.
 *
 * A pure function of the config passed in, deliberately: it neither reads nor writes the live
 * ApplicationConfig. That is what lets the admin settings API check a configuration it is *about*
 * to persist against the very same invariants the server enforces at boot, instead of maintaining
 * its own copy of them that can drift.
 *
 * `config.claims` is cloned before processing, so a caller's object is never mutated.
 */
export function validateConfiguration(
	config: ConfigurationInput
): Configuration {
	const scopes = toSet('scopes', config.scopes);
	const acrValues = toSet('acrValues', config.acrValues);
	const clientAuthMethods = toSet(
		'clientAuthMethods',
		config.clientAuthMethods
	);
	const claims = structuredClone(merge({}, config.claims));

	// Order is significant: each claims pass below builds on the one before it.
	collectScopes(scopes, claims);
	unpackArrayClaims(claims);
	ensureOpenIdSub(claims);
	removeAcrIfEmpty(acrValues, claims);
	const claimsSupported = collectClaims(scopes, claims);
	const grantTypes = collectGrantTypes(config, scopes);

	checkDependantFeatures(config);
	checkDeviceFlow(config);
	checkAuthMethods(config, clientAuthMethods);
	checkCibaDeliveryModes(config);
	checkRichAuthorizationRequests(config);
	checkErrorStore(config);
	checkRateLimit(config);

	return {
		scopes,
		acrValues,
		clientAuthMethods,
		claims,
		grantTypes,
		claimsSupported
	};
}
