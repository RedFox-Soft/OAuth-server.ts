import { isPlainObject, merge } from '../helpers/_/object.js';
import * as formatters from '../helpers/formatters.ts';
// Type-only, so it adds no runtime edge back to the module that calls this one. ApplicationConfig
// declares every setting, which makes `typeof` it the exact type of what is being validated — a
// misspelled flag read below is a compile error rather than a silently-undefined lookup.
import type { ApplicationConfigType } from './application.js';

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

function checkRichAuthorizationRequests(config: ConfigurationInput) {
	if (config['richAuthorizationRequests.enabled']) {
		const types = config['richAuthorizationRequests.types'];
		if (!isPlainObject(types)) {
			throw new TypeError(
				'features.richAuthorizationRequests.types must be an object'
			);
		}

		for (const [k, v] of Object.entries(types)) {
			if (!isPlainObject(v)) {
				throw new TypeError(
					'features.richAuthorizationRequests.types attribute values must be objects'
				);
			}
			const { validate } = v;
			if (
				typeof validate !== 'function' ||
				!['Function', 'AsyncFunction'].includes(validate.constructor.name)
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

	return {
		scopes,
		acrValues,
		clientAuthMethods,
		claims,
		grantTypes,
		claimsSupported
	};
}
