import { isPlainObject, merge } from '../helpers/_/object.js';
import * as formatters from '../helpers/formatters.ts';
import { STABLE, EXPERIMENTS } from '../helpers/features.ts';
import * as attention from '../helpers/attention.ts';

/*
 * The server settings that cannot be read straight off ApplicationConfig: collections turned into
 * Sets, and the values derived by cross-referencing scopes against claims. Everything else — every
 * feature flag and sub-option — is read flat from ApplicationConfig at its use site.
 */
export interface Configuration {
	scopes: Set<string>;
	acrValues: Set<string>;
	clientAuthMethods: Set<string>;
	claims: Record<string, any>;
	grantTypes: Set<string>;
	claimsSupported: Set<string>;
}

type Config = Record<string, any>;

function toSet(name: string, value: unknown): Set<string> {
	if (value instanceof Set) {
		return new Set(value);
	}
	if (!Array.isArray(value)) {
		throw new TypeError(`${name} must be an Array or Set`);
	}
	return new Set(value);
}

function collectScopes(scopes: Set<string>, claims: Config) {
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

function unpackArrayClaims(claims: Config) {
	Object.entries(claims).forEach(([key, value]) => {
		if (Array.isArray(value)) {
			claims[key] = value.reduce((accumulator, claim) => {
				const scope = accumulator;
				scope[claim] = null;
				return scope;
			}, {});
		}
	});
}

function ensureOpenIdSub(claims: Config) {
	if (!Object.keys(claims.openid).includes('sub')) {
		claims.openid.sub = null;
	}
}

function removeAcrIfEmpty(acrValues: Set<string>, claims: Config) {
	if (!acrValues.size) {
		delete claims.acr;
	}
}

function collectClaims(scopes: Set<string>, claims: Config): Set<string> {
	const claimsSupported = new Set<string>();
	scopes.forEach((scope) => {
		if (scope in claims) {
			Object.keys(claims[scope]).forEach(
				Set.prototype.add.bind(claimsSupported)
			);
		}
	});

	Object.entries(claims).forEach(([key, value]) => {
		if (value === null) claimsSupported.add(key);
	});

	return claimsSupported;
}

function collectGrantTypes(config: Config, scopes: Set<string>): Set<string> {
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

function checkRichAuthorizationRequests(config: Config) {
	if (config['richAuthorizationRequests.enabled']) {
		if (!isPlainObject(config['richAuthorizationRequests.types'])) {
			throw new TypeError(
				'features.richAuthorizationRequests.types must be an object'
			);
		}

		for (const [k, v] of Object.entries<any>(
			config['richAuthorizationRequests.types']
		)) {
			if (!isPlainObject(v)) {
				throw new TypeError(
					'features.richAuthorizationRequests.types attribute values must be objects'
				);
			}
			if (
				typeof v.validate !== 'function' ||
				!['Function', 'AsyncFunction'].includes(v.validate.constructor.name)
			) {
				throw new TypeError(
					`features.richAuthorizationRequests.types['${k}'].validate must be a function`
				);
			}
		}
	}
}

function checkCibaDeliveryModes(config: Config) {
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

function checkDependantFeatures(config: Config) {
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

function checkAuthMethods(config: Config, clientAuthMethods: Set<string>) {
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

function checkDeviceFlow(config: Config) {
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

function logDraftNotice(config: Config) {
	// Keyed by flag, holding the experiment itself: it is already in hand here, and re-looking it
	// up below would produce a value the compiler cannot know is present.
	const ENABLED_EXPERIMENTS = new Map<string, { name: string; version: any }>();
	let throwExperiment = false;

	// Feature flags and their experiment acknowledgements live in the config (flat dotted keys).
	// Only experimental features carry an `.ack`, so iterate the known experiments and read their
	// enabled/ack directly.
	for (const [flag, experimental] of EXPERIMENTS) {
		const enabled = config[`${flag}.enabled`];
		const ack = config[`${flag}.ack`];

		if (
			enabled &&
			!STABLE.has(flag) &&
			(Array.isArray(experimental.version)
				? !experimental.version.includes(ack)
				: ack !== experimental.version)
		) {
			if (typeof ack !== 'undefined') {
				throwExperiment = true;
			}
			ENABLED_EXPERIMENTS.set(flag, experimental);
		}
	}

	if (ENABLED_EXPERIMENTS.size) {
		attention.info(
			'The following experimental features are enabled and their implemented version not acknowledged'
		);
		ENABLED_EXPERIMENTS.forEach(({ name, version }) => {
			if (Array.isArray(version)) {
				version = version[version.length - 1];
			}

			attention.info(
				`  - ${name} (Acknowledging this feature's implemented version can be done with the value '${version}')`
			);
		});
		attention.info(
			'Breaking changes between experimental feature updates may occur and these will be published as MINOR semver oidc-provider updates.'
		);
		attention.info(
			"You may disable this notice and be warned when breaking updates occur by acknowledging the current experiment's version. See the documentation for more details."
		);

		if (throwExperiment) {
			throw new TypeError(
				'An unacknowledged version of an experimental feature is included in this oidc-provider version.'
			);
		}
	}
}

/*
 * validateConfiguration
 *
 * Check a server configuration and return the values derived from it. Throws a TypeError on any
 * combination the server cannot run with — an unsupported client auth method, a feature enabled
 * without the one it depends on, an unacknowledged experiment.
 *
 * A pure function of the config passed in, deliberately: it neither reads nor writes the live
 * ApplicationConfig. That is what lets the admin settings API check a configuration it is *about*
 * to persist against the very same invariants the server enforces at boot, instead of maintaining
 * its own copy of them that can drift.
 *
 * `config.claims` is cloned before processing, so a caller's object is never mutated.
 */
export function validateConfiguration(config: Config): Configuration {
	const scopes = toSet('scopes', config.scopes);
	const acrValues = toSet('acrValues', config.acrValues);
	const clientAuthMethods = toSet(
		'clientAuthMethods',
		config.clientAuthMethods
	);
	const claims = structuredClone(merge({}, config.claims));

	// Order is significant: the claims processing below builds on the step before it, and the
	// checks are ordered so the most fundamental misconfiguration is the one reported.
	logDraftNotice(config);

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
