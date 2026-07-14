import { isPlainObject, merge, pick } from './_/object.js';
import * as formatters from './formatters.ts';
import getDefaults from './defaults.ts';
import { STABLE, EXPERIMENTS } from './features.ts';
import * as attention from './attention.ts';
import { ApplicationConfig } from 'lib/configs/application.js';

function toSet(name, value) {
	if (value instanceof Set) {
		return new Set(value);
	}
	if (!Array.isArray(value)) {
		throw new TypeError(`${name} must be an Array or Set`);
	}
	return new Set(value);
}

function featuresTypeErrorCheck({ features }) {
	for (const value of Object.values(features)) {
		if (typeof value === 'boolean') {
			throw new TypeError(
				'Features are not enabled/disabled with a boolean value. See the documentation for more details.'
			);
		}
	}
}

class Configuration {
	#defaults = getDefaults();

	constructor(config = {}) {
		Object.assign(
			this,
			merge({}, this.#defaults, pick(config, ...Object.keys(this.#defaults)))
		);

		// ApplicationConfig is the single source for the options it owns. The collection
		// options default from it and may be overridden per-instance via the provider setup;
		// they are copied (Set/clone) so the in-place processing below never mutates the shared
		// ApplicationConfig. Feature flags and sub-options are NOT held on the provider — they
		// are read directly and flat from ApplicationConfig at each use site (incl. the
		// validations below).
		this.scopes = toSet('scopes', config.scopes ?? ApplicationConfig.scopes);
		this.acrValues = toSet(
			'acrValues',
			config.acrValues ?? ApplicationConfig.acrValues
		);
		this.clientAuthMethods = toSet(
			'clientAuthMethods',
			config.clientAuthMethods ?? ApplicationConfig.clientAuthMethods
		);
		this.claims = structuredClone(
			merge({}, ApplicationConfig.claims, config.claims ?? {})
		);

		featuresTypeErrorCheck(this);

		this.logDraftNotice();

		this.collectScopes();
		this.collectPrompts();
		this.unpackArrayClaims();
		this.ensureOpenIdSub();
		this.removeAcrIfEmpty();
		this.collectClaims();
		this.collectGrantTypes();
		this.checkDependantFeatures();
		this.checkDeviceFlow();
		this.checkAuthMethods();
		this.checkCibaDeliveryModes();
		this.checkRichAuthorizationRequests();

		// release #defaults
		this.#defaults = undefined;
	}

	checkRichAuthorizationRequests() {
		if (ApplicationConfig['richAuthorizationRequests.enabled']) {
			if (
				!isPlainObject(ApplicationConfig['richAuthorizationRequests.types'])
			) {
				throw new TypeError(
					'features.richAuthorizationRequests.types must be an object'
				);
			}

			for (const [k, v] of Object.entries(
				ApplicationConfig['richAuthorizationRequests.types']
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

	collectGrantTypes() {
		this.grantTypes = new Set(['authorization_code']);

		if (
			this.scopes.has('offline_access') ||
			this.issueRefreshToken !== this.#defaults.issueRefreshToken
		) {
			this.grantTypes.add('refresh_token');
		}

		if (ApplicationConfig['clientCredentials.enabled']) {
			this.grantTypes.add('client_credentials');
		}

		if (ApplicationConfig['deviceFlow.enabled']) {
			this.grantTypes.add('urn:ietf:params:oauth:grant-type:device_code');
		}

		if (ApplicationConfig['ciba.enabled']) {
			this.grantTypes.add('urn:openid:params:grant-type:ciba');
		}
	}

	collectScopes() {
		const claimDefinedScopes = [];
		Object.entries(this.claims).forEach(([key, value]) => {
			if (isPlainObject(value) || Array.isArray(value)) {
				claimDefinedScopes.push(key);
			}
		});
		claimDefinedScopes.forEach((scope) => {
			if (typeof scope === 'string' && !this.scopes.has(scope)) {
				this.scopes.add(scope);
			}
		});
	}

	collectPrompts() {
		this.prompts = new Set(['none']);
		this.interactions.policy.forEach(({ name, requestable }) => {
			if (requestable) {
				this.prompts.add(name);
			}
		});
	}

	unpackArrayClaims() {
		Object.entries(this.claims).forEach(([key, value]) => {
			if (Array.isArray(value)) {
				this.claims[key] = value.reduce((accumulator, claim) => {
					const scope = accumulator;
					scope[claim] = null;
					return scope;
				}, {});
			}
		});
	}

	ensureOpenIdSub() {
		if (!Object.keys(this.claims.openid).includes('sub')) {
			this.claims.openid.sub = null;
		}
	}

	removeAcrIfEmpty() {
		if (!this.acrValues.size) {
			delete this.claims.acr;
		}
	}

	collectClaims() {
		const claims = new Set();
		this.scopes.forEach((scope) => {
			if (scope in this.claims) {
				Object.keys(this.claims[scope]).forEach(Set.prototype.add.bind(claims));
			}
		});

		Object.entries(this.claims).forEach(([key, value]) => {
			if (value === null) claims.add(key);
		});

		this.claimsSupported = claims;
	}

	checkCibaDeliveryModes() {
		const modes = ApplicationConfig['ciba.deliveryModes'];
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

	checkDependantFeatures() {
		const config = ApplicationConfig;

		if (
			config['jwtIntrospection.enabled'] &&
			!config['introspection.enabled']
		) {
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

	checkAuthMethods() {
		const authMethods = new Set([
			'none',
			'client_secret_basic',
			'client_secret_jwt',
			'client_secret_post',
			'private_key_jwt'
		]);

		if (
			ApplicationConfig['mTLS.enabled'] &&
			ApplicationConfig['mTLS.tlsClientAuth']
		) {
			authMethods.add('tls_client_auth');
		}

		if (
			ApplicationConfig['mTLS.enabled'] &&
			ApplicationConfig['mTLS.selfSignedTlsClientAuth']
		) {
			authMethods.add('self_signed_tls_client_auth');
		}

		if (this.clientAuthMethods) {
			this.clientAuthMethods.forEach((method) => {
				if (!authMethods.has(method)) {
					throw new TypeError(
						`only supported clientAuthMethods are ${formatters.formatList([...authMethods])}`
					);
				}
			});
		}
	}

	checkDeviceFlow() {
		if (ApplicationConfig['deviceFlow.enabled']) {
			if (ApplicationConfig['deviceFlow.charset'] !== undefined) {
				if (
					!['base-20', 'digits'].includes(
						ApplicationConfig['deviceFlow.charset']
					)
				) {
					throw new TypeError(
						'only supported charsets are "base-20" and "digits"'
					);
				}
			}
			if (!/^[-* ]*$/.test(ApplicationConfig['deviceFlow.mask'])) {
				throw new TypeError(
					'mask can only contain asterisk("*"), hyphen-minus("-") and space(" ") characters'
				);
			}
		}
	}

	logDraftNotice() {
		const ENABLED_EXPERIMENTS = new Set();
		let throwExperiment = false;

		// Feature flags and their experiment acknowledgements live in ApplicationConfig
		// (flat dotted keys). Only experimental features carry an `.ack` there, so iterate
		// the known experiments and read their enabled/ack directly from ApplicationConfig.
		for (const [flag, experimental] of EXPERIMENTS) {
			const enabled = ApplicationConfig[`${flag}.enabled`];
			const ack = ApplicationConfig[`${flag}.ack`];

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
				ENABLED_EXPERIMENTS.add(flag);
			}
		}

		if (ENABLED_EXPERIMENTS.size) {
			attention.info(
				'The following experimental features are enabled and their implemented version not acknowledged'
			);
			ENABLED_EXPERIMENTS.forEach((experimental) => {
				const { name } = EXPERIMENTS.get(experimental);
				let { version } = EXPERIMENTS.get(experimental);

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
}

export default Configuration;
