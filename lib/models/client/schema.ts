import { CLIENT_ATTRIBUTES } from '../../consts/index.ts';
import { noVSCHAR } from '../../consts/client_attributes.ts';
import { ApplicationConfig } from '../../configs/application.ts';

import { InvalidClientMetadata } from '../../helpers/errors.ts';
import sectorIdentifier from '../../helpers/sector_identifier.ts';
import instance from '../../helpers/weak_cache.ts';
import * as formatters from '../../helpers/formatters.ts';
import { pick } from '../../helpers/_/object.js';
import omitBy from '../../helpers/_/omit_by.ts';
import { needsSecret } from './secret.ts';
import {
	authorizationSigningAlgValues,
	clientAuthSigningAlgValues,
	idTokenSigningAlgValues,
	introspectionSigningAlgValues,
	requestObjectEncryptionAlgValues,
	userinfoSigningAlgValues
} from 'lib/configs/jwaAlgorithms.js';
import { validateRedirectUri } from '../../helpers/validateRedirectUri.js';

const W3CEmailRegExp =
	/^[a-zA-Z0-9.!#$%&’*+/=?^_`{|}~-]+@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*$/;
const needsJwks = {
	jwe: /^(RSA|ECDH)/,
	jws: /^(?:(?:P|E|R)S(?:256|384|512)|Ed(?:DSA|25519))$/
};
const {
	ARYS,
	DEFAULT: DEFAULTS,
	RECOGNIZED_METADATA: RECOGNIZED,
	STRING,
	WHEN
} = CLIENT_ATTRIBUTES;

function isUndefined(value) {
	return value === undefined;
}

export default function getSchema(provider) {
	const { configuration, features } = instance(provider);
	const { scopes } = configuration;

	const RECOGNIZED_METADATA = [...RECOGNIZED];
	const DEFAULT = structuredClone(DEFAULTS);
	const DEFAULT_CONFIGURATION = structuredClone(configuration.clientDefaults);
	Object.assign(DEFAULT, DEFAULT_CONFIGURATION);

	if (features.mTLS.enabled && features.mTLS.tlsClientAuth) {
		RECOGNIZED_METADATA.push('tls_client_auth_subject_dn');
		RECOGNIZED_METADATA.push('tls_client_auth_san_dns');
		RECOGNIZED_METADATA.push('tls_client_auth_san_uri');
		RECOGNIZED_METADATA.push('tls_client_auth_san_ip');
		RECOGNIZED_METADATA.push('tls_client_auth_san_email');
		RECOGNIZED_METADATA.push('use_mtls_endpoint_aliases');
	}

	RECOGNIZED_METADATA.push('token_endpoint_auth_signing_alg');

	if (features.jwtUserinfo.enabled) {
		RECOGNIZED_METADATA.push('userinfo_signed_response_alg');
	}

	if (features.introspection.enabled) {
		if (features.jwtIntrospection.enabled) {
			RECOGNIZED_METADATA.push('introspection_signed_response_alg');

			if (features.encryption.enabled) {
				RECOGNIZED_METADATA.push('introspection_encrypted_response_alg');
				RECOGNIZED_METADATA.push('introspection_encrypted_response_enc');
			}
		}
	}

	if (features.rpInitiatedLogout.enabled) {
		RECOGNIZED_METADATA.push('post_logout_redirect_uris');
	}

	if (features.backchannelLogout.enabled) {
		RECOGNIZED_METADATA.push('backchannel_logout_session_required');
		RECOGNIZED_METADATA.push('backchannel_logout_uri');
	}

	if (features.requestObjects.enabled) {
		// request_object_signing_alg is no longer recognized snake metadata — the value
		// is the canonical dotted `requestObject.signingAlg` base key (Model B), validated
		// by TypeBox and read by consumers directly.
		RECOGNIZED_METADATA.push('require_signed_request_object');
		if (features.encryption.enabled) {
			RECOGNIZED_METADATA.push('request_object_encryption_alg');
			RECOGNIZED_METADATA.push('request_object_encryption_enc');
		}
	}

	if (features.encryption.enabled) {
		RECOGNIZED_METADATA.push('id_token_encrypted_response_alg');
		RECOGNIZED_METADATA.push('id_token_encrypted_response_enc');
		if (features.jwtUserinfo.enabled) {
			RECOGNIZED_METADATA.push('userinfo_encrypted_response_alg');
			RECOGNIZED_METADATA.push('userinfo_encrypted_response_enc');
		}
	}

	if (features.jwtResponseModes.enabled) {
		RECOGNIZED_METADATA.push('authorization_signed_response_alg');
		if (features.encryption.enabled) {
			RECOGNIZED_METADATA.push('authorization_encrypted_response_alg');
			RECOGNIZED_METADATA.push('authorization_encrypted_response_enc');
		}
	}

	if (features.mTLS.enabled && features.mTLS.certificateBoundAccessTokens) {
		RECOGNIZED_METADATA.push('tls_client_certificate_bound_access_tokens');
	}

	if (features.ciba.enabled) {
		RECOGNIZED_METADATA.push('backchannel_token_delivery_mode');
		RECOGNIZED_METADATA.push('backchannel_user_code_parameter');
		RECOGNIZED_METADATA.push('backchannel_client_notification_endpoint');
		// backchannel_authentication_request_signing_alg is no longer recognized snake
		// metadata — the value is the canonical dotted `requestObject.backChannelSigningAlg`
		// base key (Model B), validated by TypeBox and read by consumers directly.
	}

	RECOGNIZED_METADATA.push('dpop_bound_access_tokens');

	if (features.richAuthorizationRequests.enabled) {
		RECOGNIZED_METADATA.push('authorization_details_types');
	}

	instance(provider).RECOGNIZED_METADATA = RECOGNIZED_METADATA;

	const ENUM = {
		default_acr_values: () => configuration.acrValues,
		id_token_signed_response_alg: () => idTokenSigningAlgValues,
		// request_object_signing_alg / backchannel_authentication_request_signing_alg are
		// now validated by TypeBox literal unions on the canonical dotted keys
		// (requestObject.signingAlg / requestObject.backChannelSigningAlg) — no runtime ENUM.
		backchannel_token_delivery_mode: () => features.ciba.deliveryModes,
		request_object_encryption_alg: () => requestObjectEncryptionAlgValues,
		authorization_details_types: () =>
			Object.keys(features.richAuthorizationRequests.types),
		token_endpoint_auth_method: (metadata) => {
			if (metadata.metadata.subjectType === 'pairwise') {
				for (const grant of [
					'urn:ietf:params:oauth:grant-type:device_code',
					'urn:openid:params:grant-type:ciba'
				]) {
					if (
						metadata.metadata.grantTypes.includes(grant) &&
						!['private_key_jwt', 'self_signed_tls_client_auth'].includes(
							metadata.token_endpoint_auth_method
						)
					) {
						metadata.invalidate(
							`pairwise ${grant} clients must utilize private_key_jwt or self_signed_tls_client_auth token endpoint authentication methods`
						);
					}
				}
			}

			return configuration.clientAuthMethods;
		},
		token_endpoint_auth_signing_alg: ({
			token_endpoint_auth_method: method
		}) => {
			switch (method) {
				case 'private_key_jwt':
					return clientAuthSigningAlgValues.filter((x) => !x.startsWith('HS'));
				case 'client_secret_jwt':
					return clientAuthSigningAlgValues.filter((x) => x.startsWith('HS'));
				default:
					return [];
			}
		},
		userinfo_signed_response_alg: () => userinfoSigningAlgValues,
		introspection_signed_response_alg: () => introspectionSigningAlgValues,
		authorization_signed_response_alg: () => authorizationSigningAlgValues
	};

	class Schema {
		constructor(metadata) {
			this.metadata = metadata;
			Object.assign(
				this,
				omitBy(pick(DEFAULT, ...RECOGNIZED_METADATA), isUndefined),
				omitBy(pick(metadata, ...RECOGNIZED_METADATA), isUndefined)
			);

			// Canonical (Model B) request-object signing options live on the dotted
			// base keys, not in RECOGNIZED_METADATA. Carry them onto the instance so the
			// secret/JWKS requirement checks below can read them the same way they read
			// recognized metadata; ensureStripUnrecognized() removes them again before
			// the instance is projected onto the validated client.
			this['requestObject.signingAlg'] = metadata['requestObject.signingAlg'];
			this['requestObject.backChannelSigningAlg'] =
				metadata['requestObject.backChannelSigningAlg'];

			this.required();
			this.baseKeys();
			this.whens();
			this.arrays();
			this.strings();
			this.enums();
			// Web/HTTPS URL shapes and the non-negative-integer checks for
			// default_max_age / client_secret_expires_at now live in ClientSchema (TypeBox).
			this.scopes();
			this.postLogoutRedirectUris();
			validateRedirectUri(
				metadata.redirectUris ?? [],
				metadata.applicationType
			);
			this.checkContacts();
			this.jarPolicy();

			const responseTypes = this.metadata.responseTypes;

			if (
				Array.isArray(this.metadata.grantTypes) &&
				this.metadata.grantTypes.includes('authorization_code') &&
				!responseTypes?.length
			) {
				this.invalidate('responseTypes must contain members');
			}

			if (responseTypes?.length && !this.metadata.redirectUris?.length) {
				// Empty redirect_uris is only permissible when PAR allows
				// unregistered redirect URIs AND this client requires PAR — and
				// never for `none` auth or pairwise sector clients (which resolve a
				// sector from the redirect URIs).
				const parAllowsUnregistered =
					ApplicationConfig['par.enabled'] &&
					ApplicationConfig['par.allowUnregisteredRedirectUris'] &&
					this.metadata['authorization.requirePushedAuthorizationRequests'] &&
					this.token_endpoint_auth_method !== 'none' &&
					!this.sector_identifier_uri;

				if (!parAllowsUnregistered) {
					this.invalidate('redirectUris must contain members');
				}
			}

			if (responseTypes?.length && this.metadata.responseModes?.length === 0) {
				this.invalidate('responseModes must contain members');
			}

			if (
				responseTypes?.includes('code') &&
				Array.isArray(this.metadata.grantTypes) &&
				!this.metadata.grantTypes.includes('authorization_code')
			) {
				this.invalidate(
					"grantTypes must contain 'authorization_code' when code is amongst responseTypes"
				);
			}

			{
				const { 0: pop, length } = [
					'tls_client_certificate_bound_access_tokens',
					'dpop_bound_access_tokens'
				].filter((conf) => this[conf]);

				if (length > 1) {
					this.invalidate(
						'only one proof of possession mechanism can be made required at a time'
					);
				}
			}

			{
				const { length } = [
					this.tls_client_auth_san_dns,
					this.tls_client_auth_san_email,
					this.tls_client_auth_san_ip,
					this.tls_client_auth_san_uri,
					this.tls_client_auth_subject_dn
				].filter(Boolean);

				if (this.token_endpoint_auth_method === 'tls_client_auth') {
					if (length === 0) {
						this.invalidate(
							'tls_client_auth requires one of the certificate subject value parameters'
						);
					}

					if (length !== 1) {
						this.invalidate(
							'only one tls_client_auth certificate subject value must be provided'
						);
					}
				} else {
					delete this.tls_client_auth_san_dns;
					delete this.tls_client_auth_san_email;
					delete this.tls_client_auth_san_ip;
					delete this.tls_client_auth_san_uri;
					delete this.tls_client_auth_subject_dn;
				}
			}

			// SECTOR IDENTIFIER VALIDATION
			sectorIdentifier(this);

			if (this.jwks !== undefined && this.jwks_uri !== undefined) {
				this.invalidate('jwks and jwks_uri must not be used at the same time');
			}

			this.ensureStripUnrecognized();
		}

		invalidate(message) {
			throw new InvalidClientMetadata(message);
		}

		// The base registration keys are camelCased and live on `this.metadata`
		// (not in the snake_case RECOGNIZED_METADATA the other passes iterate), so
		// they bypass `strings()`/`arrays()`/`enums()`. Validate them here with the
		// same upstream message shapes (kept camelCased to match `metadata()` and
		// the `invalid_redirect_uri` mapping) before the constructor reaches the
		// inline `responseTypes`/`grantTypes` checks that assume valid arrays.
		baseKeys() {
			const m = this.metadata;

			if (m.applicationType !== undefined) {
				if (
					typeof m.applicationType !== 'string' ||
					!m.applicationType.length
				) {
					this.invalidate(
						'applicationType must be a non-empty string if provided'
					);
				}
				if (!['web', 'native'].includes(m.applicationType)) {
					this.invalidate("applicationType must be 'native' or 'web'");
				}
			}

			if (
				m.clientId === undefined ||
				m.clientId === null ||
				m.clientId === ''
			) {
				this.invalidate('clientId is mandatory property');
			}
			if (typeof m.clientId !== 'string') {
				this.invalidate('clientId must be a non-empty string if provided');
			}
			if (noVSCHAR.test(m.clientId)) {
				this.invalidate('invalid client_id value');
			}

			if (
				m.clientSecret === undefined ||
				m.clientSecret === null ||
				m.clientSecret === ''
			) {
				if (needsSecret(this)) {
					this.invalidate('clientSecret is mandatory property');
				}
			} else {
				if (typeof m.clientSecret !== 'string') {
					this.invalidate(
						'clientSecret must be a non-empty string if provided'
					);
				}
				if (noVSCHAR.test(m.clientSecret)) {
					this.invalidate('invalid client_secret value');
				}
			}

			if (m.subjectType !== undefined) {
				if (typeof m.subjectType !== 'string' || !m.subjectType.length) {
					this.invalidate('subjectType must be a non-empty string if provided');
				}
				if (!['public', 'pairwise'].includes(m.subjectType)) {
					this.invalidate('subjectType must be public or pairwise');
				}
			}

			// redirectUris: only reached when not mandatory (required() throws first
			// for the missing/empty-string cases when responseTypes are present), so
			// a non-array here (incl. null for grant-only clients) is a type error.
			if (m.redirectUris !== undefined && m.redirectUris !== '') {
				if (!Array.isArray(m.redirectUris)) {
					this.invalidate('redirectUris must be an array');
				}
				m.redirectUris.forEach((member) => {
					if (typeof member !== 'string') {
						this.invalidate('redirectUris must only contain strings');
					}
				});
			}
		}

		required() {
			const checked = [];
			if (needsSecret(this)) {
				checked.push('clientSecret');
			}

			if (this.metadata.responseTypes?.length) {
				checked.push('redirectUris');
			}

			if (
				Array.isArray(this.metadata.grantTypes) &&
				this.metadata.grantTypes.includes('urn:openid:params:grant-type:ciba')
			) {
				checked.push('backchannel_token_delivery_mode');
				if (this.backchannel_token_delivery_mode !== 'poll') {
					checked.push('backchannel_client_notification_endpoint');
				}

				if (this.metadata.subjectType === 'pairwise') {
					checked.push('jwks_uri');
					if (this.metadata.responseTypes?.length) {
						checked.push('sector_identifier_uri');
					}
				}
			}

			if (this.metadata.subjectType === 'pairwise') {
				if (
					Array.isArray(this.metadata.grantTypes) &&
					this.metadata.grantTypes.includes(
						'urn:ietf:params:oauth:grant-type:device_code'
					)
				) {
					checked.push('jwks_uri');
					if (this.metadata.responseTypes?.length) {
						checked.push('sector_identifier_uri');
					}
				}

				if (
					this.metadata.responseTypes?.length &&
					Array.isArray(this.metadata.redirectUris) &&
					new Set(this.metadata.redirectUris.map((uri) => new URL(uri).host))
						.size > 1
				) {
					checked.push('sector_identifier_uri');
				}
			}

			checked.forEach((prop) => {
				if (!this[prop] && !this.metadata[prop]) {
					this.invalidate(`${prop} is mandatory property`);
				}
			});

			const requireJwks =
				['private_key_jwt', 'self_signed_tls_client_auth'].includes(
					this.token_endpoint_auth_method
				) ||
				needsJwks.jws.test(this['requestObject.signingAlg']) ||
				needsJwks.jws.test(this['requestObject.backChannelSigningAlg']) ||
				needsJwks.jwe.test(this.id_token_encrypted_response_alg) ||
				needsJwks.jwe.test(this.userinfo_encrypted_response_alg) ||
				needsJwks.jwe.test(this.introspection_encrypted_response_alg) ||
				needsJwks.jwe.test(this.authorization_encrypted_response_alg);

			if (requireJwks && !this.jwks && !this.jwks_uri) {
				this.invalidate('jwks or jwks_uri is mandatory for this client');
			}
		}

		strings() {
			STRING.forEach((prop) => {
				if (this[prop] !== undefined) {
					const isAry = ARYS.includes(prop);
					(isAry ? this[prop] : [this[prop]]).forEach((val) => {
						if (typeof val !== 'string' || !val.length) {
							this.invalidate(
								isAry
									? `${prop} must only contain strings`
									: `${prop} must be a non-empty string if provided`
							);
						}
					});
				}
			});
		}

		arrays() {
			ARYS.forEach((prop) => {
				if (this[prop] !== undefined) {
					if (!Array.isArray(this[prop])) {
						this.invalidate(`${prop} must be an array`);
					}
					this[prop] = [...new Set(this[prop])];
				}
			});
		}

		whens() {
			Object.entries(WHEN).forEach(([when, [property, value]]) => {
				if (this[when] !== undefined && this[property] === undefined) {
					this.invalidate(
						`${property} is mandatory property when ${when} is provided`
					);
				}

				if (value && this[when] === undefined && this[property] !== undefined) {
					this[when] = value;
				}
			});
		}

		enums() {
			Object.entries(ENUM).forEach(([prop, fn]) => {
				const only = fn(this);

				if (this[prop] !== undefined) {
					const isAry = ARYS.includes(prop);
					let length;
					let method;
					if (only instanceof Set) {
						({ size: length } = only);
						method = 'has';
					} else {
						({ length } = only);
						method = 'includes';
					}

					if (isAry && !this[prop].every((val) => only[method](val))) {
						if (length) {
							this.invalidate(
								`${prop} can only contain ${formatters.formatList([...only], { type: 'disjunction' })}`
							);
						} else {
							this.invalidate(`${prop} must be empty (no values are allowed)`);
						}
					} else if (!isAry && !only[method](this[prop])) {
						if (length) {
							this.invalidate(
								`${prop} must be ${formatters.formatList([...only], { type: 'disjunction' })}`
							);
						} else {
							this.invalidate(
								`${prop} must not be provided (no values are allowed)`
							);
						}
					}
				}
			});
		}

		postLogoutRedirectUris() {
			if (this.post_logout_redirect_uris) {
				validateRedirectUri(
					this.post_logout_redirect_uris,
					this.metadata.applicationType,
					{ label: 'post_logout_redirect_uris' }
				);
			}
		}

		checkContacts() {
			if (this.contacts) {
				this.contacts.forEach((contact) => {
					if (!W3CEmailRegExp.test(contact)) {
						this.invalidate('contacts can only contain email addresses');
					}
				});
			}
		}

		jarPolicy() {
			if (
				features.requestObjects.enabled &&
				features.requestObjects.requireSignedRequestObject
			) {
				this.require_signed_request_object = true;
			}
		}

		ensureStripUnrecognized() {
			const allowed = [...RECOGNIZED_METADATA];
			Object.keys(this).forEach((prop) => {
				if (!allowed.includes(prop)) {
					delete this[prop];
				}
			});
		}

		scopes() {
			if (this.scope) {
				const parsed = new Set(this.scope.split(' '));
				parsed.forEach((scope) => {
					if (!scopes.has(scope)) {
						this.invalidate(
							'scope must only contain Authorization Server supported scope values'
						);
					}
				});
				this.scope = [...parsed].join(' ');
			}
		}
	}

	return Schema;
}
