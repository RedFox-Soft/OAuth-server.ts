import { CLIENT_ATTRIBUTES } from '../../consts/index.ts';
import {
	BASE_ATTRIBUTES,
	noVSCHAR,
	recognizedFrom,
	type ValueSetContext
} from '../../consts/client_attributes.ts';
import { ApplicationConfig, configuration } from '../../configs/application.ts';
import { ClientDefaults } from '../../configs/clientBase.ts';

import { InvalidClientMetadata } from '../../helpers/errors.ts';
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

// ClientDefaults is declared once, in camelCase (ClientSchema's convention). The recognised
// metadata defaults below are keyed by wire-format name, so the two client defaults that
// surface as OIDC metadata are translated here. Spelling only — the values stay declared in
// lib/configs/clientBase.ts, so there is still exactly one declaration of each default.
const WIRE_FORMAT_DEFAULT_KEYS = {
	idTokenSignedResponseAlg: 'id_token_signed_response_alg',
	tokenEndpointAuthMethod: 'token_endpoint_auth_method',
	'requestObject.require': 'require_signed_request_object'
} as const;

function wireFormatClientDefaults() {
	const translated: Record<string, unknown> = {};
	for (const [camel, wire] of Object.entries(WIRE_FORMAT_DEFAULT_KEYS)) {
		const value = ClientDefaults[camel as keyof typeof ClientDefaults];
		if (value !== undefined) translated[wire] = value;
	}
	return translated;
}

const W3CEmailRegExp =
	/^[a-zA-Z0-9.!#$%&’*+/=?^_`{|}~-]+@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*$/;
const needsJwks = {
	jwe: /^(RSA|ECDH)/,
	jws: /^(?:(?:P|E|R)S(?:256|384|512)|Ed(?:DSA|25519))$/
};
const {
	ARYS,
	DEFAULT: DEFAULTS,
	FORCED,
	FORMATTED,
	STRING,
	VALUE_SETS,
	WHEN
} = CLIENT_ATTRIBUTES;

function isUndefined(value: unknown) {
	return value === undefined;
}

// `value?.length` for what a submission may carry before its shapes are checked: a list or a string.
function lengthOf(value: unknown): number | undefined {
	return typeof value === 'string' || Array.isArray(value)
		? value.length
		: undefined;
}

// `value.includes(member)` for a member that may still be a string or a list.
function mentions(value: unknown, member: string): boolean {
	return (
		(typeof value === 'string' || Array.isArray(value)) &&
		value.includes(member)
	);
}

// A member an earlier pass has already required to be a list, or its absence.
function listOf(value: unknown): unknown[] | undefined {
	return Array.isArray(value) ? value : undefined;
}

// The snake_case client metadata this deployment recognizes: the always-on base list plus the
// keys the enabled features contribute. Derived from ApplicationConfig on every call rather than
// frozen at module load, because the flags are mutable at runtime (the specs toggle them), and a
// key recognized here is one the schema engine will read, camelCase onto the client, and echo back
// out of `toStored` — so a stale list would accept and advertise metadata for a disabled
// feature. Callers that consult it per-key must hoist the call out of their loop.
/*
 * The configuration a value set is computed from, read when the pass runs rather than when the
 * module loads: capabilities change while the server runs, and a set read earlier would freeze.
 */
function valueSetContext(): ValueSetContext {
	return {
		acrValues: configuration.acrValues,
		clientAuthMethods: configuration.clientAuthMethods,
		cibaDeliveryModes: ApplicationConfig['ciba.deliveryModes'],
		authorizationDetailsTypes: Object.keys(
			ApplicationConfig['richAuthorizationRequests.types']
		),
		idTokenSigningAlgs: idTokenSigningAlgValues,
		userinfoSigningAlgs: userinfoSigningAlgValues,
		introspectionSigningAlgs: introspectionSigningAlgValues,
		authorizationSigningAlgs: authorizationSigningAlgValues,
		requestObjectEncryptionAlgs: requestObjectEncryptionAlgValues,
		clientAuthSigningAlgs: clientAuthSigningAlgValues
	};
}

export function buildRecognizedMetadata() {
	return recognizedFrom(ApplicationConfig);
}

export default function getSchema() {
	const { scopes } = configuration;

	const RECOGNIZED_METADATA = buildRecognizedMetadata();
	const DEFAULT = structuredClone(DEFAULTS);
	Object.assign(DEFAULT, wireFormatClientDefaults());

	/*
	 * The instance is the metadata being validated: each pass reads, rewrites or removes recognised
	 * members on it by name, so it is typed as the record it is.
	 */
	class Schema {
		[member: string]: unknown;
		metadata: Record<string, unknown>;

		constructor(metadata: Record<string, unknown>) {
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
			this.formats();
			this.forced();

			this.crossFieldRules();

			this.ensureStripUnrecognized();
		}

		invalidate(message: string): never {
			throw new InvalidClientMetadata(message);
		}

		// The base registration keys are camelCased and live on `this.metadata`
		// (not in the snake_case RECOGNIZED_METADATA the other passes iterate), so
		// they bypass `strings()`/`arrays()`/`enums()`. Validate them here with the
		// same upstream message shapes (kept camelCased to match `metadata()` and
		// the `invalid_redirect_uri` mapping) before the constructor reaches the
		// inline `responseTypes`/`grantTypes` checks that assume valid arrays.
		/*
		 * The base registration keys, each checked by the rules its entry declares, in declaration order —
		 * see BASE_ATTRIBUTES for why "not sent" differs between them.
		 */
		baseKeys() {
			for (const [name, rules] of Object.entries(BASE_ATTRIBUTES)) {
				const value = this.metadata[name];

				if ((rules.absent ?? [undefined]).includes(value)) {
					if (rules.required) {
						this.invalidate(`${name} is mandatory property`);
					}
					continue;
				}

				if (rules.string && (typeof value !== 'string' || !value.length)) {
					this.invalidate(`${name} must be a non-empty string if provided`);
				}

				if (rules.array) {
					if (!Array.isArray(value)) {
						this.invalidate(`${name} must be an array`);
					}
					value.forEach((member) => {
						if (typeof member !== 'string') {
							this.invalidate(`${name} must only contain strings`);
						}
					});
				}

				if (
					rules.oneOf &&
					(typeof value !== 'string' || !rules.oneOf.values.includes(value))
				) {
					this.invalidate(rules.oneOf.refusal);
				}

				if (rules.printable && noVSCHAR.test(String(value))) {
					this.invalidate(rules.printable);
				}
			}
		}

		required() {
			const checked = [];
			if (needsSecret(this)) {
				checked.push('clientSecret');
			}

			if (lengthOf(this.metadata.responseTypes)) {
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
					if (lengthOf(this.metadata.responseTypes)) {
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
					if (lengthOf(this.metadata.responseTypes)) {
						checked.push('sector_identifier_uri');
					}
				}

				if (
					lengthOf(this.metadata.responseTypes) &&
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

			// RegExp#test reads its argument as a string, absent members included; so do these.
			const requireJwks =
				['private_key_jwt', 'self_signed_tls_client_auth'].includes(
					String(this.token_endpoint_auth_method)
				) ||
				needsJwks.jws.test(String(this['requestObject.signingAlg'])) ||
				needsJwks.jws.test(
					String(this['requestObject.backChannelSigningAlg'])
				) ||
				needsJwks.jwe.test(String(this.id_token_encrypted_response_alg)) ||
				needsJwks.jwe.test(String(this.userinfo_encrypted_response_alg)) ||
				needsJwks.jwe.test(String(this.introspection_encrypted_response_alg)) ||
				needsJwks.jwe.test(String(this.authorization_encrypted_response_alg));

			if (requireJwks && !this.jwks && !this.jwks_uri) {
				this.invalidate('jwks or jwks_uri is mandatory for this client');
			}
		}

		strings() {
			STRING.forEach((prop) => {
				if (this[prop] !== undefined) {
					const isAry = ARYS.includes(prop);
					const current = this[prop];
					// A list member was made an array by arrays(), which runs first.
					const values: unknown[] =
						isAry && Array.isArray(current) ? current : [current];
					values.forEach((val) => {
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

		/*
		 * A cross-field rule, not a value set: a pairwise client on the device-code or CIBA grant must
		 * authenticate with a key it holds. It has always been raised at the moment the authentication
		 * method's permitted set is consulted, and stays there so a registration breaking it and another
		 * value-set rule is refused with the same description as before.
		 */
		pairwiseGrantAuthMethod() {
			if (this.metadata.subjectType !== 'pairwise') {
				return;
			}
			for (const grant of [
				'urn:ietf:params:oauth:grant-type:device_code',
				'urn:openid:params:grant-type:ciba'
			]) {
				if (
					mentions(this.metadata.grantTypes, grant) &&
					!['private_key_jwt', 'self_signed_tls_client_auth'].includes(
						String(this.token_endpoint_auth_method)
					)
				) {
					this.invalidate(
						`pairwise ${grant} clients must utilize private_key_jwt or self_signed_tls_client_auth token endpoint authentication methods`
					);
				}
			}
		}

		enums() {
			const context = valueSetContext();
			VALUE_SETS.forEach(([prop, values]) => {
				if (prop === 'token_endpoint_auth_method') {
					this.pairwiseGrantAuthMethod();
				}
				const only = values(context, this);

				if (this[prop] !== undefined) {
					const isAry = ARYS.includes(prop);
					// An allowed set arrives as either a Set or an Array depending on the entry.
					// Membership is asked through one predicate rather than by indexing whichever
					// method name fits, so the union does not have to be indexed by a string.
					const allowed = [...only];
					const { length } = allowed;
					const allows = (value: unknown) =>
						typeof value === 'string' && allowed.includes(value);
					const current = this[prop];

					if (isAry && !listOf(current)?.every((val) => allows(val))) {
						if (length) {
							this.invalidate(
								`${prop} can only contain ${formatters.formatList([...only], { type: 'disjunction' })}`
							);
						} else {
							this.invalidate(`${prop} must be empty (no values are allowed)`);
						}
					} else if (!isAry && !allows(current)) {
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

		/*
		 * The named checks attributes declare, in the order FORMAT_RANK fixes. Each reads the attribute
		 * where its half keeps it: registration metadata on the instance, base keys on the submission.
		 */
		formats() {
			for (const [name, format, half] of FORMATTED) {
				const value = half === 'base' ? this.metadata[name] : this[name];
				switch (format) {
					case 'scope-list':
						if (typeof value === 'string' && value) {
							const parsed = new Set<string>(value.split(' '));
							parsed.forEach((scope) => {
								if (!scopes.has(scope)) {
									this.invalidate(
										`${name} must only contain Authorization Server supported scope values`
									);
								}
							});
							this[name] = [...parsed].join(' ');
						}
						break;
					case 'redirect-uri':
						validateRedirectUri(
							listOf(value)?.map(String) ?? [],
							String(this.metadata.applicationType),
							{
								label: name
							}
						);
						break;
					case 'email':
						if (value) {
							listOf(value)?.forEach((contact) => {
								if (!W3CEmailRegExp.test(String(contact))) {
									this.invalidate(`${name} can only contain email addresses`);
								}
							});
						}
						break;
				}
			}
		}

		/* Values a deployment setting imposes regardless of what the client sent. */
		forced() {
			const settings: Record<string, unknown> = ApplicationConfig;
			for (const [name, { flags, value }] of FORCED) {
				if (flags.every((flag) => settings[flag])) {
					this[name] = value;
				}
			}
		}

		/*
		 * The rules that are not a property of any one attribute, so they cannot live in the declaration.
		 * Named here so they can be counted rather than found. With `required()` and
		 * `pairwiseGrantAuthMethod()` they are the whole set of rules this validator keeps as code:
		 *
		 *   - response types are required when the authorization-code grant is used
		 *   - redirect targets are required with response types, unless a pushed request may omit them
		 *   - response modes may not be empty when response types are present
		 *   - the code response type requires the authorization-code grant
		 *   - at most one proof-of-possession mechanism may be required
		 *   - tls_client_auth needs exactly one certificate subject; other methods carry none
		 *   - an inline key set and a key-set URI are not both allowed
		 *
		 * The order is the order they have always been checked in.
		 */
		crossFieldRules() {
			// Not a base key, so any shape may still be here (ClientSchema refuses a wrong one later); a
			// string answers length and includes as it always did.
			const { responseTypes } = this.metadata;
			const responseTypeCount = lengthOf(responseTypes);
			const hasCodeResponseType = mentions(responseTypes, 'code');

			if (
				Array.isArray(this.metadata.grantTypes) &&
				this.metadata.grantTypes.includes('authorization_code') &&
				!responseTypeCount
			) {
				this.invalidate('responseTypes must contain members');
			}

			if (responseTypeCount && !lengthOf(this.metadata.redirectUris)) {
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

			if (responseTypeCount && lengthOf(this.metadata.responseModes) === 0) {
				this.invalidate('responseModes must contain members');
			}

			if (
				hasCodeResponseType &&
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

			if (this.jwks !== undefined && this.jwks_uri !== undefined) {
				this.invalidate('jwks and jwks_uri must not be used at the same time');
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
	}

	return Schema;
}
