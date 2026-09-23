/*
 * The one declaration of the client registration attributes this server recognises.
 *
 * Each attribute states the rules that used to be spread across five parallel lists — whether the
 * deployment recognises it, what it defaults to, whether it carries a list, whether it holds strings,
 * and which companion attribute implies it. The lists the validator reads are derived from this table,
 * so an attribute cannot be declared in one and forgotten in another.
 *
 * Import-free on purpose. It is read on every client resolution, and by callers that must not reach
 * the datastore; the flags arrive as an argument rather than by importing the configuration.
 *
 * ORDER IS LOAD-BEARING. The recognised set is this table filtered in declaration order, and that
 * order becomes the key order of every projected client and therefore of every stored record. It
 * reproduces the flag-gated sequence it replaced exactly, which is why two unconditional attributes
 * sit after the mTLS group rather than beside the unconditional ones at the top.
 */

/** A permitted-value set, exactly as the validator has always received it. */
export type ValueSet = ReadonlySet<string> | readonly string[];

/*
 * What a value set may be computed from. Resolved from the configuration in force at the moment the
 * validation pass runs, and handed in — the algorithm lists reach the key store, so importing them
 * here would put a storage edge into a module every client resolution loads.
 */
export type ValueSetContext = {
	readonly acrValues: ValueSet;
	readonly clientAuthMethods: ValueSet;
	readonly cibaDeliveryModes: ValueSet;
	readonly authorizationDetailsTypes: ValueSet;
	readonly idTokenSigningAlgs: readonly string[];
	readonly userinfoSigningAlgs: readonly string[];
	readonly introspectionSigningAlgs: readonly string[];
	readonly authorizationSigningAlgs: readonly string[];
	readonly requestObjectEncryptionAlgs: readonly string[];
	readonly clientAuthSigningAlgs: readonly string[];
};

/** The recognised attributes of a submission, as the validation pass holds them. */
export type Submission = Readonly<Record<string, unknown>>;

export type AttributeRules = {
	/** ApplicationConfig flag keys that must ALL hold for this attribute to be recognised. */
	requires?: readonly string[];
	/** Applied when the client sends nothing. */
	default?: unknown;
	/** Carries a list rather than a scalar. Lists are de-duplicated. */
	array?: true;
	/** Holds string values — as the scalar, or as the element type when `array`. */
	string?: true;
	/** `[companion, fallback]`: requires `companion` when present, and defaults to `fallback`. */
	when?: readonly [string] | readonly [string, string];
	/** Permitted values, computed when the pass runs from the configuration then in force. */
	values?: (context: ValueSetContext, submission: Submission) => ValueSet;
	/** A named check this attribute's value must pass — see FORMAT_RANK. */
	format?: AttributeFormat;
	/** Flags that, when all hold, force this attribute to `value` whatever was sent. */
	forcedBy?: { readonly flags: readonly string[]; readonly value: unknown };
};

/*
 * The named checks an attribute can declare, and the order they are applied in. Declaring the check on
 * the attribute and implementing it once is the same split the client schema already uses for its
 * URL formats.
 *
 * The order is the order these checks have always run in, and it is what decides which refusal a
 * submission breaking two of them receives. Within one check, attributes are taken in declaration
 * order — registration metadata first, then the base registration keys — which reproduces the
 * interleaving the validator had, including the base-key redirect targets checked between the
 * post-logout targets and the contacts.
 */
export type AttributeFormat = 'scope-list' | 'redirect-uri' | 'email';

/*
 * A record rather than a list so the compiler refuses a format that has no place in the order: a
 * format an entry declared but the order omitted would otherwise be silently never checked.
 */
const FORMAT_RANK: Readonly<Record<AttributeFormat, number>> = {
	'scope-list': 0,
	'redirect-uri': 1,
	email: 2
};

const HMAC = (alg: string) => alg.startsWith('HS');

const A128CBC = 'A128CBC-HS256';
const MTLS_SUBJECT: readonly string[] = ['mTLS.enabled', 'mTLS.tlsClientAuth'];
const JWT_INTROSPECTION: readonly string[] = [
	'introspection.enabled',
	'jwtIntrospection.enabled'
];

export const ATTRIBUTES: Readonly<Record<string, AttributeRules>> = {
	// Always recognised.
	client_id_issued_at: {},
	client_name: { string: true },
	client_secret_expires_at: {},
	client_uri: { string: true },
	contacts: { string: true, array: true, format: 'email' },
	default_acr_values: {
		string: true,
		array: true,
		values: (c) => c.acrValues
	},
	default_max_age: {},
	id_token_signed_response_alg: {
		string: true,
		default: 'RS256',
		values: (c) => c.idTokenSigningAlgs
	},
	initiate_login_uri: { string: true },
	jwks_uri: { string: true },
	jwks: {},
	logo_uri: { string: true },
	policy_uri: { string: true },
	require_auth_time: { default: false },
	scope: { string: true, format: 'scope-list' },
	sector_identifier_uri: { string: true },
	token_endpoint_auth_method: {
		string: true,
		default: 'client_secret_basic',
		values: (c) => c.clientAuthMethods
	},
	tos_uri: { string: true },

	// Certificate-subject values, and the mTLS endpoint aliases.
	tls_client_auth_subject_dn: { string: true, requires: MTLS_SUBJECT },
	tls_client_auth_san_dns: { string: true, requires: MTLS_SUBJECT },
	tls_client_auth_san_uri: { string: true, requires: MTLS_SUBJECT },
	tls_client_auth_san_ip: { string: true, requires: MTLS_SUBJECT },
	tls_client_auth_san_email: { string: true, requires: MTLS_SUBJECT },
	use_mtls_endpoint_aliases: { requires: MTLS_SUBJECT },

	// Unconditional, but appended after the mTLS group — see the order note above.
	token_endpoint_auth_signing_alg: {
		values: (c, s) => {
			switch (s.token_endpoint_auth_method) {
				case 'private_key_jwt':
					return c.clientAuthSigningAlgs.filter((alg) => !HMAC(alg));
				case 'client_secret_jwt':
					return c.clientAuthSigningAlgs.filter(HMAC);
				default:
					return [];
			}
		}
	},

	userinfo_signed_response_alg: {
		string: true,
		requires: ['jwtUserinfo.enabled'],
		values: (c) => c.userinfoSigningAlgs
	},

	introspection_signed_response_alg: {
		string: true,
		default: 'RS256',
		requires: JWT_INTROSPECTION,
		values: (c) => c.introspectionSigningAlgs
	},
	introspection_encrypted_response_alg: {
		string: true,
		requires: [...JWT_INTROSPECTION, 'encryption.enabled']
	},
	introspection_encrypted_response_enc: {
		string: true,
		when: ['introspection_encrypted_response_alg', A128CBC],
		requires: [...JWT_INTROSPECTION, 'encryption.enabled']
	},

	post_logout_redirect_uris: {
		string: true,
		array: true,
		default: [],
		format: 'redirect-uri',
		requires: ['rpInitiatedLogout.enabled']
	},

	backchannel_logout_session_required: {
		default: false,
		requires: ['backchannelLogout.enabled']
	},
	backchannel_logout_uri: {
		string: true,
		requires: ['backchannelLogout.enabled']
	},

	require_signed_request_object: {
		default: false,
		requires: ['requestObjects.enabled'],
		forcedBy: {
			flags: [
				'requestObjects.enabled',
				'requestObjects.requireSignedRequestObject'
			],
			value: true
		}
	},
	request_object_encryption_alg: {
		string: true,
		requires: ['requestObjects.enabled', 'encryption.enabled'],
		values: (c) => c.requestObjectEncryptionAlgs
	},
	request_object_encryption_enc: {
		string: true,
		when: ['request_object_encryption_alg', A128CBC],
		requires: ['requestObjects.enabled', 'encryption.enabled']
	},

	id_token_encrypted_response_alg: {
		string: true,
		requires: ['encryption.enabled']
	},
	id_token_encrypted_response_enc: {
		string: true,
		when: ['id_token_encrypted_response_alg', A128CBC],
		requires: ['encryption.enabled']
	},

	userinfo_encrypted_response_alg: {
		string: true,
		when: ['userinfo_signed_response_alg'],
		requires: ['encryption.enabled', 'jwtUserinfo.enabled']
	},
	userinfo_encrypted_response_enc: {
		string: true,
		when: ['userinfo_encrypted_response_alg', A128CBC],
		requires: ['encryption.enabled', 'jwtUserinfo.enabled']
	},

	authorization_signed_response_alg: {
		string: true,
		default: 'RS256',
		requires: ['responseMode.jwt.enabled'],
		values: (c) => c.authorizationSigningAlgs
	},
	authorization_encrypted_response_alg: {
		string: true,
		requires: ['responseMode.jwt.enabled', 'encryption.enabled']
	},
	authorization_encrypted_response_enc: {
		string: true,
		when: ['authorization_encrypted_response_alg', A128CBC],
		requires: ['responseMode.jwt.enabled', 'encryption.enabled']
	},

	tls_client_certificate_bound_access_tokens: {
		default: false,
		requires: ['mTLS.enabled', 'mTLS.certificateBoundAccessTokens']
	},

	backchannel_token_delivery_mode: {
		string: true,
		requires: ['ciba.enabled'],
		values: (c) => c.cibaDeliveryModes
	},
	backchannel_user_code_parameter: {
		default: false,
		requires: ['ciba.enabled']
	},
	backchannel_client_notification_endpoint: {
		string: true,
		requires: ['ciba.enabled']
	},

	// Unconditional, appended here — see the order note above.
	dpop_bound_access_tokens: { default: false },

	authorization_details_types: {
		string: true,
		array: true,
		default: [],
		requires: ['richAuthorizationRequests.enabled'],
		values: (c) => c.authorizationDetailsTypes
	}
};

/*
 * Which companion refusal a submission receives when it breaks more than one.
 *
 * This is the one thing the table cannot say about an attribute, because it is not a property of any
 * one attribute: it is precedence BETWEEN them. It reproduces the order the validator has always
 * reported in, which is not the declaration order. Listing an attribute here decides only its
 * precedence — a companion rule an entry declares is applied whether or not it is listed, so an
 * omission can reorder a refusal but can never drop one.
 *
 * Three encrypted-response algorithms deliberately declare no companion. Their signing counterpart is
 * defaulted before the companion rule runs, so "encrypted without a signing algorithm" can never be
 * refused; a declared rule that cannot fire would tell a reader it applies.
 */
const COMPANION_PRECEDENCE: readonly string[] = [
	'authorization_encrypted_response_enc',
	'id_token_encrypted_response_enc',
	'introspection_encrypted_response_enc',
	'request_object_encryption_enc',
	'userinfo_encrypted_response_enc',
	'userinfo_encrypted_response_alg',
	'authorization_encrypted_response_alg'
];

const entries = Object.entries(ATTRIBUTES);

/**
 * The attributes this deployment recognises, in the order the projected client carries them.
 * Flags arrive as an argument so this module stays import-free.
 */
export function recognizedFrom(
	flags: Readonly<Record<string, unknown>>
): string[] {
	return entries
		.filter(([, rules]) => (rules.requires ?? []).every((flag) => flags[flag]))
		.map(([name]) => name);
}

const DEFAULT: Record<string, unknown> = {};
for (const [name, rules] of entries) {
	if ('default' in rules) {
		DEFAULT[name] = rules.default;
	}
}

const ARYS: string[] = entries
	.filter(([, rules]) => rules.array)
	.map(([name]) => name);

/*
 * Scalars in code-unit order, then the list attributes in declaration order — the order the string
 * refusals have always been reported in.
 */
const STRING: string[] = [
	...entries
		.filter(([, rules]) => rules.string && !rules.array)
		.map(([name]) => name)
		.sort(),
	...ARYS.filter((name) => ATTRIBUTES[name]?.string)
];

const WHEN: Record<string, readonly [string] | readonly [string, string]> = {};
const companionOrder: string[] = [
	...COMPANION_PRECEDENCE,
	...entries
		.map(([name]) => name)
		.filter((name) => !COMPANION_PRECEDENCE.some((listed) => listed === name))
];
for (const name of companionOrder) {
	const when = ATTRIBUTES[name]?.when;
	if (when) {
		WHEN[name] = when;
	}
}

/*
 * Which value-set refusal a submission receives when it breaks more than one — precedence between
 * attributes, like the companion order above, and reproduced from the validator for the same reason.
 * Every entry that declares a value set is consulted whether or not it is listed here.
 */
const VALUE_SET_PRECEDENCE: readonly string[] = [
	'default_acr_values',
	'id_token_signed_response_alg',
	'backchannel_token_delivery_mode',
	'request_object_encryption_alg',
	'authorization_details_types',
	'token_endpoint_auth_method',
	'token_endpoint_auth_signing_alg',
	'userinfo_signed_response_alg',
	'introspection_signed_response_alg',
	'authorization_signed_response_alg'
];

type ValueSetRule = NonNullable<AttributeRules['values']>;

/** Every declared value set, in the precedence refusals are reported in. */
const VALUE_SETS: ReadonlyArray<readonly [string, ValueSetRule]> = [
	...VALUE_SET_PRECEDENCE,
	...entries
		.map(([name]) => name)
		.filter((name) => !VALUE_SET_PRECEDENCE.some((listed) => listed === name))
].flatMap((name): Array<readonly [string, ValueSetRule]> => {
	const values = ATTRIBUTES[name]?.values;
	return values ? [[name, values]] : [];
});

/*
 * The base registration keys: camelCase, picked verbatim onto the client and echoed as they are,
 * never recognised metadata. A table of their own rather than entries in the one above, because every
 * derivation from that one — the recognised set above all — must not see them: a base key recognised
 * as metadata would be projected onto the wire under a snake_case name it has never had.
 */
export type BaseAttributeRules = {
	/** Values treated as not sent, so the checks below are skipped. Defaults to `[undefined]`. */
	absent?: readonly unknown[];
	/** Refused as missing when absent. */
	required?: true;
	/** When sent, must be a non-empty string. */
	string?: true;
	/** When sent, must be a list whose members are strings. */
	array?: true;
	/** When sent, must be one of these values — refused with this exact text. */
	oneOf?: { readonly values: readonly string[]; readonly refusal: string };
	/** When sent, must be printable ASCII — refused with this exact text. */
	printable?: string;
	/** A named check, applied with the registration metadata's — see FORMAT_RANK. */
	format?: AttributeFormat;
};

/*
 * Checked in this order, and within one attribute in the order the fields are listed above — the
 * order the validator has always refused in.
 *
 * `absent` is per attribute because "not sent" genuinely differs between them: an empty string is a
 * refused application type but an absent secret, and a null redirect list is refused as not a list
 * rather than skipped. Refusal text that is not a template is stated verbatim: several of these have
 * always read differently from the generic wording, and that text is what integrators see.
 *
 * A secret's mandatory-ness is NOT here. It depends on the client's signing and encryption
 * algorithms as well as its authentication method, so it is a cross-field rule, and it is checked
 * before these run.
 */
export const BASE_ATTRIBUTES: Readonly<Record<string, BaseAttributeRules>> = {
	applicationType: {
		string: true,
		oneOf: {
			values: ['web', 'native'],
			refusal: "applicationType must be 'native' or 'web'"
		}
	},
	clientId: {
		absent: [undefined, null, ''],
		required: true,
		string: true,
		printable: 'invalid client_id value'
	},
	clientSecret: {
		absent: [undefined, null, ''],
		string: true,
		printable: 'invalid client_secret value'
	},
	subjectType: {
		string: true,
		oneOf: {
			values: ['public', 'pairwise'],
			refusal: 'subjectType must be public or pairwise'
		}
	},
	redirectUris: {
		absent: [undefined, ''],
		array: true,
		format: 'redirect-uri'
	}
};

type Formatted = readonly [string, AttributeFormat, 'metadata' | 'base'];

/*
 * Every attribute declaring a named check, in the order the checks are applied: by format, then —
 * the sort being stable — registration metadata before base keys, each in declaration order.
 */
const FORMATTED: readonly Formatted[] = [
	...entries.flatMap(([name, rules]): Formatted[] =>
		rules.format ? [[name, rules.format, 'metadata']] : []
	),
	...Object.entries(BASE_ATTRIBUTES).flatMap(([name, rules]): Formatted[] =>
		rules.format ? [[name, rules.format, 'base']] : []
	)
].sort(([, a], [, b]) => FORMAT_RANK[a] - FORMAT_RANK[b]);

/** Every attribute a deployment setting can force, with the value it forces. */
const FORCED: ReadonlyArray<
	readonly [string, NonNullable<AttributeRules['forcedBy']>]
> = entries.flatMap(
	([name, rules]): Array<
		readonly [string, NonNullable<AttributeRules['forcedBy']>]
	> => (rules.forcedBy ? [[name, rules.forcedBy]] : [])
);

const LOOPBACKS = new Set(['localhost', '127.0.0.1', '[::1]']);

export const noVSCHAR = /[^\x20-\x7E]/;

export {
	ARYS,
	DEFAULT,
	FORCED,
	FORMATTED,
	LOOPBACKS,
	STRING,
	VALUE_SETS,
	WHEN
};
