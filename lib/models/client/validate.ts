import crypto from 'node:crypto';

import QuickLRU from 'quick-lru';

import mapKeys from '../../helpers/_/map_keys.ts';
import snakeCase from '../../helpers/_/snake_case.ts';
import camelCase from '../../helpers/_/camel_case.ts';
import { pick } from '../../helpers/_/object.js';
import { InvalidClientMetadata } from '../../helpers/errors.ts';
import sectorValidate from '../../helpers/sector_validate.ts';
import getSchema, { buildRecognizedMetadata } from './schema.ts';
import addClient from '../../helpers/add_client.ts';
import { provider } from '../../provider.js';
import { ClientDefaults } from '../../configs/clientBase.js';
import {
	ClientSchema,
	type ClientSchemaType
} from '../../configs/clientSchema.js';
import { Value } from '@sinclair/typebox/value';
import { adapter } from '../../adapters/index.js';
import { sectorIdentifier } from './sector.ts';
import {
	responseTypeAllowed,
	responseModeAllowed,
	grantTypeAllowed,
	redirectUriAllowed,
	postLogoutRedirectUriAllowed,
	includeSid
} from './checks.ts';
import { compareClientSecret, checkClientSecretExpiration } from './secret.ts';
import { backchannelPing, backchannelLogout } from './backchannel.ts';
import {
	ClientKeyStore,
	buildAsymmetricKeyStore,
	buildSymmetricKeyStore,
	validateJWK
} from './keystore.ts';

// The base registration keys copied verbatim from the raw input. Frozen here so
// expanding `ClientSchema` to describe the full validated-object type (the rest
// of the metadata is produced by the schema engine and camelCased) cannot change
// which raw keys are picked — keeping `validateClient` behaviour-neutral.
const BASE_METADATA_KEYS = [
	'clientId',
	'clientSecret',
	'redirectUris',
	'applicationType',
	'responseTypes',
	'responseModes',
	'grantTypes',
	'subjectType',
	'authorization.requirePushedAuthorizationRequests',
	'requestObject.require',
	'requestObject.signingAlg',
	'requestObject.backChannelSigningAlg',
	'consent.require'
];

// camelCase → snake_case metadata projection honouring RECOGNIZED_METADATA.
// Replaces the former `client.metadata()` instance method.
export function clientMetadata(
	client: ClientSchemaType
): Record<string, unknown> {
	const recognized = buildRecognizedMetadata();

	return mapKeys(client, (value, key) => {
		const snaked = snakeCase(key);
		if (!recognized.includes(snaked)) {
			return key;
		}

		return snaked;
	});
}

// Prototype for validated client objects. The former `Client` class methods
// become thin delegators to the pure functions (the single source of truth),
// and the derived accessors stay as getters. Living on the prototype keeps them
// non-own/non-enumerable so they are excluded from `clientMetadata`'s
// projection and `instanceof`-free spying/restoration behaves as before — the
// object is a plain object (no `class`), but exposes the exact method surface
// the integration suite (the oracle) and call sites rely on.
export const clientPrototype = {
	responseTypeAllowed(type) {
		return responseTypeAllowed(this, type);
	},
	responseModeAllowed(responseMode) {
		return responseModeAllowed(this, responseMode);
	},
	grantTypeAllowed(type) {
		return grantTypeAllowed(this, type);
	},
	redirectUriAllowed(value) {
		return redirectUriAllowed(this, value);
	},
	postLogoutRedirectUriAllowed(value) {
		return postLogoutRedirectUriAllowed(this, value);
	},
	includeSid() {
		return includeSid(this);
	},
	compareClientSecret(actual) {
		return compareClientSecret(this, actual);
	},
	checkClientSecretExpiration(message, errorOverride) {
		return checkClientSecretExpiration(this, message, errorOverride);
	},
	metadata() {
		return clientMetadata(this);
	},
	backchannelPing(backchannelAuthenticationRequest) {
		return backchannelPing(this, backchannelAuthenticationRequest);
	},
	backchannelLogout(sub, sid) {
		return backchannelLogout(this, sub, sid);
	},
	get clientAuthMethod() {
		return this.tokenEndpointAuthMethod;
	},
	get clientAuthSigningAlg() {
		return this.tokenEndpointAuthSigningAlg;
	},
	get sectorIdentifier() {
		return sectorIdentifier(this);
	}
};

// Validate raw metadata → plain client object (defaults applied, recognised
// metadata camelCased, key stores built) or throw InvalidClientMetadata.
// Replaces the former Client-class constructor validation path.
export function validateClient(metadata: unknown): ClientSchemaType {
	const Schema = getSchema();
	const recognized = buildRecognizedMetadata();
	const clientMetadataInput = {
		...ClientDefaults,
		...(metadata as object)
	};
	const schema = new Schema(clientMetadataInput);

	// Grant-only clients (client_credentials, device_code) carry no redirect URIs.
	// The schema pass above already rejects an absent value when responseTypes are
	// present (mandatory), so reaching here with no redirectUris means none are
	// required — normalise to the empty list before the structural check.
	if (clientMetadataInput.redirectUris === undefined) {
		clientMetadataInput.redirectUris = [];
	}

	const client = Object.create(clientPrototype);
	Object.assign(client, pick(clientMetadataInput, ...BASE_METADATA_KEYS));
	Object.assign(
		client,
		mapKeys(schema, (value, key) => {
			if (!recognized.includes(key)) {
				return key;
			}

			return camelCase(key);
		})
	);

	// TypeBox validates the *projected* (camelCased/dotted) client object — the real
	// validated shape — not the raw snake_case input. This is what makes ClientSchema's
	// camelCase literal unions and formats authoritative for the recognized metadata
	// (whose keys are snake_case on input and never matched the camelCase schema keys).
	// Runs before key-store construction so an invalid client never builds key stores.
	if (!Value.Check(ClientSchema, client)) {
		throw new InvalidClientMetadata(
			'client metadata validation error',
			[...Value.Errors(ClientSchema, client)]
				.map(({ message, path }) => `${path} ${message}`.trim())
				.join(', ')
		);
	}

	buildAsymmetricKeyStore(client);
	buildSymmetricKeyStore(client);

	if (client.jwks) {
		client.jwks.keys
			.map(validateJWK)
			.filter(Boolean)
			.forEach(ClientKeyStore.prototype.add.bind(client.asymmetricKeyStore));
	}

	return client;
}

// Replaces the former static `Client.validate(metadata)` — runs sector
// validation when sectorIdentifierUri is set.
export async function assertClientValid(metadata: unknown): Promise<void> {
	const client = validateClient(metadata);

	if (client.sectorIdentifierUri !== undefined) {
		await sectorValidate(provider, client);
	}
}

// Validation memo, owned by its only consumer below. Size-bounded (LRU) — no time-based expiry,
// which would drop entries out from under in-flight resolutions.
const clientCache = new QuickLRU<string, ClientSchemaType>({ maxSize: 100 });

// Resolve a client by id from adapter('Client') — the single source of client
// identity. The adapter is read on every call so updates and deletes are always
// reflected immediately (a stale-metadata window would violate FR-009 and the
// security-first principle); the memo above only holds the *validated* object,
// keyed by a hash of the stored properties, so unchanged clients skip
// re-validation. Nullable variant behind `Client.tryFind`; the strict
// `Client.find` wraps this and throws on miss.
export async function tryFindClient(
	id: string
): Promise<ClientSchemaType | undefined> {
	const properties = await adapter('Client').find(id);
	if (!properties) {
		return;
	}

	const propHash = crypto.hash(
		'sha256',
		JSON.stringify(properties),
		'base64url'
	);
	let client = clientCache.get(propHash);
	if (!client) {
		client = await addClient(provider, properties, { store: false });
		clientCache.set(propHash, client);
	}

	return client;
}
