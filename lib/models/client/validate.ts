import crypto from 'node:crypto';

import QuickLRU from 'quick-lru';

import mapKeys from '../../helpers/_/map_keys.ts';
import camelCase from '../../helpers/_/camel_case.ts';
import { pick } from '../../helpers/_/object.js';
import { InvalidClientMetadata } from '../../helpers/errors.ts';
import getSchema, { buildRecognizedMetadata } from './schema.ts';
import { ClientDefaults } from '../../configs/clientBase.js';
import { onSettingsApplied } from '../../configs/application.js';
import { ClientSchema } from '../../configs/clientSchema.js';
import { type Client, type ClientRecord } from './types.ts';
import { Value } from '@sinclair/typebox/value';
import { adapter } from '../../adapters/index.js';
import { resolveClientDocument } from '../../client_metadata_document/resolve.js';
import { validateJWK } from './keystore.ts';
import { registerClient } from './register.ts';

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
	'consent.require',
	/*
	 * Whether the server created this client on its own request. A base key rather than recognised
	 * metadata: it is not something a client may send — `lib/actions/registration.ts` sets it after the
	 * wire translation precisely so a registration body cannot claim it — and it must survive the
	 * round trip through storage, which only keeps what is picked here.
	 */
	'registeredDynamically',
	'registrationUsedAt'
];

// Validate raw metadata → plain, frozen client object (defaults applied,
// recognised metadata camelCased) or throw InvalidClientMetadata. Key material
// is derived beside the client, on first use, by clientKeys().
export function validateClient(metadata: ClientRecord): Client {
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

	const client = { ...pick(clientMetadataInput, ...BASE_METADATA_KEYS) };
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
	if (!Value.Check(ClientSchema, client)) {
		throw new InvalidClientMetadata(
			'client metadata validation error',
			[...Value.Errors(ClientSchema, client)]
				.map(({ message, path }) => `${path} ${message}`.trim())
				.join(', ')
		);
	}

	// Checked here although the key set is built later, so an invalid one refuses the client now.
	client.jwks?.keys.forEach(validateJWK);

	/*
	 * Frozen because one validated client is shared by every request using it until its record
	 * changes, so a change made while handling one request would be seen by all of them. A copy is
	 * frozen rather than the object built above, whose arrays may be the stored record's own or the
	 * shared defaults'.
	 */
	/*
	 * Asserted, because ClientSchema cannot say which of its optional attributes a default always
	 * fills. AlwaysPresent (./types.ts) says it, and client_metadata.spec.ts proves it for every
	 * attribute the declaration gives an ungated default.
	 */
	return deepFreeze(structuredClone(client)) as Client;
}

function deepFreeze<T>(value: T): T {
	if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
		Object.values(value).forEach(deepFreeze);
		Object.freeze(value);
	}
	return value;
}

// Validation memo, owned by its only consumer below. Size-bounded (LRU) — no time-based expiry,
// which would drop entries out from under in-flight resolutions.
const clientCache = new QuickLRU<string, Client>({ maxSize: 100 });

/*
 * The key is a hash of the client's STORED properties, so a settings change does not change it — and
 * the schema a client is validated against is derived from the settings. Without this, a capability
 * switched on would govern a client nobody had resolved yet and not one already in the memo, which is
 * the difference between a setting that applies and a setting that appears to.
 */
onSettingsApplied(() => clientCache.clear());

// Resolve a client by id from adapter('Client') — the single source of client
// identity. The adapter is read on every call so updates and deletes are always
// reflected immediately (a stale-metadata window would violate FR-009 and the
// security-first principle); the memo above only holds the *validated* object,
// keyed by a hash of the stored properties, so unchanged clients skip
// re-validation. Nullable variant behind `Client.tryFind`; the strict
// `Client.find` wraps this and throws on miss.
export async function tryFindClient(id: string): Promise<Client | undefined> {
	const properties = await adapter('Client').find(id);
	if (!properties) {
		/*
		 * A `client_id` that is an https URL naming a document describing the client, resolved by
		 * retrieval instead of by a stored record and stored nowhere.
		 *
		 * Placed AFTER the adapter read, and that order is load-bearing rather than incidental. A
		 * URL-shaped client id is not new here: `test/client_id_uri/` covers dynamic registration
		 * issuing one through a deployment's `idFactory`. A branch placed before this read would shadow
		 * every such stored client with a document retrieval that must fail, taking that suite — and any
		 * deployment relying on it — with it. Adapter-first is also the safer direction on its own
		 * terms: a stored record always wins, and a registered client cannot claim a legitimate
		 * document identifier because its id is server-generated, never client-chosen.
		 */
		const document = await resolveClientDocument(id);
		if (!document) {
			return;
		}
		/*
		 * Not memoized. The document's own reuse window is the cache (`cache.ts`), bounded by what its
		 * host said; a second memo keyed on content would extend that silently past the bound the
		 * operator's host asked for.
		 */
		return registerClient(document, { store: false });
	}

	const propHash = crypto.hash(
		'sha256',
		JSON.stringify(properties),
		'base64url'
	);
	let client = clientCache.get(propHash);
	if (!client) {
		// No sector check: that runs when a client is written (register.ts), not each time it is used.
		client = validateClient(properties);
		clientCache.set(propHash, client);
	}

	return client;
}
