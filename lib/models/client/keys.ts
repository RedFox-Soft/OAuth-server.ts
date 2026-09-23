import crypto from 'node:crypto';

import KeyStore from '../../helpers/keystore.ts';
import * as base64url from '../../helpers/base64url.ts';
import {
	clientAuthSigningAlgValues,
	requestObjectEncryptionAlgValues,
	requestObjectEncryptionEncValues,
	requestObjectSigningAlgValues
} from '../../configs/jwaAlgorithms.js';
import { type Client } from './types.ts';
import { ClientKeyStore, validateJWK } from './keystore.ts';

export interface ClientKeys {
	readonly symmetric: KeyStore;
	readonly asymmetric: ClientKeyStore;
}

/*
 * Key material derived from a client, kept beside it rather than on it. Keyed by the validated client
 * object, which the validation memo holds for as long as its stored record is unchanged — so the keys,
 * and the public key set's fetch state, live exactly as long as the client they were derived from: a
 * changed record is a new client and gets new keys, and an evicted client takes its keys with it.
 */
const derived = new WeakMap<object, ClientKeys>();

export function clientKeys(client: Client): ClientKeys {
	let keys = derived.get(client);
	if (!keys) {
		keys = {
			symmetric: deriveSymmetricKeys(client),
			asymmetric: new ClientKeyStore({
				keys: (client.jwks?.keys ?? [])
					.map(validateJWK)
					.filter((key) => key !== undefined),
				jwksUri: client.jwksUri,
				thumbprintCertificates:
					client.tokenEndpointAuthMethod === 'self_signed_tls_client_auth'
			})
		};
		derived.set(client, keys);
	}
	return keys;
}

function deriveEncryptionKey(secret: string, length: number): Buffer {
	const digest =
		length <= 32
			? 'sha256'
			: length <= 48
				? 'sha384'
				: length <= 64
					? 'sha512'
					: false;
	if (!digest) {
		throw new Error('unsupported symmetric encryption key derivation');
	}
	return crypto.hash(digest, secret, 'buffer').subarray(0, length);
}

function deriveSymmetricKeys(client: Client): KeyStore {
	const store = new KeyStore();
	const algs = new Set<string>();
	const add = (alg: string | undefined) => {
		if (alg !== undefined) algs.add(alg);
	};

	if (client.clientSecret) {
		if (client.tokenEndpointAuthMethod === 'client_secret_jwt') {
			if (client.tokenEndpointAuthSigningAlg) {
				add(client.tokenEndpointAuthSigningAlg);
			} else {
				clientAuthSigningAlgValues.forEach(Set.prototype.add.bind(algs));
			}
		}

		(
			[
				'introspectionSignedResponseAlg',
				'userinfoSignedResponseAlg',
				'authorizationSignedResponseAlg',
				'idTokenSignedResponseAlg',
				'requestObject.signingAlg'
			] as const
		).forEach((prop) => {
			add(client[prop]);
		});

		if (!client['requestObject.signingAlg']) {
			requestObjectSigningAlgValues.forEach(Set.prototype.add.bind(algs));
		}

		requestObjectEncryptionAlgValues.forEach(Set.prototype.add.bind(algs));

		if (requestObjectEncryptionAlgValues.includes('dir')) {
			requestObjectEncryptionEncValues.forEach(Set.prototype.add.bind(algs));
		}

		(
			[
				['idTokenEncryptedResponseAlg', 'idTokenEncryptedResponseEnc'],
				['userinfoEncryptedResponseAlg', 'userinfoEncryptedResponseEnc'],
				[
					'introspectionEncryptedResponseAlg',
					'introspectionEncryptedResponseEnc'
				],
				[
					'authorizationEncryptedResponseAlg',
					'authorizationEncryptedResponseEnc'
				]
			] as const
		).forEach(([alg, enc]) => {
			add(client[alg]);
			if (client[alg] === 'dir') {
				add(client[enc]);
			}
		});

		for (const alg of algs) {
			if (!(
				alg.startsWith('HS') ||
				/^A(\d{3})(?:GCM)?KW$/.test(alg) ||
				/^A(\d{3})(?:GCM|CBC-HS(\d{3}))$/.test(alg)
			)) {
				algs.delete(alg);
			}
		}

		for (const alg of algs) {
			if (alg.startsWith('HS')) {
				store.add({
					alg,
					use: 'sig',
					kty: 'oct',
					k: base64url.encode(client.clientSecret)
				});
			} else if (/^A(\d{3})(?:GCM)?KW$/.test(alg)) {
				const len = parseInt(RegExp.$1, 10) / 8;
				store.add({
					alg,
					use: 'enc',
					kty: 'oct',
					k: deriveEncryptionKey(client.clientSecret, len).toString('base64url')
				});
			} else if (/^A(\d{3})(?:GCM|CBC-HS(\d{3}))$/.test(alg)) {
				const len = parseInt(RegExp.$2 || RegExp.$1, 10) / 8;
				store.add({
					alg,
					use: 'enc',
					kty: 'oct',
					k: deriveEncryptionKey(client.clientSecret, len).toString('base64url')
				});
			}
		}
	}

	return store;
}
