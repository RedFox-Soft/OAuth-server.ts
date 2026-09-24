import type { JWK } from 'jose';

// What a signing or verification key is selected by: an algorithm, or a key type when no algorithm
// is known yet. `use` is accepted and implied ('sig').
type SignatureSelection = {
	alg?: string;
	kid?: string;
	kty?: string | string[];
	crv?: string;
	use?: string;
};

// What an encryption or decryption key is selected by; `epk` is the sender's ephemeral key, if any.
type EncryptionSelection = {
	alg: string;
	kid?: string;
	kty?: string | string[];
	epk?: { crv?: unknown };
	use?: string;
};

type Scoring = { alg?: string; use?: string };

const keyscore = (key: JWK, { alg, use }: Scoring) => {
	let score = 0;

	if (alg && key.alg) {
		score++;
	}

	if (use && key.use) {
		score++;
	}

	return score;
};

const getKtyFromJWSAlg = (alg: string | undefined): string => {
	switch (alg?.substring(0, 2)) {
		case 'RS':
		case 'PS':
			return 'RSA';
		case 'HS':
			return 'oct';
		case 'ES':
			return 'EC';
		case 'Ed':
			return 'OKP';
		default:
			throw new Error();
	}
};

const getCrvFromJWSAlg = (alg: string | undefined) => {
	switch (alg) {
		case 'ES256':
			return 'P-256';
		case 'ES384':
			return 'P-384';
		case 'ES512':
			return 'P-521';
		case 'EdDSA':
		case 'Ed25519':
			return 'Ed25519';
		default:
			return undefined;
	}
};

const getKtyFromJWEAlg = (
	alg: string,
	epk: EncryptionSelection['epk']
): string | string[] => {
	switch (alg[0]) {
		case 'A':
			return 'oct';
		case 'R':
			return 'RSA';
		case 'E': {
			if (epk) {
				return typeof epk.crv === 'string' && epk.crv.startsWith('X')
					? 'OKP'
					: 'EC';
			}

			return ['OKP', 'EC'];
		}
		default:
			throw new Error();
	}
};

function stripPrivate(jwk: JWK): JWK {
	const { d, p, q, dp, dq, qi, oth, ...pub } = jwk;
	return pub;
}

class KeyStore {
	#keys: JWK[];

	#cachedPub?: WeakMap<JWK, JWK>;

	// This store backs both the server's own keys and per-client key stores, whose members differ by
	// key type (RSA/EC/OKP/oct); jose's JWK names every member any of them carries.
	constructor(keys: JWK[] = []) {
		this.#keys = keys;
	}

	#selectForDSA(options: SignatureSelection, operation: 'sign' | 'verify') {
		const {
			alg,
			kid,
			kty = getKtyFromJWSAlg(alg),
			crv = getCrvFromJWSAlg(alg)
		} = options;

		const scoring = { alg, use: 'sig' };

		return this.#filter((jwk) => {
			let candidate =
				typeof kty === 'string'
					? jwk.kty === kty
					: jwk.kty !== undefined && kty.includes(jwk.kty);

			if (candidate && typeof kid === 'string') {
				candidate = kid === jwk.kid;
			}

			if (candidate && typeof jwk.alg === 'string') {
				candidate = alg === jwk.alg;
			}

			if (candidate && typeof jwk.use === 'string') {
				candidate = jwk.use === 'sig';
			}

			if (candidate && crv) {
				candidate = jwk.crv === crv;
			}

			if (candidate && Array.isArray(jwk.key_ops)) {
				candidate = jwk.key_ops.includes(operation);
			}

			return candidate;
		}, scoring);
	}

	selectForVerify(options: SignatureSelection) {
		return this.#selectForDSA(options, 'verify');
	}

	selectForSign(options: SignatureSelection) {
		return this.#selectForDSA(options, 'sign');
	}

	#selectForEncDec(
		options: EncryptionSelection,
		operation: 'encrypt' | 'decrypt'
	) {
		const { alg, kid, epk, kty = getKtyFromJWEAlg(alg, epk) } = options;

		const scoring = { alg, use: 'enc' };

		return this.#filter((jwk) => {
			let candidate = Array.isArray(kty)
				? jwk.kty !== undefined && kty.includes(jwk.kty)
				: jwk.kty === kty;

			if (candidate && kid !== undefined) {
				candidate = kid === jwk.kid;
			}

			if (candidate && jwk.alg !== undefined) {
				candidate = alg === jwk.alg;
			}

			if (candidate && jwk.use !== undefined) {
				candidate = jwk.use === 'enc';
			}

			if (candidate && epk) {
				candidate = epk.crv === jwk.crv;
			}

			if (candidate && Array.isArray(jwk.key_ops)) {
				switch (kty) {
					case 'RSA': {
						candidate = jwk.key_ops.includes(operation);
						break;
					}
					case 'EC':
					case 'OKP': {
						if (operation === 'decrypt')
							candidate = jwk.key_ops.includes('deriveBits');
						break;
					}
					default:
				}
			}

			return candidate;
		}, scoring);
	}

	selectForDecrypt(options: EncryptionSelection) {
		return this.#selectForEncDec(options, 'decrypt');
	}

	selectForEncrypt(options: EncryptionSelection) {
		return this.#selectForEncDec(options, 'encrypt');
	}

	#filter(selector: (jwk: JWK) => boolean, scoring: Scoring) {
		return this.#keys
			.filter(selector)
			.sort(
				(first, second) => keyscore(second, scoring) - keyscore(first, scoring)
			);
	}

	add(key: JWK) {
		this.#keys.push(key);
	}

	clear() {
		this.#keys = [];
	}

	getKeyObject(input: JWK, getPublic = false): JWK {
		if (input.kty === 'oct' || !input.d || !getPublic) {
			return input;
		}

		this.#cachedPub ||= new WeakMap();

		if (!this.#cachedPub.has(input)) {
			this.#cachedPub.set(input, stripPrivate(input));
		}

		return this.#cachedPub.get(input) ?? input;
	}

	*[Symbol.iterator]() {
		for (const key of this.#keys) {
			yield key;
		}
	}
}

export default KeyStore;
