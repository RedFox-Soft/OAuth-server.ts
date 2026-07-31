import { hkdfSync } from 'node:crypto';
import * as base64url from './base64url.js';
import { ApplicationConfig } from 'lib/configs/application.js';
import { isUsableNonceSecret } from 'lib/configs/nonceSecret.js';

function sixfourbeify(value: number): Uint8Array<ArrayBuffer> {
	const buf = Buffer.alloc(8);
	for (let i = buf.length - 1; i >= 0; i--) {
		buf[i] = value & 0xff;
		value >>= 8;
	}

	return buf;
}

function compute(secret: Uint8Array<ArrayBuffer>, step: number) {
	return base64url.encodeBuffer(
		Buffer.from(hkdfSync('sha256', secret, sixfourbeify(step), '', 32))
	);
}

function compare(server: string, client: string) {
	let result = 0;

	if (server.length !== client.length) {
		result = 1;
		client = server;
	}

	for (let i = 0; i < server.length; i++) {
		result |= server.charCodeAt(i) ^ client.charCodeAt(i);
	}

	return result;
}

const STEP = 60;

export class DPoPNonces {
	#counter;

	#secret;

	#prevprev: string;
	#prev: string;
	#now: string;
	#next: string;
	#nextnext: string;

	constructor(secret: Uint8Array | undefined) {
		// The same predicate configs/configuration.ts validates with, so there is exactly one definition
		// of a usable secret. Before spec 014 this check was the only one, and it ran here — on the
		// request path, outside any try — which is how an unusable secret turned every DPoP-bearing
		// request into a 500. It is kept as the definition of the constraint, not as a live guard:
		// configs/nonceSecret.ts resolves a usable secret before the server serves anything.
		if (!isUsableNonceSecret(secret)) {
			throw new TypeError('dpop.nonceSecret must be 32 bytes of byte material');
		}

		this.#secret = Uint8Array.prototype.slice.call(secret);
		this.#counter = Math.floor(Date.now() / 1000 / STEP);

		[this.#prevprev, this.#prev, this.#now, this.#next, this.#nextnext] = [
			this.#counter - 2,
			this.#counter - 1,
			this.#counter,
			this.#counter + 1,
			this.#counter++ + 2
		].map((_) => compute(this.#secret, _));

		setInterval(() => {
			[this.#prevprev, this.#prev, this.#now, this.#next, this.#nextnext] = [
				this.#prev,
				this.#now,
				this.#next,
				this.#nextnext,
				compute(this.#secret, this.#counter++ + 2)
			];
		}, STEP * 1000).unref();
	}

	nextNonce(): string {
		return this.#next;
	}

	checkNonce(nonce: string): boolean {
		let result = 0;

		for (const server of [
			this.#prevprev,
			this.#prev,
			this.#now,
			this.#next,
			this.#nextnext
		]) {
			result ^= compare(server, nonce);
		}

		return result === 0;
	}

	static #singleton: DPoPNonces | undefined;

	/*
	 * Always returns a generator. That is the whole of what spec 014 changed here, and it is what let
	 * four `throw new Error('dpop.nonceSecret configuration is missing')` sites be deleted rather than
	 * merely tidied: a caller cannot handle an absent generator wrongly if there is no absent case to
	 * handle. configs/nonceSecret.ts resolves a usable secret before the server serves anything, so
	 * the only remaining check is the constructor's, kept as the definition of the constraint.
	 *
	 * The `enabling` static that used to gate this is gone. It existed so a test could fabricate a
	 * server with DPoP on and no nonce generator — a state no deployment can now be in, so a test
	 * asserting behaviour for it was asserting a fiction.
	 */
	static fabrica(): DPoPNonces {
		return (DPoPNonces.#singleton ??= new DPoPNonces(
			ApplicationConfig['dpop.nonceSecret']
		));
	}
}
