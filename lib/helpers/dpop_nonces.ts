import { hkdfSync } from 'node:crypto';
import * as base64url from './base64url.js';
import { ApplicationConfig } from 'lib/configs/application.js';

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

	constructor(secret: Buffer) {
		if (!Buffer.isBuffer(secret) || secret.byteLength !== 32) {
			throw new TypeError(
				'features.dPoP.nonceSecret must be a 32-byte Buffer instance'
			);
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

	static enabling = true;
	static #singleton: DPoPNonces | undefined;
	static fabrica(): DPoPNonces | undefined {
		const nonceSecret = ApplicationConfig['dpop.nonceSecret'];
		if (DPoPNonces.enabling && nonceSecret !== undefined) {
			return (DPoPNonces.#singleton ??= new DPoPNonces(nonceSecret));
		}
	}
}
