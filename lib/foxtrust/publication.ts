import { ApplicationConfig } from '../configs/application.js';
import { FOXTRUST_TIMEOUT_MS } from '../consts/foxtrust_publication.js';
import { packageVersion } from '../helpers/package_version.js';

/*
 * The transport both readers of FoxTrust's publication share (specs/125 research R2, specs/129 research R2): requests
 * that carry nothing about this instance, bodies read no further than a cap, and paths kept inside the publication.
 * What a reader then trusts is its own business; this module only fetches bytes and says why it could not.
 */

export type PublicationFailureKind = 'size' | 'header' | 'network' | 'http';

export class PublicationFailure extends Error {
	constructor(readonly kind: PublicationFailureKind) {
		super(kind);
	}
}

/* No instance identifier, key or cookie leaves with these requests; the version only while usage reports are on. */
export function userAgent(): string {
	const version = packageVersion();
	return ApplicationConfig['telemetry.enabled'] && version !== undefined
		? `FoxAuth/${version}`
		: 'FoxAuth';
}

export async function get(
	url: string,
	headers: Record<string, string> = {}
): Promise<Response> {
	let response: Response;
	try {
		response = await fetch(url, {
			headers: { 'user-agent': userAgent(), ...headers },
			redirect: 'manual',
			signal: AbortSignal.timeout(FOXTRUST_TIMEOUT_MS)
		});
	} catch {
		throw new PublicationFailure('network');
	}
	if (response.status !== 200 && response.status !== 304) {
		throw new PublicationFailure('http');
	}
	return response;
}

/*
 * The body, read no further than `cap`. The publication may be served compressed through a CDN and the runtime
 * decompresses it, so Content-Length is absent or counts the compressed bytes: the cap is held on what is read.
 * With `expected` (a size the signed manifest states) the bytes go straight into one buffer of that size, so a large
 * file is never held twice while it is read; a body of any other length is a `size` failure.
 */
export async function readCapped(
	response: Response,
	cap: number,
	expected?: number
): Promise<Uint8Array<ArrayBuffer>> {
	const reader = response.body?.getReader();
	if (!reader) {
		if (expected !== undefined && expected !== 0) {
			throw new PublicationFailure('size');
		}
		return new Uint8Array();
	}
	if (expected !== undefined) {
		if (expected > cap) {
			await reader.cancel();
			throw new PublicationFailure('size');
		}
		const out = new Uint8Array(expected);
		let offset = 0;
		for (;;) {
			const { done, value } = await reader.read();
			if (done) break;
			if (offset + value.byteLength > expected) {
				await reader.cancel();
				throw new PublicationFailure('size');
			}
			out.set(value, offset);
			offset += value.byteLength;
		}
		if (offset !== expected) throw new PublicationFailure('size');
		return out;
	}
	const chunks: Uint8Array[] = [];
	let total = 0;
	for (;;) {
		const { done, value } = await reader.read();
		if (done) break;
		total += value.byteLength;
		if (total > cap) {
			await reader.cancel();
			throw new PublicationFailure('size');
		}
		chunks.push(value);
	}
	const out = new Uint8Array(total);
	let offset = 0;
	for (const chunk of chunks) {
		out.set(chunk, offset);
		offset += chunk.byteLength;
	}
	return out;
}

/* A whole body that must be there (status 200), read under `cap`. */
export async function getBytes(
	url: string,
	cap: number
): Promise<Uint8Array<ArrayBuffer>> {
	const response = await get(url);
	if (response.status !== 200) throw new PublicationFailure('http');
	return readCapped(response, cap);
}

/* A path the manifest names, kept inside the publication: no scheme, no host, no climbing out. */
export function fileUrl(base: string, path: string): string {
	if (
		!/^v1\/[A-Za-z0-9/_.-]+$/.test(path) ||
		path.includes('..') ||
		path.includes('//')
	) {
		throw new PublicationFailure('header');
	}
	return `${base}/${path}`;
}

export async function sha256Hex(
	bytes: Uint8Array<ArrayBuffer>
): Promise<string> {
	const digest = await crypto.subtle.digest('SHA-256', bytes);
	return Buffer.from(digest).toString('hex');
}
