import { spyOn } from 'bun:test';

import { fetchAnswering } from '../fetch_mock.ts';
import { setClockForTests } from 'lib/telemetry/clock.ts';
import { attackerListPass, type PassOutcome } from 'lib/attacker_list/fetch.ts';
import { resetAttackerListForTests } from 'lib/attacker_list/state.ts';
import { resetAttackerListSchedulerForTests } from 'lib/attacker_list/scheduler.ts';
import { resetListedCountsForTests } from 'lib/attacker_list/counters.ts';

/*
 * A stand-in for FoxTrust's publication (contract format 1, https://foxtrust.dev/docs/snapshots "Attacker list"),
 * signing with a key generated here and passed to the pass through its seam. Nothing reaches the network: every
 * request is answered from `files`, and a request for anything else fails.
 */

export const BASE = 'https://publication.test';

export interface ListLine {
	readonly network: string;
	readonly lastSeen: number;
	readonly corroborated?: boolean;
	readonly code?: string;
}

export interface Signer {
	readonly keys: Record<string, string>;
	sign(bytes: Uint8Array<ArrayBuffer>): Promise<Uint8Array<ArrayBuffer>>;
}

export async function signer(keyId = 'test0001'): Promise<Signer> {
	const pair = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, [
		'sign',
		'verify'
	]);
	const raw = await crypto.subtle.exportKey('raw', pair.publicKey);
	return {
		keys: { [keyId]: Buffer.from(raw).toString('base64') },
		sign: async (bytes) =>
			new Uint8Array(
				await crypto.subtle.sign('Ed25519', pair.privateKey, bytes)
			)
	};
}

const encoder = new TextEncoder();

export function listFile(options: {
	version: string;
	builtAt: string;
	validUntil: string;
	lines: readonly ListLine[];
	kind?: string;
	format?: number;
	dispute?: string;
}): Uint8Array<ArrayBuffer> {
	const header = {
		kind: options.kind ?? 'foxtrust-attackers',
		format: options.format ?? 1,
		version: options.version,
		builtAt: options.builtAt,
		validUntil: options.validUntil,
		windowDays: 7,
		entries: options.lines.length,
		columns: ['network', 'code', 'last_seen', 'band', 'corroborated'],
		rules: '2026-11-09.1',
		rulesSha256: 'x',
		dataVersion: 'x',
		dispute: options.dispute ?? 'https://foxtrust.dev/dispute'
	};
	const body = options.lines.map(
		(line) =>
			`${line.network}\t${line.code ?? 'login_bruteforce'}\t${String(line.lastSeen)}\tweak\t${line.corroborated ? '1' : '0'}`
	);
	return encoder.encode(`${[JSON.stringify(header), ...body].join('\n')}\n`);
}

interface Served {
	bytes: Uint8Array<ArrayBuffer>;
	etag?: string;
}

export interface Publication {
	readonly files: Map<string, Served>;
	readonly requests: { url: string; headers: Headers }[];
	/* Publishes a list and a manifest pointing at it, both signed by `by` unless overridden. */
	publish(options: {
		version: string;
		builtAt: string;
		validUntil: string;
		lines: readonly ListLine[];
		by: Signer;
		fileSignedBy?: Signer;
		manifestSize?: number;
		manifestSha256?: string;
		format?: string;
		file?: Uint8Array<ArrayBuffer>;
	}): Promise<void>;
}

async function sha256Hex(bytes: Uint8Array<ArrayBuffer>): Promise<string> {
	return Buffer.from(await crypto.subtle.digest('SHA-256', bytes)).toString(
		'hex'
	);
}

export function publication(): Publication {
	const files = new Map<string, Served>();
	const requests: { url: string; headers: Headers }[] = [];
	spyOn(globalThis, 'fetch').mockImplementation(
		fetchAnswering(async (input, init) => {
			const url = input instanceof Request ? input.url : String(input);
			requests.push({ url, headers: new Headers(init?.headers) });
			if (!url.startsWith(`${BASE}/`)) {
				throw new TypeError(`unexpected request to ${url}`);
			}
			const served = files.get(url.slice(BASE.length + 1));
			if (!served) return new Response('not found', { status: 404 });
			const ifNoneMatch = new Headers(init?.headers).get('if-none-match');
			if (served.etag && ifNoneMatch === served.etag) {
				return new Response(null, { status: 304 });
			}
			return new Response(served.bytes, {
				status: 200,
				headers: served.etag ? { etag: served.etag } : {}
			});
		})
	);
	return {
		files,
		requests,
		async publish(options) {
			const file =
				options.file ??
				listFile({
					version: options.version,
					builtAt: options.builtAt,
					validUntil: options.validUntil,
					lines: options.lines
				});
			const path = `v1/attackers/1/${options.version}.txt`;
			files.set(path, { bytes: file, etag: `"${options.version}"` });
			files.set(`${path}.sig`, {
				bytes: await (options.fileSignedBy ?? options.by).sign(file)
			});
			const manifest = {
				attackers: {
					[options.format ?? '1']: {
						version: options.version,
						path,
						sha256: options.manifestSha256 ?? (await sha256Hex(file)),
						size: options.manifestSize ?? file.byteLength,
						builtAt: options.builtAt,
						validUntil: options.validUntil,
						entries: options.lines.length,
						keyId: Object.keys(options.by.keys)[0]
					}
				}
			};
			const manifestBytes = encoder.encode(JSON.stringify(manifest));
			files.set('v1/manifest.json', { bytes: manifestBytes });
			files.set('v1/manifest.json.sig', {
				bytes: await options.by.sign(manifestBytes)
			});
		}
	};
}

/* One check against the stand-in publication, trusting `by`'s key. */
export function pass(by: Signer): Promise<PassOutcome> {
	return attackerListPass({ base: BASE, keys: by.keys });
}

const HOUR_MS = 60 * 60 * 1000;

/*
 * Times relative to the current case's start, so validity and recency are exact. Each case starts a day after the one
 * before it: the instance remembers the newest list it accepted, as it must, so a case reusing an earlier case's
 * times would meet that memory instead of the behaviour it is about.
 */
let caseStart = Date.UTC(2026, 10, 9, 18, 50);
export const at = (hours: number) => new Date(caseStart + hours * HOUR_MS);
export const iso = (hours: number) => at(hours).toISOString();
export const seconds = (hours: number) =>
	Math.floor((caseStart + hours * HOUR_MS) / 1000);

/* Holds the list's clock (lib/telemetry/clock.ts) at `hours` after T0; answers the undo. */
export function clockAt(hours: number): () => void {
	const fixed = at(hours);
	return setClockForTests(() => fixed);
}

/* A case starts a day later, with no list, no tally and no counts from the one before it. */
export function resetAttackerList(): void {
	caseStart += 24 * HOUR_MS;
	resetAttackerListForTests();
	resetAttackerListSchedulerForTests();
	resetListedCountsForTests();
}

/* Public addresses, as the attack-report suites use: documentation ranges are never matched. */
let used = 0;
export function listedAddress(): string {
	used += 1;
	return `11.${(used >> 16) & 255}.${(used >> 8) & 255}.${used & 255}`;
}
