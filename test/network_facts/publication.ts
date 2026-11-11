import { spyOn } from 'bun:test';

import { fetchAnswering } from '../fetch_mock.ts';
import { signer, type Signer } from '../attacker_list/helper.ts';
import { setClockForTests } from 'lib/telemetry/clock.ts';
import {
	networkFactsPass,
	resetNetworkFactsFetchForTests,
	type PassOutcome
} from 'lib/network_facts/fetch.ts';
import { resetNetworkFactsForTests } from 'lib/network_facts/state.ts';
import { resetNetworkFactsSchedulerForTests } from 'lib/network_facts/scheduler.ts';
import { writeMmdb, type Entry, type WriterOptions } from './mmdb_writer.ts';

/*
 * A stand-in for FoxTrust's publication of the snapshot (specs/129 contracts/publication-consumer.md), signing with a
 * key generated here and handed to the pass through its seam. Nothing reaches the network: every request is answered
 * from `files` and logged, so a case can say exactly what the server sent.
 */

export { signer, type Signer };

export const BASE = 'https://publication.test';

interface Served {
	bytes: Uint8Array<ArrayBuffer>;
	etag?: string;
}

export interface Logged {
	url: string;
	headers: Headers;
	body: string | null;
}

export interface FileSpec {
	readonly version: string;
	readonly builtAt: string;
	readonly entries?: readonly Entry[];
	readonly options?: WriterOptions;
	/* The bytes served, instead of a file written from `entries`. */
	readonly bytes?: Uint8Array<ArrayBuffer>;
	readonly signedBy?: Signer;
	readonly manifestSize?: number;
	readonly manifestSha256?: string;
	readonly base?: string;
}

export interface Publication {
	readonly files: Map<string, Served>;
	readonly requests: Logged[];
	publish(options: {
		by: Signer;
		full: FileSpec;
		delta?: FileSpec | null;
		extra?: Record<string, unknown>;
	}): Promise<void>;
}

async function sha256Hex(bytes: Uint8Array<ArrayBuffer>): Promise<string> {
	return Buffer.from(await crypto.subtle.digest('SHA-256', bytes)).toString(
		'hex'
	);
}

const encoder = new TextEncoder();

export function publication(): Publication {
	const files = new Map<string, Served>();
	const requests: Logged[] = [];
	spyOn(globalThis, 'fetch').mockImplementation(
		fetchAnswering(async (input, init) => {
			const url = input instanceof Request ? input.url : String(input);
			const headers = new Headers(init?.headers);
			const body =
				typeof init?.body === 'string'
					? init.body
					: init?.body
						? '[body]'
						: null;
			requests.push({ url, headers, body });
			if (!url.startsWith(`${BASE}/`)) {
				throw new TypeError(`unexpected request to ${url}`);
			}
			const served = files.get(url.slice(BASE.length + 1));
			if (!served) return new Response('not found', { status: 404 });
			if (served.etag && headers.get('if-none-match') === served.etag) {
				return new Response(null, { status: 304 });
			}
			return new Response(served.bytes, {
				status: 200,
				headers: served.etag ? { etag: served.etag } : {}
			});
		})
	);

	const put = async (
		kind: 'full' | 'delta',
		spec: FileSpec,
		by: Signer
	): Promise<Record<string, unknown>> => {
		const bytes =
			spec.bytes ?? writeMmdb(spec.entries ?? [], spec.options ?? {});
		const path = `v1/${kind}/${spec.version}.mmdb`;
		files.set(path, { bytes, etag: `"${spec.version}"` });
		files.set(`${path}.sig`, {
			bytes: await (spec.signedBy ?? by).sign(bytes)
		});
		return {
			version: spec.version,
			path,
			sha256: spec.manifestSha256 ?? (await sha256Hex(bytes)),
			size: spec.manifestSize ?? bytes.byteLength,
			builtAt: spec.builtAt,
			dataVersion: 'x',
			algorithm: 'x',
			configSha256: 'x',
			keyId: Object.keys(by.keys)[0],
			...(kind === 'delta' ? { base: spec.base } : {})
		};
	};

	return {
		files,
		requests,
		async publish({ by, full, delta, extra }) {
			const manifest = {
				format: 1,
				generatedAt: full.builtAt,
				full: await put('full', full, by),
				delta: delta
					? await put(
							'delta',
							{ ...delta, base: delta.base ?? full.version },
							by
						)
					: null,
				/* Keys a FoxAuth release does not read: the parser must pass over them. */
				attackers: {},
				notices: [],
				...extra
			};
			const manifestBytes = encoder.encode(JSON.stringify(manifest));
			files.set('v1/manifest.json', {
				bytes: manifestBytes,
				etag: `"m-${full.version}-${delta?.version ?? 'none'}"`
			});
			files.set('v1/manifest.json.sig', {
				bytes: await by.sign(manifestBytes)
			});
		}
	};
}

export function pass(by: Signer): Promise<PassOutcome> {
	return networkFactsPass({ base: BASE, keys: by.keys });
}

const HOUR_MS = 60 * 60 * 1000;

/*
 * Times relative to the current case's start. Each case starts two days after the one before it: the instance
 * remembers the newest build time it accepted, as it must, so a case reusing an earlier case's times would meet that
 * memory instead of the behaviour it is about.
 */
let caseStart = Date.UTC(2026, 10, 11, 4, 50);
export const at = (hours: number) => new Date(caseStart + hours * HOUR_MS);
export const iso = (hours: number) => at(hours).toISOString();
export const fullVersion = (day = 0) => {
	const d = at(day * 24);
	return `f${d.toISOString().slice(0, 10).replaceAll('-', '')}`;
};
export const deltaVersion = (hours: number) => {
	const d = at(hours);
	return `d${d.toISOString().slice(0, 10).replaceAll('-', '')}T${d.toISOString().slice(11, 13)}`;
};

export function clockAt(hours: number): () => void {
	const fixed = at(hours);
	return setClockForTests(() => fixed);
}

export function resetNetworkFacts(): void {
	caseStart += 48 * HOUR_MS;
	resetNetworkFactsForTests();
	resetNetworkFactsFetchForTests();
	resetNetworkFactsSchedulerForTests();
}

/* Records as FoxTrust writes them after its spec 040. */
export const TOR = {
	risk: 60,
	level: 'medium',
	categories: ['tor'],
	reasons: [{ code: 'tor_exit', last_seen: 1_794_000_000, contribution: 60 }],
	country: { iso_code: 'DE' }
};
export const HOSTING_NL = {
	risk: 10,
	level: 'low',
	categories: ['hosting'],
	reasons: [{ code: 'hosting', last_seen: 1_794_000_000, contribution: 10 }],
	country: { iso_code: 'NL' }
};
export const CLOUD_US = {
	risk: 10,
	level: 'low',
	categories: ['cloud'],
	reasons: [],
	country: { iso_code: 'US' }
};
export const VPN_FR = {
	risk: 20,
	level: 'low',
	categories: ['vpn'],
	reasons: [],
	country: { iso_code: 'FR' }
};
export const HOME_DE = {
	risk: 0,
	level: 'low',
	categories: [],
	reasons: [],
	country: { iso_code: 'DE' }
};
export const HOME_AT = {
	risk: 0,
	level: 'low',
	categories: [],
	reasons: [],
	country: { iso_code: 'AT' }
};
export const RELAY = {
	risk: 0,
	level: 'low',
	categories: ['private_relay'],
	reasons: [],
	country: { iso_code: 'GB' }
};

/* The addresses the standard snapshot of these specs knows, by what they are. */
export const ADDRESSES = {
	tor: '45.10.20.30',
	hosting: '45.11.0.5',
	cloud: '2a05:d000::1',
	vpn: '45.12.0.9',
	homeDe: '91.20.30.40',
	homeAt: '91.21.0.1',
	relay: '172.224.0.1',
	nothing: '100.64.200.1',
	unlisted: '11.0.0.1'
} as const;

export const STANDARD: readonly Entry[] = [
	{ cidr: '45.10.20.30/32', value: TOR },
	{ cidr: '45.11.0.0/16', value: HOSTING_NL },
	{ cidr: '2a05:d000::/32', value: CLOUD_US },
	{ cidr: '45.12.0.0/24', value: VPN_FR },
	{ cidr: '91.20.0.0/16', value: HOME_DE },
	{ cidr: '91.21.0.0/16', value: HOME_AT },
	{ cidr: '172.224.0.0/16', value: RELAY }
];

/* Publishes the standard snapshot built at `hours` and loads it; answers what the pass said. */
export async function loadStandard(
	published: Publication,
	by: Signer,
	hours = 0
): Promise<PassOutcome> {
	await published.publish({
		by,
		full: { version: fullVersion(), builtAt: iso(hours), entries: STANDARD }
	});
	return pass(by);
}
