import { getTelemetryStateStore } from '../adapters/index.js';
import {
	FOXTRUST_KEYS,
	FOXTRUST_MANIFEST,
	FOXTRUST_MANIFEST_MAX_BYTES,
	FOXTRUST_PUBLICATION_BASE
} from '../consts/foxtrust_publication.js';
import {
	NETWORK_FACTS_DATABASE_TYPE,
	NETWORK_FACTS_DELTA_MAX_BYTES,
	NETWORK_FACTS_FULL_MAX_BYTES
} from '../consts/network_facts.js';
import {
	fileUrl,
	get,
	getBytes,
	PublicationFailure,
	readCapped,
	sha256Hex
} from '../foxtrust/publication.js';
import { verifySignature } from '../foxtrust/verify.js';
import { now } from '../telemetry/clock.js';
import { makePair } from './facts.js';
import { openMmdb, type MmdbReader } from './mmdb.js';
import {
	acceptPair,
	heldPair,
	networkFactsOn,
	noteCheck,
	noteProblem,
	noteUnreadable,
	type ProblemKind
} from './state.js';

/*
 * One look at FoxTrust's publication for newer network facts (specs/129 research R3, contracts/publication-consumer.md
 * "Acceptance"). Every step must hold before the next runs; a failure records why and leaves the data in use as it is.
 *
 * The publication and its keys are arguments defaulted to the constants, the seam the attacker list uses, so a test
 * can stand in for FoxTrust with a key of its own. Nothing in the server passes them.
 */

export type PassOutcome = 'off' | 'accepted' | 'unchanged' | ProblemKind;

export interface PassOptions {
	readonly base?: string;
	readonly keys?: Readonly<Record<string, string>>;
}

interface PublishedFile {
	version: string;
	path: string;
	sha256: string;
	size: number;
	builtAt: string;
	base: string | null;
}

class PassFailure extends Error {
	constructor(readonly kind: ProblemKind) {
		super(kind);
	}
}

const FULL_VERSION = /^f\d{8}$/;
const DELTA_VERSION = /^d\d{8}T\d{2}$/;
const FILE_PATH = /^v1\/(full|delta)\/[fd][0-9T]+\.mmdb$/;
const SHA256 = /^[0-9a-f]{64}$/;

/* The manifest's ETag, kept only after a pass that accepted everything it named. */
let manifestEtag: string | null = null;

function entryOf(raw: unknown, kind: 'full' | 'delta'): PublishedFile {
	if (typeof raw !== 'object' || raw === null) throw new PassFailure('header');
	const e = raw as Record<string, unknown>;
	const sha = typeof e.sha256 === 'string' ? e.sha256.toLowerCase() : '';
	if (
		typeof e.version !== 'string' ||
		!(kind === 'full' ? FULL_VERSION : DELTA_VERSION).test(e.version) ||
		typeof e.path !== 'string' ||
		!FILE_PATH.test(e.path) ||
		!SHA256.test(sha) ||
		!Number.isInteger(e.size) ||
		(e.size as number) <= 0 ||
		typeof e.builtAt !== 'string' ||
		Number.isNaN(Date.parse(e.builtAt)) ||
		(kind === 'delta' &&
			(typeof e.base !== 'string' || !FULL_VERSION.test(e.base)))
	) {
		throw new PassFailure('header');
	}
	return {
		version: e.version,
		path: e.path,
		sha256: sha,
		size: e.size as number,
		builtAt: new Date(e.builtAt).toISOString(),
		base: kind === 'delta' ? (e.base as string) : null
	};
}

async function download(
	base: string,
	keys: Readonly<Record<string, string>>,
	entry: PublishedFile,
	cap: number
): Promise<MmdbReader> {
	if (entry.size > cap) throw new PassFailure('size');
	const url = fileUrl(base, entry.path);
	const response = await get(url);
	if (response.status !== 200) throw new PassFailure('http');
	const bytes = await readCapped(response, cap, entry.size);
	const signature = await getBytes(`${url}.sig`, FOXTRUST_MANIFEST_MAX_BYTES);
	if (!(await verifySignature(bytes, signature, keys))) {
		throw new PassFailure('signature');
	}
	if ((await sha256Hex(bytes)) !== entry.sha256) {
		throw new PassFailure('digest');
	}
	const reader = openMmdb(bytes);
	if (
		!reader ||
		reader.metadata.databaseType !== NETWORK_FACTS_DATABASE_TYPE ||
		reader.metadata.binaryFormatMajorVersion !== 2 ||
		reader.metadata.ipVersion !== 6
	) {
		throw new PassFailure('format');
	}
	return reader;
}

export async function networkFactsPass(
	options: PassOptions = {}
): Promise<PassOutcome> {
	if (!networkFactsOn()) return 'off';
	const base = options.base ?? FOXTRUST_PUBLICATION_BASE;
	const keys = options.keys ?? FOXTRUST_KEYS;
	const startedMs = now().getTime();
	noteCheck(startedMs);
	try {
		const held = heldPair();
		const manifestResponse = await get(
			`${base}/${FOXTRUST_MANIFEST}`,
			held && manifestEtag ? { 'if-none-match': manifestEtag } : {}
		);
		if (manifestResponse.status === 304) return 'unchanged';
		const etag = manifestResponse.headers.get('etag');
		const manifestBytes = await readCapped(
			manifestResponse,
			FOXTRUST_MANIFEST_MAX_BYTES
		);
		const manifestSig = await getBytes(
			`${base}/${FOXTRUST_MANIFEST}.sig`,
			FOXTRUST_MANIFEST_MAX_BYTES
		);
		if (!(await verifySignature(manifestBytes, manifestSig, keys))) {
			throw new PassFailure('signature');
		}
		let manifest: Record<string, unknown>;
		try {
			const parsed: unknown = JSON.parse(
				new TextDecoder().decode(manifestBytes)
			);
			if (typeof parsed !== 'object' || parsed === null) throw new Error();
			manifest = parsed as Record<string, unknown>;
		} catch {
			throw new PassFailure('header');
		}
		const fullEntry = entryOf(manifest.full, 'full');
		const deltaEntry =
			manifest.delta === null || manifest.delta === undefined
				? null
				: entryOf(manifest.delta, 'delta');

		const full =
			held && held.fullVersion === fullEntry.version
				? held.full
				: await download(base, keys, fullEntry, NETWORK_FACTS_FULL_MAX_BYTES);

		let delta: MmdbReader | null = null;
		let deltaVersion: string | null = null;
		let deltaBuiltAt: string | null = null;
		let deltaProblem: ProblemKind | null = null;
		if (deltaEntry && deltaEntry.base !== fullEntry.version) {
			deltaProblem = 'base';
		} else if (deltaEntry) {
			if (held?.deltaVersion === deltaEntry.version && held.delta) {
				delta = held.delta;
				deltaVersion = deltaEntry.version;
				deltaBuiltAt = deltaEntry.builtAt;
			} else {
				try {
					delta = await download(
						base,
						keys,
						deltaEntry,
						NETWORK_FACTS_DELTA_MAX_BYTES
					);
					deltaVersion = deltaEntry.version;
					deltaBuiltAt = deltaEntry.builtAt;
				} catch (error) {
					deltaProblem = kindOf(error);
				}
			}
		}
		/* An update that failed keeps the previous one of the same full file (FoxTrust's own consumer does so). */
		if (
			!delta &&
			deltaProblem &&
			held?.delta &&
			held.fullVersion === fullEntry.version
		) {
			delta = held.delta;
			deltaVersion = held.deltaVersion;
			deltaBuiltAt = held.builtAt;
		}

		const builtAt =
			deltaBuiltAt && deltaBuiltAt > fullEntry.builtAt
				? deltaBuiltAt
				: fullEntry.builtAt;
		const store = getTelemetryStateStore();
		await store.instanceId();
		const stored = (await store.read())?.networkFactsBuiltAt;
		if (
			(held && builtAt < held.builtAt) ||
			(stored !== undefined && builtAt < stored)
		) {
			throw new PassFailure('older');
		}
		if (
			held &&
			held.fullVersion === fullEntry.version &&
			held.deltaVersion === deltaVersion
		) {
			if (deltaProblem) throw new PassFailure(deltaProblem);
			manifestEtag = etag;
			return 'unchanged';
		}

		// Recorded before it is used, so data in use is always data a restart would refuse to see replaced by older.
		await store.raiseNetworkFactsBuiltAt(builtAt);
		acceptPair(
			makePair({
				full,
				delta,
				fullVersion: fullEntry.version,
				deltaVersion,
				builtAt,
				onUnreadable: noteUnreadable
			}),
			now().getTime()
		);
		if (deltaProblem) {
			noteProblem(deltaProblem, startedMs);
		} else {
			manifestEtag = etag;
		}
		return 'accepted';
	} catch (error) {
		const kind = kindOf(error);
		noteProblem(kind, startedMs);
		return kind;
	}
}

function kindOf(error: unknown): ProblemKind {
	if (error instanceof PassFailure || error instanceof PublicationFailure) {
		return error.kind;
	}
	return 'network';
}

/* Test-only: a spec file starts as a process that has seen no manifest. */
export function resetNetworkFactsFetchForTests(): void {
	manifestEtag = null;
}
