import { getTelemetryStateStore } from '../adapters/index.js';
import { ApplicationConfig } from '../configs/application.js';
import {
	ATTACKER_LIST_BASE,
	ATTACKER_LIST_FORMAT,
	ATTACKER_LIST_KEYS,
	ATTACKER_LIST_MANIFEST,
	ATTACKER_LIST_MAX_BYTES,
	ATTACKER_LIST_TIMEOUT_MS
} from '../consts/attacker_list.js';
import { packageVersion } from '../helpers/package_version.js';
import { now } from '../telemetry/clock.js';
import { buildMatcher } from './matcher.js';
import { parseListFile } from './parse.js';
import {
	acceptList,
	effective,
	heldList,
	noteCheck,
	noteProblem,
	noteUnchanged,
	noteUnknownFormat,
	type ProblemKind
} from './state.js';
import { verifySignature } from './verify.js';

/*
 * One check for a newer attacker list (specs/125; FoxTrust's contract, "Verifying"; contracts/publication-consumer.md
 * "Acceptance"). Every step must hold before the next runs; a failure records why and keeps the list already held
 * until its own validity ends.
 *
 * The publication and its keys are arguments defaulted to the constants — the seam `sendReport` uses — so a test can
 * stand in for FoxTrust with a key of its own. Nothing in the server passes them: there is no setting and no
 * environment variable for either.
 */

export type PassOutcome =
	'off' | 'accepted' | 'unchanged' | 'no-list' | 'unknown-format' | ProblemKind;

export interface PassOptions {
	readonly base?: string;
	readonly keys?: Readonly<Record<string, string>>;
}

interface ManifestEntry {
	version: string;
	path: string;
	sha256: string;
	size: number;
}

class PassFailure extends Error {
	constructor(readonly kind: ProblemKind) {
		super(kind);
	}
}

/* No instance identifier, key or cookie leaves with these requests; the version only while usage reports are on. */
function userAgent(): string {
	const version = packageVersion();
	return ApplicationConfig['telemetry.enabled'] && version !== undefined
		? `FoxAuth/${version}`
		: 'FoxAuth';
}

/*
 * The body, read no further than the cap. The publication serves gzip through Cloudflare and the runtime
 * decompresses it, so Content-Length is absent or counts the compressed bytes: the cap is held on what is read.
 */
async function capped(response: Response): Promise<Uint8Array<ArrayBuffer>> {
	const reader = response.body?.getReader();
	if (!reader) return new Uint8Array();
	const chunks: Uint8Array[] = [];
	let total = 0;
	for (;;) {
		const { done, value } = await reader.read();
		if (done) break;
		total += value.byteLength;
		if (total > ATTACKER_LIST_MAX_BYTES) {
			await reader.cancel();
			throw new PassFailure('size');
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

async function get(
	url: string,
	headers: Record<string, string> = {}
): Promise<Response> {
	let response: Response;
	try {
		response = await fetch(url, {
			headers: { 'user-agent': userAgent(), ...headers },
			redirect: 'manual',
			signal: AbortSignal.timeout(ATTACKER_LIST_TIMEOUT_MS)
		});
	} catch {
		throw new PassFailure('network');
	}
	if (response.status !== 200 && response.status !== 304) {
		throw new PassFailure('http');
	}
	return response;
}

async function getBytes(url: string): Promise<Uint8Array<ArrayBuffer>> {
	const response = await get(url);
	if (response.status !== 200) throw new PassFailure('http');
	return capped(response);
}

/* A path the manifest names, kept inside the publication: no scheme, no host, no climbing out. */
function fileUrl(base: string, path: string): string {
	if (
		!/^v1\/[A-Za-z0-9/_.-]+$/.test(path) ||
		path.includes('..') ||
		path.includes('//')
	) {
		throw new PassFailure('header');
	}
	return `${base}/${path}`;
}

function entryOf(manifest: unknown): ManifestEntry | 'absent' | 'other-format' {
	if (typeof manifest !== 'object' || manifest === null) {
		throw new PassFailure('header');
	}
	const lists = (manifest as { attackers?: unknown }).attackers;
	if (typeof lists !== 'object' || lists === null) return 'absent';
	const entry = (lists as Record<string, unknown>)[
		String(ATTACKER_LIST_FORMAT)
	];
	if (entry === undefined) {
		return Object.keys(lists).length > 0 ? 'other-format' : 'absent';
	}
	const e = entry as Record<string, unknown>;
	if (
		typeof e.version !== 'string' ||
		typeof e.path !== 'string' ||
		typeof e.sha256 !== 'string' ||
		!Number.isInteger(e.size)
	) {
		throw new PassFailure('header');
	}
	return {
		version: e.version,
		path: e.path,
		sha256: e.sha256.toLowerCase(),
		size: e.size as number
	};
}

async function sha256Hex(bytes: Uint8Array<ArrayBuffer>): Promise<string> {
	const digest = await crypto.subtle.digest('SHA-256', bytes);
	return Buffer.from(digest).toString('hex');
}

export async function attackerListPass(
	options: PassOptions = {}
): Promise<PassOutcome> {
	if (!effective()) return 'off';
	const base = options.base ?? ATTACKER_LIST_BASE;
	const keys = options.keys ?? ATTACKER_LIST_KEYS;
	const startedMs = now().getTime();
	noteCheck(startedMs);
	try {
		const manifestBytes = await getBytes(`${base}/${ATTACKER_LIST_MANIFEST}`);
		const manifestSig = await getBytes(`${base}/${ATTACKER_LIST_MANIFEST}.sig`);
		if (!(await verifySignature(manifestBytes, manifestSig, keys))) {
			throw new PassFailure('signature');
		}
		let manifest: unknown;
		try {
			manifest = JSON.parse(new TextDecoder().decode(manifestBytes));
		} catch {
			throw new PassFailure('header');
		}
		const entry = entryOf(manifest);
		if (entry === 'absent') return 'no-list';
		if (entry === 'other-format') {
			noteUnknownFormat(startedMs);
			return 'unknown-format';
		}

		const held = heldList();
		if (held && held.version === entry.version) {
			noteUnchanged();
			return 'unchanged';
		}

		const url = fileUrl(base, entry.path);
		const fileResponse = await get(
			url,
			held?.etag ? { 'if-none-match': held.etag } : {}
		);
		if (fileResponse.status === 304) {
			noteUnchanged();
			return 'unchanged';
		}
		const etag = fileResponse.headers.get('etag');
		const bytes = await capped(fileResponse);
		const signature = await getBytes(`${url}.sig`);
		if (!(await verifySignature(bytes, signature, keys))) {
			throw new PassFailure('signature');
		}
		if (bytes.byteLength !== entry.size) throw new PassFailure('size');
		if ((await sha256Hex(bytes)) !== entry.sha256) {
			throw new PassFailure('digest');
		}

		const parsed = parseListFile(new TextDecoder().decode(bytes));
		if (!parsed || parsed.header.version !== entry.version) {
			throw new PassFailure('header');
		}
		const { header } = parsed;
		const validUntilMs = Date.parse(header.validUntil);
		if (validUntilMs <= now().getTime()) throw new PassFailure('expired');

		const store = getTelemetryStateStore();
		await store.instanceId();
		const stored = (await store.read())?.attackerListBuiltAt;
		const builtAt = new Date(header.builtAt).toISOString();
		if (
			(held && builtAt <= new Date(held.builtAt).toISOString()) ||
			(stored !== undefined && builtAt <= stored)
		) {
			throw new PassFailure('older');
		}

		const matcher = buildMatcher(parsed.entries);
		// Recorded before it is used, so a list in use is always one a restart would refuse to see replaced by older.
		await store.raiseAttackerListBuiltAt(builtAt);
		acceptList(
			{
				matcher,
				version: header.version,
				builtAt,
				validUntilMs,
				entries: matcher.size,
				dispute: header.dispute,
				etag
			},
			now().getTime()
		);
		return 'accepted';
	} catch (error) {
		const kind = error instanceof PassFailure ? error.kind : 'network';
		noteProblem(kind, startedMs);
		return kind;
	}
}
