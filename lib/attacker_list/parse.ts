import { parseAddress, parseRange } from '../behind_proxy/net.js';
import {
	ATTACKER_LIST_CODES,
	ATTACKER_LIST_FORMAT,
	ATTACKER_LIST_KIND
} from '../consts/attacker_list.js';

/*
 * FoxTrust's attacker list, format 1 (specs/125; contract at https://foxtrust.dev/docs/snapshots, "Attacker list"):
 * line one is a JSON header, every other line `network \t code \t last_seen \t band \t corroborated`.
 *
 * Read defensively. A header that is not exactly what format 1 promises rejects the file; a line that is not makes
 * only that line skipped, so one odd line never costs the whole list. The band is not read: nothing in this release
 * decides on it.
 */

export interface ListHeader {
	readonly kind: string;
	readonly format: number;
	readonly version: string;
	readonly builtAt: string;
	readonly validUntil: string;
	readonly entries: number;
	/* Where a listed party disputes a listing; shown last on the refusal page. Absent when not an https URL. */
	readonly dispute: string | null;
}

export interface ParsedEntry {
	readonly version: 4 | 6;
	/* The IPv4 address, or the first 64 bits of the IPv6 /64. */
	readonly key: bigint;
	/* Unix seconds of the hour of the latest sighting. */
	readonly lastSeen: number;
	readonly corroborated: boolean;
}

const COLUMNS = ['network', 'code', 'last_seen', 'band', 'corroborated'];

const isIso = (value: unknown): value is string =>
	typeof value === 'string' && !Number.isNaN(Date.parse(value));

function httpsOrNull(value: unknown): string | null {
	if (typeof value !== 'string') return null;
	try {
		return new URL(value).protocol === 'https:' ? value : null;
	} catch {
		return null;
	}
}

export function parseHeader(line: string): ListHeader | null {
	let raw: unknown;
	try {
		raw = JSON.parse(line);
	} catch {
		return null;
	}
	if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) {
		return null;
	}
	const h = raw as Record<string, unknown>;
	if (h.kind !== ATTACKER_LIST_KIND || h.format !== ATTACKER_LIST_FORMAT) {
		return null;
	}
	if (
		typeof h.version !== 'string' ||
		!isIso(h.builtAt) ||
		!isIso(h.validUntil) ||
		!Number.isInteger(h.entries) ||
		!Array.isArray(h.columns) ||
		h.columns.length !== COLUMNS.length ||
		!COLUMNS.every((name, i) => (h.columns as unknown[])[i] === name)
	) {
		return null;
	}
	return {
		kind: h.kind,
		format: h.format,
		version: h.version,
		builtAt: h.builtAt,
		validUntil: h.validUntil,
		entries: h.entries as number,
		dispute: httpsOrNull(h.dispute)
	};
}

/* One entry line, or null for a line this release does not use (another code, another width, malformed). */
export function parseEntry(line: string): ParsedEntry | null {
	const fields = line.split('\t');
	if (fields.length !== COLUMNS.length) return null;
	const [network, code, lastSeenText, , corroboratedText] = fields as [
		string,
		string,
		string,
		string,
		string
	];
	if (!ATTACKER_LIST_CODES.includes(code)) return null;
	if (!/^[0-9]{1,12}$/.test(lastSeenText)) return null;
	if (corroboratedText !== '0' && corroboratedText !== '1') return null;
	const lastSeen = Number(lastSeenText);
	const corroborated = corroboratedText === '1';

	if (network.includes(':')) {
		if (!network.endsWith('/64')) return null;
		const range = parseRange(network);
		if ('error' in range || range.version !== 6 || range.bits !== 64) {
			return null;
		}
		return { version: 6, key: range.base >> 64n, lastSeen, corroborated };
	}
	if (network.includes('/')) return null;
	const address = parseAddress(network);
	if (address?.version !== 4) return null;
	return { version: 4, key: address.value, lastSeen, corroborated };
}

export function parseListFile(
	text: string
): { header: ListHeader; entries: ParsedEntry[] } | null {
	const lines = text.split('\n');
	const header = parseHeader(lines[0] ?? '');
	if (!header) return null;
	const entries: ParsedEntry[] = [];
	for (let i = 1; i < lines.length; i += 1) {
		const line = lines[i];
		if (line === '') continue;
		const entry = parseEntry(line);
		if (entry) entries.push(entry);
	}
	return { header, entries };
}
