import type { ActivityLookup } from '../adapters/types.js';
import {
	BATCH_DESTINATION,
	LOOKUP_TEXT_MAX,
	REGION_CODE_MAX
} from '../consts/address_lookup.js';
import { packageVersion } from '../helpers/package_version.js';

/* One address's answer: what it found, nothing, invalid in FoxTrust's eyes, or past the day's allowance. */
export type BatchEntry = ActivityLookup | null | 'invalid' | 'quota';

export type BatchAnswer =
	| {
			kind: 'answered';
			entries: Map<string, BatchEntry>;
			limit?: number;
			remaining?: number;
			/*
			 * Every valid entry came back empty: FoxTrust's answer when its read timed out, which counts nothing and must
			 * not be remembered as "nothing known" (research R7).
			 */
			allEmpty: boolean;
	  }
	| { kind: 'key-refused' }
	| { kind: 'used-up' }
	| { kind: 'later' };

function record(value: unknown): Record<string, unknown> | undefined {
	/*
	 * Asserted because TypeScript narrows a non-null, non-array `object` no further: its members are exactly what the
	 * callers read through `unknown` and check one by one.
	 */
	return typeof value === 'object' && value !== null && !Array.isArray(value)
		? (value as Record<string, unknown>)
		: undefined;
}

function text(value: unknown, max: number): string | undefined {
	if (typeof value !== 'string') return undefined;
	const trimmed = value.trim().slice(0, max);
	return trimmed.length > 0 ? trimmed : undefined;
}

function englishName(value: unknown): string | undefined {
	return text(record(record(value)?.names)?.en, LOOKUP_TEXT_MAX);
}

/*
 * The four facts of one result, and nothing else (SI-3): the AS number and name, the first region's code and English
 * name, the city's English name. FoxTrust never sends risk, level, reasons, categories or country here, and if it ever
 * did they would not be read.
 */
export function factsOf(
	result: Record<string, unknown>
): ActivityLookup | null {
	const network = record(result.network);
	const asn = network?.asn;
	const region = Array.isArray(result.subdivisions)
		? record(result.subdivisions[0])
		: undefined;
	const lookup: ActivityLookup = {
		...(typeof asn === 'number' && Number.isInteger(asn) && asn >= 0
			? { asn }
			: {}),
		...(text(network?.org, LOOKUP_TEXT_MAX) === undefined
			? {}
			: { asName: text(network?.org, LOOKUP_TEXT_MAX) }),
		...(text(region?.isoCode, REGION_CODE_MAX) === undefined
			? {}
			: { regionCode: text(region?.isoCode, REGION_CODE_MAX) }),
		...(englishName(region) === undefined
			? {}
			: { region: englishName(region) }),
		...(englishName(result.city) === undefined
			? {}
			: { city: englishName(result.city) })
	};
	return Object.keys(lookup).length > 0 ? lookup : null;
}

function figure(header: string | null): number | undefined {
	if (header === null) return undefined;
	const value = Number(header);
	return Number.isInteger(value) && value >= 0 ? value : undefined;
}

function errorCode(body: unknown): unknown {
	const error = record(body)?.error;
	return typeof error === 'string' ? error : record(error)?.code;
}

/*
 * One batch request (contracts/foxtrust-client.md §3): the addresses exactly as the rows hold them, answered by the
 * same strings. The key leaves this server only in its `authorization` header (SI-7). Never throws, never logs.
 */
export async function lookUpBatch(
	key: string,
	ips: readonly string[],
	timeoutMs: number
): Promise<BatchAnswer> {
	const version = packageVersion();
	let response: Response;
	try {
		response = await fetch(BATCH_DESTINATION, {
			method: 'POST',
			headers: {
				authorization: `Bearer ${key}`,
				'content-type': 'application/json',
				'user-agent': version === undefined ? 'FoxAuth' : `FoxAuth/${version}`
			},
			body: JSON.stringify({ ips }),
			redirect: 'manual',
			signal: AbortSignal.timeout(timeoutMs)
		});
	} catch {
		return { kind: 'later' };
	}
	let body: unknown;
	try {
		body = await response.json();
	} catch {
		body = null;
	}
	if (response.status === 401) return { kind: 'key-refused' };
	if (response.status === 429 && errorCode(body) === 'quota_exceeded') {
		return { kind: 'used-up' };
	}
	const results = record(body)?.results;
	if (response.status !== 200 || !Array.isArray(results)) {
		return { kind: 'later' };
	}

	const asked = new Set(ips);
	const entries = new Map<string, BatchEntry>();
	const items: unknown[] = results;
	for (const item of items) {
		const result = record(item);
		const ip = result?.ip;
		if (!result || typeof ip !== 'string' || !asked.has(ip)) continue;
		if (result.error === 'invalid_ip') entries.set(ip, 'invalid');
		else if (result.error === 'quota') entries.set(ip, 'quota');
		else if (result.error === undefined) entries.set(ip, factsOf(result));
	}
	const valid = [...entries.values()].filter(
		(entry) => entry !== 'invalid' && entry !== 'quota'
	);
	return {
		kind: 'answered',
		entries,
		limit: figure(response.headers.get('x-ratelimit-limit')),
		remaining: figure(response.headers.get('x-ratelimit-remaining')),
		allEmpty: valid.length > 0 && valid.every((entry) => entry === null)
	};
}
