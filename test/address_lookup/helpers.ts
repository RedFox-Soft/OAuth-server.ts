import { spyOn } from 'bun:test';
import { Type, type Static } from '@sinclair/typebox';

import { fetchAnswering } from '../fetch_mock.ts';
import { shaped } from '../shape.ts';
import { readActivity } from '../person_activity/helpers.ts';
import { flushPersonActivityNow } from 'lib/person_activity/flush.ts';
import {
	foxtrustKeyStore,
	getTelemetryStateStore
} from 'lib/adapters/index.ts';
import {
	BATCH_DESTINATION,
	REGISTRATION_DESTINATION
} from 'lib/consts/address_lookup.ts';
import { TELEMETRY_DESTINATION } from 'lib/consts/telemetry_fields.ts';
import { registrationPass } from 'lib/address_lookup/register.ts';
import { setClockForTests } from 'lib/telemetry/clock.ts';
import { reportPass } from 'lib/telemetry/scheduler.ts';
import { sendReport } from 'lib/telemetry/send.ts';

/*
 * FoxTrust as this server meets it (specs/136 contracts/foxtrust-client.md): the usage report, the registration and
 * the batch lookup, each answered as a case sets, every request recorded with its headers and body. Any other URL
 * fails, as the real network is never reached.
 */

export const KEY = `ftk_abcdefghijkl_${'K'.repeat(43)}`;

export interface Sent {
	url: string;
	headers: Record<string, string>;
	body: string;
}

export interface Answer {
	status: number;
	body?: unknown;
	headers?: Record<string, string>;
}

/* What FoxTrust answers for an address it knows everything about. */
export function known(ip: string) {
	return {
		ip,
		network: { asn: 64500, org: 'Example Net', asCountry: 'DE' },
		subdivisions: [{ isoCode: 'BY', names: { en: 'Bavaria' } }],
		city: { names: { en: 'Munich' } }
	};
}

/* What FoxTrust answers for an address it knows nothing about, and for every address when its read timed out. */
export function empty(ip: string) {
	return {
		ip,
		network: { asn: null, org: null, asCountry: null },
		subdivisions: [],
		city: null
	};
}

export function batchOf(results: unknown[], remaining = 999): Answer {
	return {
		status: 200,
		body: {
			results,
			data: { version: 'v', delta: 'd', builtAt: 'b', stale: false }
		},
		headers: {
			'x-ratelimit-limit': '1000',
			'x-ratelimit-remaining': String(remaining)
		}
	};
}

function headersOf(init: RequestInit | undefined): Record<string, string> {
	const headers: Record<string, string> = {};
	new Headers(init?.headers).forEach((value, name) => {
		headers[name] = value;
	});
	return headers;
}

export interface FoxTrustFake {
	requests: Sent[];
	registration: Answer | 'unreachable';
	batch: (ips: string[]) => Answer | 'hang';
	registrations(): Sent[];
	batches(): Sent[];
	reports(): Sent[];
	ipsSent(): string[];
}

export function foxtrust(): FoxTrustFake {
	const fake: FoxTrustFake = {
		requests: [],
		registration: {
			status: 403,
			body: { error: 'not_yet', retryAfterDays: 7 }
		},
		batch: (ips) => batchOf(ips.map(known)),
		registrations: () =>
			fake.requests.filter((sent) => sent.url === REGISTRATION_DESTINATION),
		batches: () =>
			fake.requests.filter((sent) => sent.url === BATCH_DESTINATION),
		reports: () =>
			fake.requests.filter((sent) => sent.url === TELEMETRY_DESTINATION),
		ipsSent: () =>
			fake
				.batches()
				.flatMap((sent) => (JSON.parse(sent.body) as { ips: string[] }).ips)
	};
	spyOn(globalThis, 'fetch').mockImplementation(
		fetchAnswering(async (input, init) => {
			const url = input instanceof Request ? input.url : String(input);
			const body = typeof init?.body === 'string' ? init.body : '';
			fake.requests.push({ url, headers: headersOf(init), body });
			let answer: Answer | 'unreachable' | 'hang';
			if (url === TELEMETRY_DESTINATION) {
				answer = { status: 204 };
			} else if (url === REGISTRATION_DESTINATION) {
				answer = fake.registration;
			} else if (url === BATCH_DESTINATION) {
				answer = fake.batch((JSON.parse(body) as { ips: string[] }).ips);
			} else {
				throw new TypeError(`unexpected request to ${url}`);
			}
			if (answer === 'unreachable') {
				throw new TypeError('fetch failed');
			}
			if (answer === 'hang') {
				return new Promise<Response>((_resolve, reject) => {
					init?.signal?.addEventListener('abort', () =>
						reject(new Error('aborted by its own signal'))
					);
				});
			}
			return new Response(
				answer.body === undefined ? null : JSON.stringify(answer.body),
				{
					status: answer.status,
					headers: {
						'content-type': 'application/json',
						...(answer.headers ?? {})
					}
				}
			);
		})
	);
	return fake;
}

/* The server holds a key FoxTrust issued, as after a 201, without going through registration. */
export async function seedFoxTrustKey(key: string = KEY): Promise<void> {
	const store = getTelemetryStateStore();
	await store.instanceId();
	const stored = await foxtrustKeyStore.read();
	const bytes = Buffer.from(key, 'utf8');
	if (stored === null) await foxtrustKeyStore.create(bytes);
	else await foxtrustKeyStore.replace(stored, bytes);
	await store.setLookupKey({
		receivedAt: new Date().toISOString(),
		dailyQuota: 1000,
		burst: 5
	});
}

/* Runs `work` with the clock usage reporting and lookups run on set to `iso`. */
export async function at<T>(iso: string, work: () => Promise<T>): Promise<T> {
	const moment = new Date(iso);
	const undo = setClockForTests(() => moment);
	try {
		return await work();
	} finally {
		undo();
	}
}

/* One delivered usage report on `iso`, past the instance's report slot. */
export function deliverReport(iso: string): Promise<unknown> {
	return at(iso, () =>
		reportPass(new Date(iso), sendReport, { ignoreSlot: true })
	);
}

/* One registration pass on `iso`, past the instance's report slot. */
export function registerAt(iso: string): Promise<unknown> {
	return at(iso, () => registrationPass(new Date(iso), { ignoreSlot: true }));
}

/* `iso` plus `days` UTC days, same time of day. */
export function daysAfter(iso: string, days: number): string {
	return new Date(
		new Date(iso).getTime() + days * 24 * 60 * 60 * 1000
	).toISOString();
}

/* What an administrator reads of one row: its address and the owner and location beside it. */
export const LookupRow = Type.Object({
	kind: Type.String(),
	outcome: Type.String(),
	address: Type.Union([Type.String(), Type.Null()]),
	lookup: Type.Union([
		Type.Null(),
		Type.Object({
			asn: Type.Union([Type.Number(), Type.Null()]),
			asName: Type.Union([Type.String(), Type.Null()]),
			regionCode: Type.Union([Type.String(), Type.Null()]),
			region: Type.Union([Type.String(), Type.Null()]),
			city: Type.Union([Type.String(), Type.Null()])
		})
	])
});

export const LookupPage = Type.Object({
	rows: Type.Array(LookupRow),
	lookupState: Type.String()
});
export type LookupPage = Static<typeof LookupPage>;

/* The person's activity as the administrator reads it, once the server has written (and looked up) what it held. */
export async function lookupsOf(
	cookie: string,
	bucketId: string,
	accountId: string,
	body: Record<string, unknown> = {}
): Promise<LookupPage> {
	await flushPersonActivityNow();
	const reply = await readActivity(cookie, bucketId, accountId, body);
	if (reply.status !== 200) {
		throw new Error(`reading the activity answered ${String(reply.status)}`);
	}
	return shaped(LookupPage, reply.body);
}
