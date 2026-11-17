import crypto from 'node:crypto';

import { ApplicationConfig } from '../configs/application.js';
import { getTelemetryStateStore } from '../adapters/index.js';
import type {
	Registration,
	RegistrationOutcome,
	TelemetryState
} from '../adapters/types.js';
import {
	FIRST_REGISTRATION_AFTER_DAYS,
	REGISTRATION_DESTINATION,
	REGISTRATION_FIELDS,
	REGISTRATION_FORMAT,
	REGISTRATION_TIMEOUT_MS,
	STOPPED_RETRY_DAYS
} from '../consts/address_lookup.js';
import { packageVersion } from '../helpers/package_version.js';
import { now } from '../telemetry/clock.js';
import { minuteOfDay, slotOf } from '../telemetry/slot.js';
import { reportingAllowed } from '../telemetry/status.js';
import { dayOf, startOfDayAfter } from './days.js';
import { isFoxTrustKey, keepKey, keyInUse } from './foxtrust_key.js';
import { instanceKey, signRegistration } from './instance_key.js';

export type RegistrationPassOutcome =
	| 'off'
	| 'held'
	| 'not-due'
	| 'unreadable'
	| 'claimed-elsewhere'
	| RegistrationOutcome;

/*
 * When this instance may next ask (research R9, R10): the time an earlier answer set, or, before any, the start of the
 * seventh UTC day after the first delivered report that carried the instance key. Null while no such report has
 * been delivered: FoxTrust cannot have seen one, so it could only answer "not yet".
 */
export function nextTryAfter(state: TelemetryState | null): Date | null {
	const registration = state?.registration;
	if (registration?.notBefore !== undefined) {
		return new Date(registration.notBefore);
	}
	if (registration?.firstKeyReportAt !== undefined) {
		return startOfDayAfter(
			new Date(registration.firstKeyReportAt),
			FIRST_REGISTRATION_AFTER_DAYS
		);
	}
	return null;
}

interface Answer {
	status: number;
	body: unknown;
	retryAfter: string | null;
}

async function send(body: Record<string, unknown>): Promise<Answer | null> {
	const version = packageVersion();
	try {
		const response = await fetch(REGISTRATION_DESTINATION, {
			method: 'POST',
			headers: {
				'content-type': 'application/json',
				'user-agent': version === undefined ? 'FoxAuth' : `FoxAuth/${version}`
			},
			body: JSON.stringify(body),
			redirect: 'manual',
			signal: AbortSignal.timeout(REGISTRATION_TIMEOUT_MS)
		});
		let parsed: unknown = null;
		try {
			parsed = await response.json();
		} catch {
			parsed = null;
		}
		return {
			status: response.status,
			body: parsed,
			retryAfter: response.headers.get('retry-after')
		};
	} catch {
		return null;
	}
}

function member(body: unknown, name: string): unknown {
	return typeof body === 'object' && body !== null && name in body
		? (body as Record<string, unknown>)[name]
		: undefined;
}

function wholeNumber(value: unknown): number | undefined {
	return typeof value === 'number' && Number.isInteger(value) && value >= 0
		? value
		: undefined;
}

/* `Retry-After` as seconds or an HTTP date; never earlier than the next UTC day, since one day is claimed at a time. */
function retryAt(at: Date, header: string | null): Date {
	const nextDay = startOfDayAfter(at, 1);
	if (header === null) return nextDay;
	const seconds = Number(header);
	const named = Number.isFinite(seconds)
		? new Date(at.getTime() + Math.max(0, seconds) * 1000)
		: new Date(header);
	if (Number.isNaN(named.getTime())) return nextDay;
	return named.getTime() > nextDay.getTime() ? named : nextDay;
}

/*
 * What an answer means for the next attempt, by FoxTrust's contract (research R9's table). A 201 is handled by the
 * caller, which must store the key before recording that it has one.
 */
function afterAnswer(
	at: Date,
	answer: Answer | null
): { changes: Partial<Registration>; outcome: RegistrationOutcome } {
	const stamp = at.toISOString();
	const error = member(answer?.body, 'error');
	if (answer?.status === 403 && error === 'not_yet') {
		const days = wholeNumber(member(answer.body, 'retryAfterDays')) ?? 1;
		return {
			outcome: 'not_yet',
			changes: {
				lastAnswer: { at: stamp, outcome: 'not_yet', retryAfterDays: days },
				notBefore: startOfDayAfter(at, Math.max(1, days)).toISOString()
			}
		};
	}
	if (
		(answer?.status === 403 && error === 'muted') ||
		(answer?.status === 409 && error === 'key_mismatch')
	) {
		const outcome = error === 'muted' ? 'muted' : 'key_mismatch';
		return {
			outcome,
			changes: {
				lastAnswer: { at: stamp, outcome },
				stopped: outcome,
				notBefore: startOfDayAfter(at, STOPPED_RETRY_DAYS).toISOString()
			}
		};
	}
	if (answer?.status === 400) {
		const named = member(answer.body, 'field');
		const field = REGISTRATION_FIELDS.find((known) => known === named);
		return {
			outcome: 'invalid',
			changes: {
				lastAnswer: {
					at: stamp,
					outcome: 'invalid',
					...(field === undefined ? {} : { field })
				},
				notBefore: startOfDayAfter(at, 1).toISOString()
			}
		};
	}
	if (answer?.status === 429 || answer?.status === 503) {
		const outcome = answer.status === 429 ? 'limited' : 'unavailable';
		return {
			outcome,
			changes: {
				lastAnswer: { at: stamp, outcome },
				notBefore: retryAt(at, answer.retryAfter).toISOString()
			}
		};
	}
	return {
		outcome: 'unreachable',
		changes: {
			lastAnswer: { at: stamp, outcome: 'unreachable' },
			notBefore: startOfDayAfter(at, 1).toISOString()
		}
	};
}

/*
 * One registration attempt, from the usage report's tick (research R9): only while lookups and usage reporting are on,
 * no key is in use, the next try is due, the instance key opens and today has not been claimed by another process.
 *
 * Swallows everything, as the usage report does (owner, 2026-10-28): a FoxTrust that cannot be reached, refuses or
 * answers nonsense is not an error a person, a log or the error store ever sees. The status shows the last answer.
 */
export async function registrationPass(
	at: Date = now(),
	{ ignoreSlot = false }: { ignoreSlot?: boolean } = {}
): Promise<RegistrationPassOutcome> {
	try {
		if (!ApplicationConfig['addressLookup.enabled'] || !reportingAllowed()) {
			return 'off';
		}
		const store = getTelemetryStateStore();
		const instanceId = await store.instanceId();
		const state = await store.read();
		if (keyInUse(state)) return 'held';
		const due = nextTryAfter(state);
		if (due === null || at.getTime() < due.getTime()) return 'not-due';
		if (!ignoreSlot && minuteOfDay(at) < slotOf(instanceId)) return 'not-due';
		const issuedAt = at.toISOString();
		const last = state?.registration?.lastIssuedAt;
		// Never a signing time at or before the last one sent (SI-5): a clock set back waits until it passes it.
		if (last !== undefined && issuedAt <= last) return 'not-due';
		const key = await instanceKey();
		if (!key.readable) return 'unreadable';
		if (!(await store.claimRegistrationDay(dayOf(at)))) {
			return 'claimed-elsewhere';
		}
		const nonce = crypto.randomBytes(16).toString('base64url');
		const fields = {
			instanceId,
			instanceKey: key.publicKey,
			issuedAt,
			nonce
		};
		const body = {
			format: REGISTRATION_FORMAT,
			...fields,
			signature: signRegistration(key.privateKey, fields)
		};
		// Written before the request leaves, so a crash after sending cannot let a later attempt reuse it.
		await store.updateRegistration({ lastIssuedAt: issuedAt });
		const answer = await send(body);

		if (answer?.status === 201) {
			const issued = member(answer.body, 'key');
			const dailyQuota = wholeNumber(member(answer.body, 'dailyQuota'));
			const burst = wholeNumber(member(answer.body, 'burst'));
			if (
				isFoxTrustKey(issued) &&
				dailyQuota !== undefined &&
				burst !== undefined
			) {
				await keepKey(issued);
				await store.setLookupKey({
					receivedAt: issuedAt,
					dailyQuota,
					burst
				});
				await store.updateRegistration(
					{ lastAnswer: { at: issuedAt, outcome: 'key' } },
					['stopped', 'notBefore']
				);
				return 'key';
			}
		}
		const { changes, outcome } = afterAnswer(at, answer);
		await store.updateRegistration(changes);
		return outcome;
	} catch {
		return 'unreachable';
	}
}
