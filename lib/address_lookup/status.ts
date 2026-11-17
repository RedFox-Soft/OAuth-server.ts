import { ApplicationConfig } from '../configs/application.js';
import { getTelemetryStateStore } from '../adapters/index.js';
import type { RegistrationOutcome } from '../adapters/types.js';
import { now } from '../telemetry/clock.js';
import { reportingAllowed } from '../telemetry/status.js';
import { dayOf } from './days.js';
import { keyInUse } from './foxtrust_key.js';
import { instanceKey } from './instance_key.js';
import { nextTryAfter } from './register.js';

/*
 * Why a row of a person's activity may lack an owner and location, as the instance stands now (research R13): every
 * reader of activity sees it, and it says nothing about the key but whether there is one.
 */
export type LookupState = 'on' | 'off' | 'no-key' | 'used-up';

export async function lookupState(at: Date = now()): Promise<LookupState> {
	if (!ApplicationConfig['addressLookup.enabled']) return 'off';
	try {
		const state = await getTelemetryStateStore().read();
		if (!keyInUse(state)) return 'no-key';
		return state?.lookups?.exhaustedDay === dayOf(at) ? 'used-up' : 'on';
	} catch {
		return 'no-key';
	}
}

export type AddressLookupState =
	'off' | 'key-unreadable' | 'on' | 'stopped' | 'reporting-off' | 'waiting';

export interface AddressLookupStatus {
	setting: boolean;
	state: AddressLookupState;
	instanceId: string;
	instanceKey: string | null;
	key: { receivedAt: string; dailyQuota: number; burst: number } | null;
	today: {
		day: string;
		limit: number | null;
		remaining: number | null;
		usedUp: boolean;
	} | null;
	registration: {
		firstKeyReportAt: string | null;
		lastTriedAt: string | null;
		lastAnswer: RegistrationOutcome | null;
		lastInvalidField: string | null;
		nextTryAfter: string | null;
	};
	stopped: 'muted' | 'key_mismatch' | null;
}

/*
 * What the super administrator reads beside the setting, and the agent through address_lookup_status_get
 * (contracts/admin-api.md §1). The key itself is never part of it (SI-7), nor the private half of the instance key
 * (SI-1): only the public half, which FoxTrust support asks for.
 */
export async function addressLookupStatus(
	at: Date = now()
): Promise<AddressLookupStatus> {
	const store = getTelemetryStateStore();
	const instanceId = await store.instanceId();
	const state = await store.read();
	const own = await instanceKey().catch(() => ({ readable: false as const }));
	const registration = state?.registration;
	const inUse = keyInUse(state);
	const day = dayOf(at);
	const lookupKey = state?.lookupKey;
	const figures = state?.lookups?.day === day ? state.lookups : undefined;
	const setting = ApplicationConfig['addressLookup.enabled'];

	/*
	 * A server without a datastore never reports, so it never has a first report to count from: it reads as waiting
	 * with no date, which is what it is.
	 */
	const status: AddressLookupState = !setting
		? 'off'
		: !own.readable
			? 'key-unreadable'
			: inUse
				? 'on'
				: registration?.stopped !== undefined
					? 'stopped'
					: !reportingAllowed()
						? 'reporting-off'
						: 'waiting';
	const next = nextTryAfter(state);
	return {
		setting,
		state: status,
		instanceId,
		instanceKey: own.readable ? own.publicKey : null,
		key:
			inUse && lookupKey
				? {
						receivedAt: lookupKey.receivedAt,
						dailyQuota: lookupKey.dailyQuota,
						burst: lookupKey.burst
					}
				: null,
		today:
			inUse && lookupKey
				? {
						day,
						limit: figures?.limit ?? lookupKey.dailyQuota,
						remaining:
							figures?.remaining ?? (figures ? null : lookupKey.dailyQuota),
						usedUp: state.lookups?.exhaustedDay === day
					}
				: null,
		registration: {
			firstKeyReportAt: registration?.firstKeyReportAt ?? null,
			lastTriedAt: registration?.lastAnswer?.at ?? null,
			lastAnswer: registration?.lastAnswer?.outcome ?? null,
			lastInvalidField: registration?.lastAnswer?.field ?? null,
			nextTryAfter: inUse || next === null ? null : next.toISOString()
		},
		stopped: registration?.stopped ?? null
	};
}
