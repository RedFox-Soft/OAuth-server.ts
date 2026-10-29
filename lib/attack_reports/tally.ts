import {
	ApplicationConfig,
	onSettingsApplied
} from '../configs/application.js';
import {
	ATTACK_MAX_TRACKED_ADDRESSES,
	PROBE_PATHS,
	type AttackTypeName,
	type ProbeLabel
} from '../consts/attack_report_fields.js';
import { callerAddressOf } from '../helpers/caller_address.js';
import { InvalidClientAuth } from '../helpers/errors.js';
import { now } from '../telemetry/clock.js';
import { reportedAddressOf } from './address.js';

/*
 * The attacks this process saw, per reported address and UTC hour (specs/114).
 *
 * `noteAttack` is called beside a refusal the server already makes, on the request path, so it is
 * synchronous, never awaits and cannot throw: counting must never slow or fail what is being counted (the
 * argument of lib/telemetry/counters.ts). It never writes the address anywhere but here. The sign-in throttle
 * keeps addresses out of its event and logs on purpose, and the only way an address leaves this process is
 * an attack report.
 *
 * In memory and per process, like the per-origin limiter: a datastore write per attacking request would be the
 * amplifier the limiter was built to avoid. Thresholds therefore apply per process, which the spec accepts.
 */

export interface AddressTally {
	counts: Partial<Record<AttackTypeName, number>>;
	probes: Set<ProbeLabel>;
}

export interface HourTally {
	/*
	 * At most ATTACK_MAX_TRACKED_ADDRESSES. Once full, new addresses are ignored for the rest of the hour while
	 * those already present keep counting. An LRU would instead evict the heaviest early hitter under an
	 * address-rotation flood, which is the address most worth reporting.
	 */
	addresses: Map<string, AddressTally>;
}

const HOUR_MS = 60 * 60 * 1000;

let hours = new Map<string, HourTally>();

export function hourOf(at: Date): string {
	return new Date(Math.floor(at.getTime() / HOUR_MS) * HOUR_MS).toISOString();
}

/* Only the current hour and the one before it are ever kept: the one before is the next report. */
function hourTallyFor(hour: string): HourTally {
	let tally = hours.get(hour);
	if (tally) return tally;
	const previous = new Date(new Date(hour).getTime() - HOUR_MS).toISOString();
	for (const kept of hours.keys()) {
		if (kept < previous) hours.delete(kept);
	}
	tally = { addresses: new Map() };
	hours.set(hour, tally);
	return tally;
}

export function noteAttack(
	request: Request,
	type: AttackTypeName,
	probe?: ProbeLabel
): void {
	try {
		if (!ApplicationConfig['attackReports.enabled']) return;
		const address = reportedAddressOf(callerAddressOf(request));
		if (address === null) return;
		const tally = hourTallyFor(hourOf(now()));
		let entry = tally.addresses.get(address);
		if (!entry) {
			if (tally.addresses.size >= ATTACK_MAX_TRACKED_ADDRESSES) return;
			entry = { counts: {}, probes: new Set() };
			tally.addresses.set(address, entry);
		}
		entry.counts[type] = (entry.counts[type] ?? 0) + 1;
		if (probe !== undefined) entry.probes.add(probe);
	} catch {
		// Counting is never a reason for a request to fail.
	}
}

const PROBE_EXACT = new Map<string, ProbeLabel>(
	PROBE_PATHS.flatMap((probe) =>
		probe.exact.map((path) => [path, probe.label] as const)
	)
);
const PROBE_PREFIXES: readonly (readonly [string, ProbeLabel])[] =
	PROBE_PATHS.flatMap((probe) =>
		probe.prefixes.map((prefix) => [prefix, probe.label] as const)
	);

/* Called for every request, so one map lookup and a short scan, never a URL object. */
export function probeLabelOf(path: string): ProbeLabel | null {
	const exact = PROBE_EXACT.get(path);
	if (exact !== undefined) return exact;
	for (const [prefix, label] of PROBE_PREFIXES) {
		if (path.startsWith(prefix)) return label;
	}
	return null;
}

/* Removes and returns one hour's tally, or undefined when nothing was counted in it. */
export function takeHour(hour: string): HourTally | undefined {
	const tally = hours.get(hour);
	hours.delete(hour);
	return tally;
}

/* Drops every hour before `hour`, so a closed hour that was not reported is not kept. */
export function dropHoursBefore(hour: string): void {
	for (const kept of hours.keys()) {
		if (kept < hour) hours.delete(kept);
	}
}

export function discardAll(): void {
	hours = new Map();
}

/* Turning reporting off discards what was counted and not yet sent (FR-020). */
onSettingsApplied((appliedKeys) => {
	if (
		appliedKeys.includes('attackReports.enabled') &&
		!ApplicationConfig['attackReports.enabled']
	) {
		discardAll();
	}
});

/* Test-only: a spec file starts with nothing counted by the one before it. */
export function resetAttackTallyForTests(): void {
	hours = new Map();
}

/*
 * A client credential refused at a token-side endpoint, counted only when one was presented (FR-002): a public
 * client sending its client_id alone, or a request naming no client at all, has guessed nothing. What decides
 * is the request, not the error's wording, so a refusal for an unknown client counts too when it came with a
 * secret, an assertion or a certificate.
 */
export function noteClientAuthFailure(
	request: Request,
	params: Record<string, unknown>,
	headers: Record<string, string | undefined>,
	error: unknown
): void {
	try {
		if (!(error instanceof InvalidClientAuth)) return;
		const presented =
			typeof params.client_secret === 'string' ||
			typeof params.client_assertion === 'string' ||
			/^basic\s/i.test(headers.authorization ?? '') ||
			/*
			 * The header itself, not the parsed certificate: reading that warns the operator when proxy
			 * certificates are not trusted, and a refusal an attacker can repeat must not write a log line.
			 */
			headers['client-cert'] !== undefined ||
			headers['x-client-cert'] !== undefined;
		if (presented) noteAttack(request, 'client_auth_failures');
	} catch {
		// Counting is never a reason for a request to fail.
	}
}
