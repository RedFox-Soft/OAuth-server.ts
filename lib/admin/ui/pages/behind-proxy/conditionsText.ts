import type { TimeWindow } from '../../../../behind_proxy/clock.js';
import type {
	Condition,
	ConditionKind,
	NetworkFactsPart
} from '../../../../behind_proxy/conditions.js';
import type { Loosened } from '../../../../behind_proxy/condition_widening.js';

/*
 * Conditions at the proxy (specs/124) in the words the console shows them in: a rule's summary line, the save bar's
 * list of changes and the confirmation of a widening. Values of one condition are joined by "or", never a comma,
 * because "from Office, VPN" reads as both (research, UX У11).
 */

export const DAYS = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];

export const KIND_LABELS: Record<ConditionKind, string> = {
	network: 'From where',
	time: 'When',
	attribute: 'Attribute',
	fresh: 'Ask to sign in again',
	group: 'Groups'
};

export const ATTRIBUTE_LABELS: Record<string, string> = {
	department: 'Department',
	division: 'Division',
	organization: 'Organization',
	costCenter: 'Cost center',
	employeeNumber: 'Employee number',
	title: 'Title'
};

export function clock(minute: number): string {
	const h = Math.floor(minute / 60);
	const m = minute % 60;
	return `${String(h).padStart(2, '0')}:${String(m).padStart(2, '0')}`;
}

function or(values: readonly string[]): string {
	return values.join(' or ');
}

/* "Mon–Fri", "Sat, Sun", "Mon, Wed–Fri": runs of days written as ranges. */
export function daysText(days: readonly number[]): string {
	const sorted = [...days].sort((a, b) => a - b);
	const parts: string[] = [];
	for (let i = 0; i < sorted.length;) {
		let j = i;
		while (j + 1 < sorted.length && sorted[j + 1] === sorted[j] + 1) j += 1;
		parts.push(
			j - i >= 2
				? `${DAYS[sorted[i]]}–${DAYS[sorted[j]]}`
				: sorted
						.slice(i, j + 1)
						.map((d) => DAYS[d])
						.join(', ')
		);
		i = j + 1;
	}
	return parts.join(', ');
}

/* A window as a person reads it; one past midnight says where it ends: "Fri 22:00 → Sat 06:00". */
export function windowText(window: TimeWindow): string {
	if (window.end > window.start) {
		return `${daysText(window.days)} ${clock(window.start)}–${clock(window.end)}`;
	}
	if (window.days.length === 1) {
		const day = window.days[0];
		return `${DAYS[day]} ${clock(window.start)} → ${DAYS[(day + 1) % 7]} ${clock(window.end)}`;
	}
	return `${daysText(window.days)} ${clock(window.start)} → ${clock(window.end)} the next day`;
}

export function attributeText(name: string): string {
	return name.startsWith('claim:')
		? `claim ${name.slice('claim:'.length)}`
		: (ATTRIBUTE_LABELS[name] ?? name).toLowerCase();
}

export function freshText(minutes: number): string {
	if (minutes % 1440 === 0) {
		const days = minutes / 1440;
		return days === 1 ? '1 day' : `${String(days)} days`;
	}
	if (minutes % 60 === 0) {
		const hours = minutes / 60;
		return hours === 1 ? '1 h' : `${String(hours)} h`;
	}
	return `${String(minutes)} min`;
}

const CATEGORY_WORDS = {
	tor: 'Tor',
	vpn: 'a VPN',
	hosting: 'hosting'
} as const;

function countryNames(codes: readonly string[]): string {
	let names: Intl.DisplayNames | null = null;
	try {
		names = new Intl.DisplayNames(['en'], { type: 'region' });
	} catch {
		names = null;
	}
	return or(codes.map((code) => names?.of(code) ?? code));
}

/* "not from Tor, a VPN or hosting", "only from Germany or Austria", and what a match leads to (specs/129 FR-026). */
export function factsText(facts: NetworkFactsPart): string {
	const parts: string[] = [];
	if (facts.categories.length > 0) {
		parts.push(
			`not from ${or(facts.categories.map((c) => CATEGORY_WORDS[c]))}`
		);
	}
	if (facts.countries) {
		parts.push(
			`${facts.countries.mode === 'only' ? 'only from' : 'not from'} ${countryNames(facts.countries.codes)}`
		);
	}
	const outcome = facts.outcome;
	const what =
		outcome.kind === 'refuse'
			? ''
			: ` (otherwise sign in again${outcome.withPasskey ? ' with a passkey' : outcome.withCode ? ' with two-step sign-in' : ''} within ${freshText(outcome.maxAgeMinutes)})`;
	return `${parts.join(', ')}${what}`;
}

/* Whether a condition names countries, so the DB-IP attribution goes beside it (FR-025). */
export function namesCountries(condition: Condition): boolean {
	return (
		condition.kind === 'network' && condition.facts?.countries !== undefined
	);
}

export function conditionText(
	condition: Condition,
	nameOf: (groupId: string) => string | null = () => null
): string {
	switch (condition.kind) {
		case 'network': {
			const parts: string[] = [];
			if (condition.only.length > 0) parts.push(`from ${or(condition.only)}`);
			if (condition.not.length > 0) parts.push(`not from ${or(condition.not)}`);
			if (condition.facts) parts.push(factsText(condition.facts));
			return parts.join(', ');
		}
		case 'time':
			return or(condition.windows.map(windowText));
		case 'attribute':
			return `${attributeText(condition.attribute)} is ${or(condition.values)}`;
		case 'fresh':
			return condition.withPasskey
				? `signed in with a passkey within ${freshText(condition.maxAgeMinutes)}`
				: condition.withCode
					? `signed in with two steps within ${freshText(condition.maxAgeMinutes)}`
					: `signed in within ${freshText(condition.maxAgeMinutes)}`;
		case 'group':
			return `members of ${or(condition.groupIds.map((id) => nameOf(id) ?? 'a deleted group'))}`;
	}
}

/* What a widening's loosened condition says in the confirmation: the condition it no longer holds to. */
export function loosenedText(
	loosened: Loosened,
	nameOf?: (groupId: string) => string | null
): string {
	return `no longer only "${conditionText(loosened.before, nameOf)}"`;
}
