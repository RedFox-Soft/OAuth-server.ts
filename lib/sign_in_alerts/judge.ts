import type { PersonActivityRow } from '../adapters/types.js';

export type Newness = 'network' | 'browser' | 'both';

/* A successful sign-in, the only kind that is judged or that counts as history. */
export function isSignedIn(row: PersonActivityRow): boolean {
	return (
		row.kind === 'signIn' &&
		row.outcome === 'let_in' &&
		row.reason === 'signed_in'
	);
}

/*
 * Whether a key of the row is new among the earlier rows, compared only when both sides know one (specs/138 research
 * R2): a server that began looking networks up yesterday must not call every network new because its history has no
 * owners yet. `undefined` is "not judged".
 */
function isNewAmong<K>(
	key: K | undefined,
	earlier: readonly PersonActivityRow[],
	keyOf: (row: PersonActivityRow) => K | undefined
): boolean | undefined {
	if (key === undefined) return undefined;
	const known = earlier
		.map(keyOf)
		.filter((value): value is K => value !== undefined);
	if (known.length === 0) return undefined;
	return !known.includes(key);
}

const asnOf = (row: PersonActivityRow) => row.lookup?.asn;
const countryOf = (row: PersonActivityRow) => row.facts?.country;
const deviceOf = (row: PersonActivityRow) =>
	row.device ? `${row.device.browser}/${row.device.system}` : undefined;

/*
 * The network: its owner when both sides know one, else its country when both know one. A new address inside a known
 * network is not new: home and mobile addresses change all the time, and an email about each would be ignored.
 */
function networkIsNew(
	row: PersonActivityRow,
	earlier: readonly PersonActivityRow[]
): boolean {
	return (
		isNewAmong(asnOf(row), earlier, asnOf) ??
		isNewAmong(countryOf(row), earlier, countryOf) ??
		false
	);
}

/*
 * Why a successful sign-in is new for its account, against `history`: the account's successful sign-ins of the last
 * 90 days. Only rows before this one count, so the order rows are written in does not matter; nothing to compare
 * means nothing new (FR-002).
 */
export function judge(
	row: PersonActivityRow,
	history: readonly PersonActivityRow[]
): Newness | null {
	const earlier = history.filter(
		(other) =>
			other._id !== row._id &&
			other.bucketId === row.bucketId &&
			other.accountId === row.accountId &&
			isSignedIn(other) &&
			other.firstAt.getTime() < row.firstAt.getTime()
	);
	if (earlier.length === 0) return null;
	const network = networkIsNew(row, earlier);
	const browser = isNewAmong(deviceOf(row), earlier, deviceOf) ?? false;
	if (network && browser) return 'both';
	if (network) return 'network';
	if (browser) return 'browser';
	return null;
}

/* The network a claim is keyed by: the owner, else the country, else none. */
export function networkKey(row: PersonActivityRow): string {
	const asn = asnOf(row);
	if (asn !== undefined) return `as:${String(asn)}`;
	const country = countryOf(row);
	return country === undefined ? '-' : `cc:${country}`;
}

export function browserKey(row: PersonActivityRow): string {
	return deviceOf(row) ?? '-';
}
