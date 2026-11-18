import {
	getActivityStore,
	getBehindProxyAppStore,
	getPersonActivityStore,
	getProtectedResourceStore,
	getSchemaMigrationStore
} from '../adapters/index.js';
import type {
	BehindProxyApp,
	PersonActivityCursor,
	PersonActivityRow,
	ProtectedResource,
	UserBucket
} from '../adapters/types.js';
import {
	APPS_USED_SCAN,
	NEW_ADDRESS_AFTER,
	PERSON_ACTIVITY_DAYS
} from '../consts/person_activity.js';
import {
	ADMIN_SIGN_IN_LOG_FENCE_ID,
	PERSON_ACTIVITY_FENCE_ID
} from '../consts/migrations.js';
import { ADMIN_BUCKET_ID, ADMIN_CLIENT_ID } from '../admin/consts.js';
import { ADMIN_MCP_CLIENT_ID } from '../mcp/consts.js';
import { knownProviderByIssuer } from '../consts/known_providers.js';
import { ApplicationConfig } from '../configs/application.js';
import { newestFirst } from '../adapters/person_activity_rows.js';
import { Client } from '../models/client.js';
import { namespaceOf } from '../resources/namespace.js';
import {
	checksWords,
	toolsView,
	wordsOf,
	type RowWords,
	type ToolsView
} from './words.js';
import { lookupState, type LookupState } from '../address_lookup/status.js';

/*
 * Reading a person's activity (specs/133 contracts/admin-api.md). Names are looked up as they are today, for the
 * console to show; the reason phrases come from the fixed table and name only what was recorded (research R18).
 */

const RESERVED_CLIENT_NAMES: ReadonlyMap<string, string> = new Map([
	[ADMIN_CLIENT_ID, 'Console'],
	[ADMIN_MCP_CLIENT_ID, 'Admin MCP (reserved client)']
]);

const began = new Map<string, Date>();

async function fenceAppliedAt(id: string): Promise<Date | null> {
	const known = began.get(id);
	if (known) return known;
	const records = await getSchemaMigrationStore().all();
	const fence = records.find((record) => record.id === id);
	if (!fence) return null;
	began.set(id, fence.appliedAt);
	return fence.appliedAt;
}

/*
 * When recording began: the time the fence migration was recorded (research R14), on a fresh install the
 * provisioning. Kept once found, because it never changes; read again while absent, because `db:migrate` may record
 * it while the server runs. Administrators' sign-ins began with a fence of their own (specs/137 research R4), so for
 * the administrators' project it is the later of the two.
 */
export async function recordingBegan(bucketId?: string): Promise<Date | null> {
	const people = await fenceAppliedAt(PERSON_ACTIVITY_FENCE_ID);
	if (bucketId !== ADMIN_BUCKET_ID) return people;
	const administrators = await fenceAppliedAt(ADMIN_SIGN_IN_LOG_FENCE_ID);
	if (!people || !administrators) return administrators ?? people;
	return administrators > people ? administrators : people;
}

export function forgetRecordingBeganForTests(): void {
	began.clear();
}

export interface ActivityRowView {
	id: string;
	day: string;
	kind: PersonActivityRow['kind'];
	outcome: PersonActivityRow['outcome'];
	reason: PersonActivityRow['reason'];
	words: RowWords;
	place: PersonActivityRow['place'] & { name: string | null };
	client: string | null;
	address: string | null;
	addressFrom: 'sign_in' | 'proxy' | null;
	facts: { country: string | null; categories: string[] } | null;
	/* The address's network owner and location, looked up at FoxTrust's API (specs/136), or null. */
	lookup: {
		asn: number | null;
		asName: string | null;
		regionCode: string | null;
		region: string | null;
		city: string | null;
	} | null;
	newAddress: boolean;
	/* Why the owner was emailed about this sign-in (specs/138), or null. */
	alerted: PersonActivityRow['alerted'] | null;
	count: number;
	/* A use row (specs/134): the proxy checks behind it, said only in a tooltip, never as a count of visits. */
	checks: string | null;
	tools: ToolsView | null;
	firstAt: string;
	lastAt: string;
	check: { app: string } | { api: string } | null;
}

export interface ActivityPageView {
	/* Whether this server records now: the console says so when an operator turned it off. */
	recording: boolean;
	recordingBegan: string | null;
	keptDays: number;
	rows: ActivityRowView[];
	next: string | null;
	busyDays: string[];
	/* Why rows may lack an owner and location, as the instance stands now (specs/136 research R13). */
	lookupState: LookupState;
}

export interface ActivityPageQuery {
	kind?: PersonActivityRow['kind'];
	outcome?: PersonActivityRow['outcome'];
	before?: string;
	limit?: number;
}

/* The cursor is opaque to its reader: the last row's time and id, so the next page starts strictly after it. */
function encodeCursor(cursor: PersonActivityCursor): string {
	return Buffer.from(
		JSON.stringify([cursor.lastAt.toISOString(), cursor.id])
	).toString('base64url');
}

function decodeCursor(
	text: string | undefined
): PersonActivityCursor | undefined {
	if (text === undefined || text === '') return undefined;
	try {
		const parsed: unknown = JSON.parse(
			Buffer.from(text, 'base64url').toString('utf8')
		);
		if (
			Array.isArray(parsed) &&
			parsed.length === 2 &&
			typeof parsed[0] === 'string' &&
			typeof parsed[1] === 'string'
		) {
			const lastAt = new Date(parsed[0]);
			if (!Number.isNaN(lastAt.getTime())) return { lastAt, id: parsed[1] };
		}
	} catch {
		return undefined;
	}
	return undefined;
}

/* Today's names for what the rows name, read once per page; the person's own page reads them too (own.ts). */
export class Names {
	private apps = new Map<string, Promise<BehindProxyApp | null>>();
	private appsByOrigin: Promise<BehindProxyApp[]> | null = null;
	private apis = new Map<string, Promise<ProtectedResource | null>>();
	private clients = new Map<string, Promise<string | null>>();

	constructor(private bucket: UserBucket) {}

	app(id: string): Promise<BehindProxyApp | null> {
		let found = this.apps.get(id);
		if (!found) {
			found = getBehindProxyAppStore()
				.find(id)
				.then((app) => (app?.bucketId === this.bucket._id ? app : null));
			this.apps.set(id, found);
		}
		return found;
	}

	async appAt(origin: string): Promise<BehindProxyApp | null> {
		this.appsByOrigin ??= getBehindProxyAppStore().listByBucket(
			this.bucket._id
		);
		const apps = await this.appsByOrigin;
		return (
			apps.find((app) => {
				try {
					return new URL(app.address).origin === origin;
				} catch {
					return false;
				}
			}) ?? null
		);
	}

	api(identifier: string): Promise<ProtectedResource | null> {
		let found = this.apis.get(identifier);
		if (!found) {
			found = getProtectedResourceStore()
				.find(namespaceOf(this.bucket), identifier)
				.then((api) => (api?.bucketId === this.bucket._id ? api : null));
			this.apis.set(identifier, found);
		}
		return found;
	}

	client(id: string): Promise<string | null> {
		/*
		 * The console and the reserved MCP client carry no `clientName`, and they are where administrators sign in most
		 * (specs/137 research R5): without a name every such row would read "The app".
		 */
		const reserved = RESERVED_CLIENT_NAMES.get(id);
		if (reserved !== undefined) return Promise.resolve(reserved);
		let found = this.clients.get(id);
		if (!found) {
			found = Client.tryFind(id).then((client) => client?.clientName ?? null);
			this.clients.set(id, found);
		}
		return found;
	}

	provider(id: string): string | null {
		const provider = this.bucket.federation.find((p) => p.id === id);
		if (!provider) return null;
		return (
			knownProviderByIssuer(provider.issuer)?.displayName ??
			provider.displayName
		);
	}
}

async function viewOf(
	row: PersonActivityRow,
	names: Names,
	newAddress: boolean
): Promise<ActivityRowView> {
	let place: string | null = null;
	let client: string | null = null;
	let check: ActivityRowView['check'] = null;
	if (row.kind === 'app' && row.place.appId) {
		const app = await names.app(row.place.appId);
		place = app?.name ?? null;
		if (app) check = { app: app._id };
	} else if (row.kind === 'api' && row.place.resource) {
		const api = await names.api(row.place.resource);
		place = api?.name ?? null;
		if (api) check = { api: api.identifier };
		if (row.place.clientId) client = await names.client(row.place.clientId);
	} else if (row.place.appOrigin) {
		place = (await names.appAt(row.place.appOrigin))?.name ?? null;
	} else if (row.place.clientId) {
		place = await names.client(row.place.clientId);
	}
	/* A sign-in turned away because an API it asked for wants a code names that API (specs/130). */
	const asking =
		row.kind === 'signIn' && row.place.resource
			? ((await names.api(row.place.resource))?.name ?? null)
			: null;
	const provider = row.place.providerId
		? names.provider(row.place.providerId)
		: null;
	return {
		id: row._id,
		day: row.day,
		kind: row.kind,
		outcome: row.outcome,
		reason: row.reason,
		words: wordsOf(row, { place, client, provider, asking }),
		place: { ...row.place, name: place },
		client,
		address: row.address ?? null,
		addressFrom: row.addressFrom ?? null,
		facts: row.facts
			? {
					country: row.facts.country ?? null,
					categories: [...row.facts.categories]
				}
			: null,
		lookup: row.lookup
			? {
					asn: row.lookup.asn ?? null,
					asName: row.lookup.asName ?? null,
					regionCode: row.lookup.regionCode ?? null,
					region: row.lookup.region ?? null,
					city: row.lookup.city ?? null
				}
			: null,
		newAddress,
		alerted: row.alerted ?? null,
		count: row.count,
		checks: row.reason === 'used' ? checksWords(row.count) : null,
		tools: toolsView(row.tools),
		firstAt: row.firstAt.toISOString(),
		lastAt: row.lastAt.toISOString(),
		check
	};
}

/*
 * "New address" (FR-022, У10): a successful sign-in from an address none of the person's earlier successful sign-ins
 * used, said only once there are at least five of them to compare with. Never on an app or API row.
 */
async function newAddressIds(
	bucketId: string,
	accountId: string,
	rows: readonly PersonActivityRow[],
	now: Date
): Promise<Set<string>> {
	const candidates = rows.filter(
		(row) => row.kind === 'signIn' && row.outcome === 'let_in' && row.address
	);
	if (candidates.length === 0) return new Set();
	/* Every successful sign-in kept: within 90 days they are at most a few hundred for one person. */
	const { rows: history } = await getPersonActivityStore().listForPerson(
		bucketId,
		accountId,
		{ kind: 'signIn', outcome: 'let_in', limit: 500, now }
	);
	const newAddress = new Set<string>();
	for (const row of candidates) {
		const earlier = history.filter(
			(other) =>
				other.lastAt.getTime() < row.lastAt.getTime() ||
				(other.lastAt.getTime() === row.lastAt.getTime() && other._id < row._id)
		);
		if (earlier.length < NEW_ADDRESS_AFTER) continue;
		if (!earlier.some((other) => other.address === row.address)) {
			newAddress.add(row._id);
		}
	}
	return newAddress;
}

export async function activityPage(
	bucket: UserBucket,
	accountId: string,
	query: ActivityPageQuery
): Promise<ActivityPageView> {
	const now = new Date();
	const store = getPersonActivityStore();
	const before = decodeCursor(query.before);
	const page = await store.listForPerson(bucket._id, accountId, {
		limit: query.limit ?? 50,
		now,
		...(query.kind === undefined ? {} : { kind: query.kind }),
		...(query.outcome === undefined ? {} : { outcome: query.outcome }),
		...(before === undefined ? {} : { before })
	});
	const names = new Names(bucket);
	const fresh = await newAddressIds(bucket._id, accountId, page.rows, now);
	const rows = await Promise.all(
		page.rows.map((row) => viewOf(row, names, fresh.has(row._id)))
	);
	const days = [...new Set(page.rows.map((row) => row.day))];
	const [busyDays, startedAt, lookups] = await Promise.all([
		store.overflowDays(bucket._id, days, now),
		recordingBegan(bucket._id),
		lookupState()
	]);
	return {
		recording: ApplicationConfig['personActivity.enabled'],
		recordingBegan: startedAt?.toISOString() ?? null,
		keptDays: PERSON_ACTIVITY_DAYS,
		rows,
		next: page.next ? encodeCursor(page.next) : null,
		busyDays: busyDays.sort(),
		lookupState: lookups
	};
}

export interface FeedRowView extends ActivityRowView {
	accountId: string;
	email: string | null;
}

export interface ActivityFeedView extends Omit<ActivityPageView, 'rows'> {
	rows: FeedRowView[];
}

/*
 * Every administrator's sign-ins on one page, newest first (specs/137): the union of each account's own indexed
 * timeline, cut to `limit` in the timeline's order, so paging with the last row's cursor neither drops nor repeats
 * one. Only for the administrators' project, whose accounts are tens; a project of people would need an index.
 */
export async function activityFeed(
	bucket: UserBucket,
	accounts: readonly { _id: string; email: string }[],
	query: Omit<ActivityPageQuery, 'kind'>
): Promise<ActivityFeedView> {
	const now = new Date();
	const store = getPersonActivityStore();
	const before = decodeCursor(query.before);
	const limit = query.limit ?? 50;
	const pages = await Promise.all(
		accounts.map((account) =>
			store.listForPerson(bucket._id, account._id, {
				limit,
				now,
				kind: 'signIn',
				...(query.outcome === undefined ? {} : { outcome: query.outcome }),
				...(before === undefined ? {} : { before })
			})
		)
	);
	const merged = pages.flatMap((page) => page.rows).sort(newestFirst);
	const shown = merged.slice(0, limit);
	const last = shown.at(-1);
	const more = merged.length > limit || pages.some((page) => page.next);
	const names = new Names(bucket);
	const emails = new Map(
		accounts.map((account) => [account._id, account.email])
	);
	const fresh = new Set<string>();
	for (const accountId of new Set(shown.map((row) => row.accountId))) {
		const mine = shown.filter((row) => row.accountId === accountId);
		for (const id of await newAddressIds(bucket._id, accountId, mine, now)) {
			fresh.add(id);
		}
	}
	const rows = await Promise.all(
		shown.map(async (row) => ({
			...(await viewOf(row, names, fresh.has(row._id))),
			accountId: row.accountId,
			email: emails.get(row.accountId) ?? null
		}))
	);
	const days = [...new Set(shown.map((row) => row.day))];
	const [busyDays, startedAt, lookups] = await Promise.all([
		store.overflowDays(bucket._id, days, now),
		recordingBegan(bucket._id),
		lookupState()
	]);
	return {
		recording: ApplicationConfig['personActivity.enabled'],
		recordingBegan: startedAt?.toISOString() ?? null,
		keptDays: PERSON_ACTIVITY_DAYS,
		rows,
		next:
			more && last ? encodeCursor({ lastAt: last.lastAt, id: last._id }) : null,
		busyDays: busyDays.sort(),
		lookupState: lookups
	};
}

export interface ActivitySummary {
	recordingBegan: string | null;
	keptDays: number;
	lastSignIn: {
		at: string;
		clientId: string | null;
		name: string | null;
		method: string | null;
	} | null;
	notLetInSince: {
		at: string;
		count: number;
		reason: string;
		kind: PersonActivityRow['kind'];
	} | null;
	lastActive: { day: string } | { month: string } | null;
	/* Apps behind the proxy and APIs the person was let through in the last 90 days, newest first (specs/134). */
	appsUsed: AppUsed[];
}

export interface AppUsed {
	kind: 'app' | 'api';
	/* The app's id, or the API's identifier. */
	id: string;
	name: string | null;
	/* The UTC day last used. */
	lastDay: string;
}

/*
 * What a person used (specs/134 research R8), from their use rows: one line per app or API, its latest day. An API
 * reached through two applications is one line. Names as they are today.
 */
async function appsUsedBy(
	bucket: UserBucket,
	accountId: string,
	now: Date,
	names: Names
): Promise<AppUsed[]> {
	const store = getPersonActivityStore();
	const [apps, apis] = await Promise.all(
		(['app', 'api'] as const).map((kind) =>
			store.listForPerson(bucket._id, accountId, {
				kind,
				outcome: 'let_in',
				limit: APPS_USED_SCAN,
				now
			})
		)
	);
	const latest = new Map<string, AppUsed>();
	for (const row of [...apps.rows, ...apis.rows]) {
		const id = row.kind === 'app' ? row.place.appId : row.place.resource;
		if (id === undefined || (row.kind !== 'app' && row.kind !== 'api'))
			continue;
		const key = `${row.kind}\u0000${id}`;
		const seen = latest.get(key);
		if (!seen || row.day > seen.lastDay) {
			latest.set(key, { kind: row.kind, id, name: null, lastDay: row.day });
		}
	}
	const used = [...latest.values()].sort((a, b) =>
		a.lastDay < b.lastDay ? 1 : a.lastDay > b.lastDay ? -1 : 0
	);
	for (const entry of used) {
		entry.name =
			entry.kind === 'app'
				? ((await names.app(entry.id))?.name ?? null)
				: ((await names.api(entry.id))?.name ?? null);
	}
	return used;
}

const RECENT_ROWS = 200;

/*
 * The latest day the person was marked active, else the latest month (R17), in one read of their marks (specs/134
 * research R5).
 */
async function lastActive(
	bucketId: string,
	accountId: string,
	now: Date
): Promise<ActivitySummary['lastActive']> {
	const marked = await getActivityStore().lastMarkedMany(
		bucketId,
		[accountId],
		now
	);
	return marked.get(accountId) ?? null;
}

export type SignInSummary = Pick<
	ActivitySummary,
	'lastSignIn' | 'notLetInSince'
>;

/*
 * The last successful sign-in, and what turned the person away after it: the Profile tab's first two lines, and an
 * administrator's line in Accounts (specs/137). No address, country or device, so reading it is not audited.
 */
export async function signInSummary(
	bucket: UserBucket,
	accountId: string,
	now: Date,
	names: Names
): Promise<SignInSummary> {
	const store = getPersonActivityStore();
	const [recent, signedIn] = await Promise.all([
		store.listForPerson(bucket._id, accountId, { limit: RECENT_ROWS, now }),
		store.listForPerson(bucket._id, accountId, {
			kind: 'signIn',
			outcome: 'let_in',
			limit: 1,
			now
		})
	]);
	const last = signedIn.rows.at(0);
	let lastSignIn: ActivitySummary['lastSignIn'] = null;
	if (last) {
		const view = await viewOf(last, names, false);
		lastSignIn = {
			at: view.lastAt,
			clientId: last.place.clientId ?? null,
			name: view.place.name,
			method: view.words.method
		};
	}
	const after = recent.rows.filter(
		(row) =>
			row.outcome !== 'let_in' &&
			(!last || row.lastAt.getTime() > last.lastAt.getTime())
	);
	let notLetInSince: ActivitySummary['notLetInSince'] = null;
	const latest = after.at(0);
	if (latest) {
		const view = await viewOf(latest, names, false);
		notLetInSince = {
			at: view.lastAt,
			count: after.reduce((sum, row) => sum + row.count, 0),
			reason: view.words.reason,
			kind: latest.kind
		};
	}
	return { lastSignIn, notLetInSince };
}

/*
 * The Profile tab's lines (FR-021). No address, country or device: it is read on every person's page, unaudited, so it
 * carries nothing the audit of the timeline protects (research R16).
 */
export async function activitySummary(
	bucket: UserBucket,
	accountId: string
): Promise<ActivitySummary> {
	const now = new Date();
	const names = new Names(bucket);
	const [{ lastSignIn, notLetInSince }, startedAt, active, appsUsed] =
		await Promise.all([
			signInSummary(bucket, accountId, now, names),
			recordingBegan(bucket._id),
			lastActive(bucket._id, accountId, now),
			appsUsedBy(bucket, accountId, now, names)
		]);
	return {
		recordingBegan: startedAt?.toISOString() ?? null,
		keptDays: PERSON_ACTIVITY_DAYS,
		lastSignIn,
		notLetInSince,
		lastActive: active,
		appsUsed
	};
}
