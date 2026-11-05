import {
	getBehindProxyAppStore,
	getBucketGroupStore
} from '../../adapters/index.js';
import { UniqueValueTaken } from '../../adapters/conflicts.js';
import type {
	BehindProxyApp,
	BehindProxyAppPatch,
	BehindProxyRule,
	BehindProxyWho,
	UserBucket
} from '../../adapters/types.js';
import {
	canonicalAddress,
	type AddressProblem
} from '../../behind_proxy/address.js';
import { canonicalPath } from '../../behind_proxy/decide.js';
import { appSessions } from '../../behind_proxy/records.js';
import { mismatchedHostsOf } from '../../behind_proxy/usage.js';
import { issuerFor } from '../../configs/issuer.js';
import nanoid from '../../helpers/nanoid.js';
import { signUpsPaused } from '../../plans/signups.js';
import { AdminError } from '../auth/rbac.js';

/*
 * The web apps a project puts sign-in in front of through the operator's own proxy (specs/122): every rule about
 * what may be declared, in one place the console and an agent both reach through the admin routes. Each write
 * calls `record` after every refusal and before the write, so a refused request leaves no audit entry and an
 * accepted one is recorded before it takes effect.
 */

type RecordCreation = (id: string) => Promise<unknown>;

export type WhoInput =
	| { kind: 'groups'; groups: string[] }
	| { kind: 'project' }
	| { kind: 'public'; subtree: boolean }
	| { kind: 'none' };

export interface RuleInput {
	path: string;
	who: WhoInput;
}

export interface CreateAppInput {
	name: string;
	address: string;
	proxyKind: BehindProxyApp['proxyKind'];
	rootGroups: string[];
}

export interface UpdateAppInput {
	name?: string;
	address?: string;
	proxyKind?: BehindProxyApp['proxyKind'];
	rules?: RuleInput[];
}

const MAX_RULES = 50;
const MAX_GROUPS = 50;
const ROOT = '/';

function refuse(message: string, field: string): AdminError {
	return new AdminError(422, message, { field });
}

function nameOf(input: string): string {
	const name = input.trim();
	if (name.length === 0 || name.length > 100) {
		throw refuse('name must be 1 to 100 characters', 'name');
	}
	return name;
}

const ADDRESS_PROBLEMS: Readonly<Record<AddressProblem, string>> = {
	not_a_url: 'address must be a URL, such as https://app.example.com',
	not_https: 'address must start with https://',
	userinfo: 'address must not carry a user name or password',
	ip_literal: 'address must be a host name, not an IP address',
	no_host: 'address must name a host'
};

/* Only the origin is kept: a path, query or fragment pasted from a browser is dropped, and the answer shows it. */
async function addressOf(
	bucket: UserBucket,
	input: string,
	self?: string
): Promise<string> {
	const canonical = canonicalAddress(input);
	if ('problem' in canonical) {
		throw refuse(ADDRESS_PROBLEMS[canonical.problem], 'address');
	}
	const apps = await getBehindProxyAppStore().listByBucket(bucket._id);
	if (
		apps.some((app) => app._id !== self && app.address === canonical.address)
	) {
		throw refuse(
			`another app of this project is at ${canonical.address}`,
			'address'
		);
	}
	return canonical.address;
}

async function groupIdsOf(
	bucket: UserBucket,
	ids: readonly string[],
	field: string
): Promise<string[]> {
	const unique = [...new Set(ids)];
	if (unique.length === 0) {
		throw refuse('name at least one group', field);
	}
	if (unique.length > MAX_GROUPS) {
		throw refuse(`name at most ${String(MAX_GROUPS)} groups`, field);
	}
	const found = await getBucketGroupStore().findMany(unique);
	const ours = new Set(
		found
			.filter((group) => group.bucketId === bucket._id)
			.map((group) => group._id)
	);
	for (const id of unique) {
		if (!ours.has(id)) {
			throw refuse(`group ${id} is not a group of this project`, field);
		}
	}
	return unique;
}

/*
 * A rule's path as it is stored: as entered, without a trailing slash. Anything the check would read differently
 * from what was typed — a dot segment, a doubled slash, an escape — is refused here rather than rewritten, so the
 * console never shows a rule other than the one the administrator wrote.
 */
function rulePathOf(input: string): string {
	const path = input.replace(/\/+$/, '') || ROOT;
	if (/[?#*%;\\]/.test(path)) {
		throw refuse(
			`path ${input} must not contain ? # * % ; or a backslash`,
			'rules'
		);
	}
	const canonical = canonicalPath(path);
	if ('ambiguous' in canonical || canonical.path !== path) {
		throw refuse(
			`path ${input} must be a plain path such as /admin or /api/reports`,
			'rules'
		);
	}
	return canonical.path;
}

function byPath(a: BehindProxyRule, b: BehindProxyRule): number {
	if (a.path === b.path) return 0;
	return a.path < b.path ? -1 : 1;
}

async function rulesOf(
	bucket: UserBucket,
	input: readonly RuleInput[]
): Promise<BehindProxyRule[]> {
	if (input.length > MAX_RULES) {
		throw refuse(`at most ${String(MAX_RULES)} rules`, 'rules');
	}
	const rules: BehindProxyRule[] = [];
	const seen = new Set<string>();
	for (const rule of input) {
		const path = rulePathOf(rule.path);
		const key = path.toLowerCase();
		if (seen.has(key)) {
			throw refuse(`path ${path} has more than one rule`, 'rules');
		}
		seen.add(key);
		rules.push({ path, who: await whoOf(bucket, rule.who) });
	}
	if (!seen.has(ROOT)) {
		throw refuse('the rule for / must remain', 'rules');
	}
	return rules.sort(byPath);
}

async function whoOf(
	bucket: UserBucket,
	who: WhoInput
): Promise<BehindProxyWho> {
	switch (who.kind) {
		case 'groups':
			return {
				kind: 'groups',
				groupIds: await groupIdsOf(bucket, who.groups, 'rules')
			};
		case 'public':
			return { kind: 'public', subtree: who.subtree };
		case 'project':
		case 'none':
			return { kind: who.kind };
	}
}

function addressTaken(error: unknown): AdminError | null {
	return error instanceof UniqueValueTaken
		? refuse('another app of this project is at this address', 'address')
		: null;
}

export async function loadApp(
	bucket: UserBucket,
	id: string
): Promise<BehindProxyApp> {
	const app = await getBehindProxyAppStore().find(id);
	if (!app || app.bucketId !== bucket._id) {
		throw new AdminError(404, 'app not found');
	}
	return app;
}

export async function createApp(
	bucket: UserBucket,
	input: CreateAppInput,
	record: RecordCreation
): Promise<BehindProxyApp> {
	const name = nameOf(input.name);
	const address = await addressOf(bucket, input.address);
	const rootGroups = await groupIdsOf(bucket, input.rootGroups, 'rootGroups');

	const id = nanoid();
	await record(id);
	const now = new Date();
	try {
		return await getBehindProxyAppStore().create({
			_id: id,
			bucketId: bucket._id,
			name,
			address,
			proxyKind: input.proxyKind,
			rules: [{ path: ROOT, who: { kind: 'groups', groupIds: rootGroups } }],
			createdAt: now,
			updatedAt: now
		});
	} catch (error) {
		throw addressTaken(error) ?? error;
	}
}

/*
 * A change of address keeps the app's sessions: they belong to the app's id, and the redirect URI of the
 * project's implicit client follows the stored address on its next resolution.
 */
export async function updateApp(
	bucket: UserBucket,
	id: string,
	input: UpdateAppInput,
	record: () => Promise<unknown>
): Promise<BehindProxyApp> {
	await loadApp(bucket, id);
	const patch: BehindProxyAppPatch = {};
	if (input.name !== undefined) patch.name = nameOf(input.name);
	if (input.address !== undefined) {
		patch.address = await addressOf(bucket, input.address, id);
	}
	if (input.proxyKind !== undefined) patch.proxyKind = input.proxyKind;
	if (input.rules !== undefined) {
		patch.rules = await rulesOf(bucket, input.rules);
	}

	await record();
	let updated: BehindProxyApp | null;
	try {
		updated = await getBehindProxyAppStore().update(id, patch);
	} catch (error) {
		throw addressTaken(error) ?? error;
	}
	if (!updated) throw new AdminError(404, 'app not found');
	return updated;
}

/* The app goes with every session people hold at it, so a deleted app admits nobody on a cookie it issued. */
export async function deleteApp(
	bucket: UserBucket,
	id: string,
	record: () => Promise<unknown>
): Promise<void> {
	await loadApp(bucket, id);
	await record();
	await getBehindProxyAppStore().delete(id);
	await appSessions().destroyByOwner('appId', id);
}

/* The sessions of apps already removed with their project (lib/admin/buckets/destroy.ts). */
export async function endSessionsOfApps(ids: readonly string[]): Promise<void> {
	for (const id of ids) {
		await appSessions().destroyByOwner('appId', id);
	}
}

/*
 * Where the proxy sends its check: the project's own address, then the app's id. The issuer, because the check is
 * mounted wherever the project's sign-in is (bare at the root, under its path segment, or on its own origin).
 */
export function verifyUrlOf(bucket: UserBucket, appId: string): string {
	return `${issuerFor(bucket)}/verify/${appId}`;
}

/*
 * Whether anyone may create an account in the project now, which turns "Everyone in the project" into "anyone who
 * signs up". The registration page's own test: open, and not paused by the plan's active-user cap.
 */
export async function signUpsOpenIn(bucket: UserBucket): Promise<boolean> {
	return bucket.registrationOpen && !(await signUpsPaused(bucket));
}

function iso(date: Date | undefined): string | null {
	return date ? date.toISOString() : null;
}

/*
 * Apps as the console and an agent read them: in edge words, with each group named by its current name — or
 * `null` for one deleted since, which then admits nobody — the rule for `/` first, then by path.
 */
export async function viewApps(
	bucket: UserBucket,
	apps: readonly BehindProxyApp[]
) {
	const groupIds = [
		...new Set(
			apps.flatMap((app) =>
				app.rules.flatMap((rule) =>
					rule.who.kind === 'groups' ? rule.who.groupIds : []
				)
			)
		)
	];
	const groups = groupIds.length
		? await getBucketGroupStore().findMany(groupIds)
		: [];
	const names = new Map(
		groups
			.filter((group) => group.bucketId === bucket._id)
			.map((group) => [group._id, group.displayName])
	);
	const signUpsOpen = apps.length ? await signUpsOpenIn(bucket) : false;
	return apps.map((app) => ({
		id: app._id,
		name: app.name,
		address: app.address,
		proxyKind: app.proxyKind,
		rules: [...app.rules].sort(byPath).map(({ path, who }) => ({
			path,
			who:
				who.kind === 'groups'
					? {
							kind: 'groups' as const,
							groups: who.groupIds.map((id) => ({
								id,
								name: names.get(id) ?? null
							}))
						}
					: who
		})),
		verifyUrl: verifyUrlOf(bucket, app._id),
		checklist: {
			createdAt: app.createdAt.toISOString(),
			firstAskedAt: iso(app.firstAskedAt),
			firstSignInAt: iso(app.firstSignInAt),
			firstAllowedAt: iso(app.firstAllowedAt)
		},
		lastAskedAt: iso(app.lastAskedAt),
		/* The hosts the proxy recently reported for the app that were not its address, kept in memory only. */
		mismatchedHosts: mismatchedHostsOf(app._id),
		signUpsOpen
	}));
}

export async function viewApp(bucket: UserBucket, app: BehindProxyApp) {
	const [view] = await viewApps(bucket, [app]);
	return view;
}
