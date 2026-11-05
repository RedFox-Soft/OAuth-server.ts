import { Type, type Static } from '@sinclair/typebox';

import { elysia } from 'lib/index.ts';
import { ISSUER } from 'lib/configs/env.js';
import { getBucketGroupStore, getBucketStore } from 'lib/adapters/index.ts';
import type { User } from 'lib/adapters/types.ts';
import { UNASSIGNED_GROUP_ID } from 'lib/admin/consts.ts';
import { forgetBucketAddresses } from 'lib/admin/auth/bucketAddress.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { AccessToken } from 'lib/models/access_token.js';
import { Client } from 'lib/models/client.js';
import { ADMIN_MCP_CLIENT_ID, MCP_RESOURCE } from 'lib/mcp/consts.ts';
import nanoid from 'lib/helpers/nanoid.ts';
import { createAdministrator } from '../administrators.ts';
import { groupIdFor } from '../admin_session.ts';
import { cookieFor } from '../admin/ownership_fixtures.ts';
import { adminCookie } from '../end_user_lifecycle/fixtures.ts';
import { Browser, PASSWORD, person } from '../connected_apps/helpers.ts';
import { admin, type Reply } from '../provisioning/helpers.ts';
import { call, rpc, type McpMessage } from '../mcp/rpc.ts';
import { present, shaped } from '../shape.ts';

/*
 * Apps behind a proxy (specs/122) as the people around them reach them: an administrator through the real admin
 * routes, an agent through /mcp, and a reverse proxy through the check endpoint — sent exactly as Caddy, Traefik or
 * nginx would send it, with the original host, path and method in `X-Forwarded-*` and the browser's own cookies.
 */

export interface Member {
	email: string;
	accountId: string;
}

export interface Project {
	id: string;
	slug: string;
	/* Bucket group ids. */
	staff: string;
	admins: string;
}

export interface World {
	/* A super administrator's console cookie. */
	cookie: string;
	/* Root open to Staff in most cases; Staff and Admins groups, one person in each and one in neither. */
	acme: Project & {
		staffMember: Member;
		adminMember: Member;
		outsider: Member;
	};
	/* A second project, whose apps must be unknown at acme's address. */
	beta: Project & { staffMember: Member };
	/* A project that lets anyone create an account. */
	open: Project & { staffMember: Member };
}

export async function project(
	name: string,
	fields: { registrationOpen?: boolean; ownerGroupId?: string } = {}
): Promise<Project> {
	forgetBucketAddresses();
	const bucket = await getBucketStore().create({
		_id: `${name}-${nanoid()
			.toLowerCase()
			.replace(/[^a-z0-9]/g, '')}`,
		name: `${name} people`,
		slug: name,
		ownerGroupId: fields.ownerGroupId ?? UNASSIGNED_GROUP_ID,
		...(fields.registrationOpen ? { registrationOpen: true } : {})
	});
	return {
		id: bucket._id,
		slug: name,
		staff: await group(bucket._id, 'Staff'),
		admins: await group(bucket._id, 'Admins')
	};
}

export async function group(
	bucketId: string,
	displayName: string,
	memberIds: string[] = []
): Promise<string> {
	const created = await getBucketGroupStore().create(
		{ _id: nanoid(), bucketId, displayName },
		memberIds
	);
	return created._id;
}

/* A person who signs in with a password, in the given groups of the project. */
export async function member(
	of: Project,
	groups: readonly string[] = []
): Promise<Member> {
	const created = await person(of.id);
	for (const groupId of groups) {
		await getBucketGroupStore().change(groupId, {
			add: [created.accountId],
			remove: []
		});
	}
	return created;
}

/*
 * The projects, people and groups the area's specs share. Seeded in a spec's `beforeAll`, after `bootstrap`,
 * because a config declares settings and clients only.
 */
export async function world(): Promise<World> {
	await ensureAdminSeed();
	const cookie = await adminCookie();
	const acme = await project('acme');
	const beta = await project('beta');
	const open = await project('open', { registrationOpen: true });
	return {
		cookie,
		acme: {
			...acme,
			staffMember: await member(acme, [acme.staff]),
			adminMember: await member(acme, [acme.admins]),
			outsider: await member(acme)
		},
		beta: { ...beta, staffMember: await member(beta, [beta.staff]) },
		open: { ...open, staffMember: await member(open, [open.staff]) }
	};
}

export async function scheduleDeletion(bucketId: string): Promise<void> {
	const scheduledAt = new Date();
	await getBucketStore().scheduleDeletion(bucketId, {
		scheduledAt,
		purgeAt: new Date(scheduledAt.getTime() + 30 * 86_400_000),
		scheduledBy: { userId: 'an-administrator' }
	});
	forgetBucketAddresses();
}

/* --- the administrative routes ------------------------------------------------------------------------------ */

export type WhoBody =
	| { kind: 'groups'; groups: string[] }
	| { kind: 'project' }
	| { kind: 'public'; subtree: boolean }
	| { kind: 'none' };

export interface RuleBody {
	path: string;
	who: WhoBody;
}

export const AppView = Type.Object({
	id: Type.String(),
	name: Type.String(),
	address: Type.String(),
	proxyKind: Type.String(),
	rules: Type.Array(Type.Object({ path: Type.String(), who: Type.Unknown() })),
	verifyUrl: Type.String()
});
export type AppView = Static<typeof AppView>;

export function behindProxyPath(bucketId: string, appId?: string): string {
	const base = `/admin/api/projects/${bucketId}/behind-proxy`;
	return appId === undefined ? base : `${base}/${appId}`;
}

/* Fails with what the route answered, so a missing route reads as one rather than as a later undefined. */
export function expectStatus(reply: Reply, status: number, what: string) {
	if (reply.status !== status) {
		throw new Error(
			`${what}: expected ${String(status)}, got ${String(reply.status)} ${JSON.stringify(reply.body).slice(0, 300)}`
		);
	}
}

let addresses = 0;

/* An address no other app of the file uses, so cases never meet each other's apps. */
export function freshAddress(): string {
	addresses += 1;
	return `https://app${String(addresses)}.example.com`;
}

export async function createApp(
	cookie: string,
	bucketId: string,
	fields: {
		rootGroups: string[];
		address?: string;
		name?: string;
		proxyKind?: 'caddy' | 'traefik' | 'nginx';
	}
): Promise<AppView> {
	const reply = await admin('POST', behindProxyPath(bucketId), cookie, {
		name: fields.name ?? 'Dashboards',
		address: fields.address ?? freshAddress(),
		proxyKind: fields.proxyKind ?? 'caddy',
		rootGroups: fields.rootGroups
	});
	expectStatus(reply, 201, 'creating an app behind the proxy');
	return shaped(AppView, reply.body);
}

export async function setRules(
	cookie: string,
	bucketId: string,
	appId: string,
	rules: RuleBody[]
): Promise<AppView> {
	const reply = await admin('PATCH', behindProxyPath(bucketId, appId), cookie, {
		rules
	});
	expectStatus(reply, 200, 'changing the rules of an app behind the proxy');
	return shaped(AppView, reply.body);
}

export async function readApp(
	cookie: string,
	bucketId: string,
	appId: string
): Promise<AppView> {
	const reply = await admin('GET', behindProxyPath(bucketId, appId), cookie);
	expectStatus(reply, 200, 'reading an app behind the proxy');
	return shaped(AppView, reply.body);
}

/* --- the check, as a proxy sends it ------------------------------------------------------------------------- */

export const FORWARDED = [
	'X-Forwarded-Host',
	'X-Forwarded-Uri',
	'X-Forwarded-Method'
] as const;
export type Forwarded = (typeof FORWARDED)[number];

export const NAVIGATION = 'text/html,application/xhtml+xml,*/*;q=0.8';

export function sessionCookieName(appId: string): string {
	return `__Host-foxauth-${appId}`;
}

export function markerCookieName(appId: string): string {
	return `__Host-foxauth-signin-${appId}`;
}

/* Where a proxy sends the check: the project's own address, then the app's id. */
export function verifyUrl(
	slug: string,
	appId: string,
	mode?: 'status'
): string {
	return `${ISSUER}/${slug}/verify/${appId}${mode ? '?mode=status' : ''}`;
}

export interface Check {
	slug: string;
	appId: string;
	/* The host the browser asked for, as the proxy reports it. */
	host: string;
	/* The original path and query. */
	uri?: string;
	method?: string;
	cookie?: string;
	accept?: string;
	mode?: 'status';
	/* Headers a proxy that is wired wrong would leave out. */
	omit?: readonly Forwarded[];
	headers?: Record<string, string>;
}

export function hostOf(address: string): string {
	return new URL(address).host;
}

export function check(input: Check): Promise<Response> {
	const forwarded: Record<Forwarded, string> = {
		'X-Forwarded-Host': input.host,
		'X-Forwarded-Uri': input.uri ?? '/',
		'X-Forwarded-Method': input.method ?? 'GET'
	};
	const headers = new Headers(input.headers);
	for (const name of FORWARDED) {
		if (!input.omit?.includes(name)) headers.set(name, forwarded[name]);
	}
	headers.set('X-Forwarded-Proto', 'https');
	headers.set('Accept', input.accept ?? NAVIGATION);
	if (input.cookie) headers.set('Cookie', input.cookie);
	return elysia.handle(
		new Request(verifyUrl(input.slug, input.appId, input.mode), {
			method: 'GET',
			headers,
			redirect: 'manual'
		})
	);
}

/* The check for one app, at its own address. */
export function checkApp(
	target: { slug: string; app: Pick<AppView, 'id' | 'address'> },
	input: Omit<Check, 'slug' | 'appId' | 'host'> & { host?: string } = {}
): Promise<Response> {
	return check({
		slug: target.slug,
		appId: target.app.id,
		host: input.host ?? hostOf(target.app.address),
		...input
	});
}

/* An answer, whole, so two can be compared byte for byte. */
export async function answerOf(response: Response): Promise<{
	status: number;
	headers: [string, string][];
	body: string;
}> {
	return {
		status: response.status,
		headers: [...response.headers.entries()].sort(([a], [b]) =>
			a.localeCompare(b)
		),
		body: await response.text()
	};
}

/* The cookies the browser keeps for the app's host — never sent to FoxAuth's own. */
export class AppJar {
	#cookies = new Map<string, string>();

	absorb(response: Response): Response {
		for (const raw of response.headers.getSetCookie()) {
			const [pair] = raw.split(';');
			const at = pair.indexOf('=');
			const name = pair.slice(0, at);
			const value = pair.slice(at + 1);
			if (!value || /max-age=0/i.test(raw) || raw.includes('1970')) {
				this.#cookies.delete(name);
			} else {
				this.#cookies.set(name, value);
			}
		}
		return response;
	}

	get(name: string): string | undefined {
		return this.#cookies.get(name);
	}

	get header(): string {
		return [...this.#cookies].map(([k, v]) => `${k}=${v}`).join('; ');
	}
}

export interface SignedIn {
	/* `__Host-foxauth-<appId>=<value>`, as the browser sends it. */
	cookie: string;
	/* Where the completed sign-in sent the browser. */
	landedAt: string;
	jar: AppJar;
	/* The browser at FoxAuth's own address, holding the project session. */
	browser: Browser;
}

export interface AtCallback {
	/* The address on the app's host the project sent the browser back to, code and state in its query. */
	callback: URL;
	jar: AppJar;
	/* The browser at FoxAuth's own address, holding the project session. */
	browser: Browser;
}

/*
 * A person opens the app and signs in, as their browser and the proxy would carry it, up to the point where the
 * project sends the browser back to `/_foxauth/callback` on the app's host: the navigation is sent to the
 * project's sign-in, and the login form is answered unless the browser is already signed in to the project.
 */
export async function reachCallback(
	target: { slug: string; app: Pick<AppView, 'id' | 'address'> },
	who: Pick<Member, 'email'>,
	options: { from?: string; browser?: Browser; jar?: AppJar } = {}
): Promise<AtCallback> {
	const jar = options.jar ?? new AppJar();
	const browser = options.browser ?? new Browser();
	const started = jar.absorb(
		await checkApp(target, { uri: options.from ?? '/', cookie: jar.header })
	);
	if (started.status !== 302) {
		throw new Error(
			`a navigation with no session should be sent to sign-in, got ${String(started.status)}`
		);
	}
	const toSignIn = present(started.headers.get('location'), 'a sign-in');

	let step = await browser.open(toSignIn);
	if (/\/ui\/[^/]+\/login$/.test(step.url)) {
		const posted = await browser.post(step.url, {
			username: who.email,
			password: PASSWORD
		});
		const resume = present(
			posted.headers.get('location'),
			'a redirect after the login'
		);
		step = await browser.open(new URL(resume, step.url).toString());
	}

	const back = new URL(step.url);
	const app = new URL(target.app.address);
	if (back.origin !== app.origin || back.pathname !== '/_foxauth/callback') {
		throw new Error(
			`the sign-in should return to the app's callback, got ${step.url} (${String(step.response.status)})`
		);
	}
	return { callback: back, jar, browser };
}

/* The callback relayed to the check, as the proxy relays it, with whatever cookies `cookie` says the browser holds. */
export function relayCallback(
	target: { slug: string; app: Pick<AppView, 'id' | 'address'> },
	callback: URL,
	cookie: string
): Promise<Response> {
	return checkApp(target, {
		uri: `${callback.pathname}${callback.search}`,
		cookie
	});
}

/* The whole sign-in, through the callback; answers the app session cookie. */
export async function signInThrough(
	target: { slug: string; app: Pick<AppView, 'id' | 'address'> },
	who: Pick<Member, 'email'>,
	options: { from?: string; browser?: Browser; jar?: AppJar } = {}
): Promise<SignedIn> {
	const { callback, jar, browser } = await reachCallback(target, who, options);
	const completed = jar.absorb(
		await relayCallback(target, callback, jar.header)
	);
	if (completed.status !== 302) {
		throw new Error(
			`the callback should complete the sign-in, got ${String(completed.status)} ${await completed.text()}`
		);
	}
	const value = present(
		jar.get(sessionCookieName(target.app.id)),
		'the app session cookie'
	);
	return {
		cookie: `${sessionCookieName(target.app.id)}=${value}`,
		landedAt: present(completed.headers.get('location'), 'a landing'),
		jar,
		browser
	};
}

/* --- an agent ----------------------------------------------------------------------------------------------- */

/* An access token for the administrative MCP endpoint, acting for `user`, with the session initialised. */
export async function agentFor(user: User): Promise<string> {
	const at = new AccessToken({
		client: await Client.find(ADMIN_MCP_CLIENT_ID),
		accountId: user._id,
		scope: 'openid'
	});
	at.setAudience(MCP_RESOURCE);
	const token = await at.save();
	await rpc(
		{
			jsonrpc: '2.0',
			id: 0,
			method: 'initialize',
			params: {
				protocolVersion: '2026-07-28',
				capabilities: {},
				clientInfo: { name: 'test-agent', version: '1.0.0' }
			}
		},
		token
	);
	return token;
}

export function tool(
	token: string,
	name: string,
	args: Record<string, unknown>
): Promise<McpMessage> {
	return rpc(call(name, args), token);
}

/* The second call of the two a high-consequence tool takes, carrying what the first handed out. */
export async function confirm(
	token: string,
	name: string,
	args: Record<string, unknown>,
	described: McpMessage
): Promise<McpMessage> {
	const confirmationToken = present(
		described.result?.structuredContent?.confirmationToken,
		`a confirmation asked for by ${name}`
	);
	return tool(token, name, { ...args, confirmationToken });
}

/*
 * An administrator who may edit a project and is not a super administrator: the project belongs to their own
 * group, as one they created would.
 */
export async function editor(): Promise<{
	user: User;
	cookie: string;
	project: Project;
}> {
	await ensureAdminSeed();
	const user = await createAdministrator('plain');
	const cookie = await cookieFor(user);
	const owned = await project(
		`ed${nanoid()
			.toLowerCase()
			.replace(/[^a-z0-9]/g, '')
			.slice(0, 8)}`,
		{
			ownerGroupId: await groupIdFor(user)
		}
	);
	return { user, cookie, project: owned };
}
