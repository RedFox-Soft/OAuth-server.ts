import { spyOn } from 'bun:test';

import { agent, bindClientToBucket, getHeader } from '../test_helper.ts';
import { AuthorizationRequest } from '../AuthorizationRequest.ts';
import { fetchAnswering } from '../fetch_mock.ts';
import { elysia } from 'lib/index.ts';
import { ISSUER } from 'lib/configs/env.js';
import { ApplicationConfig } from 'lib/configs/application.js';
import { getBucketStore, getSmtpSettingsStore } from 'lib/adapters/index.ts';
import { UNASSIGNED_GROUP_ID } from 'lib/admin/consts.ts';
import { ATTACK_DESTINATION } from 'lib/consts/attack_report_fields.ts';
import { setClockForTests } from 'lib/telemetry/clock.ts';
import {
	attackReportPass,
	type AttackPassOutcome
} from 'lib/attack_reports/scheduler.ts';
import type { AttackReport } from 'lib/attack_reports/report.ts';
import { resetRateLimiter } from 'lib/plugins/rateLimit.js';
import {
	PEER_HEADER,
	statePeerThroughHeader
} from '../caller_address/helper.ts';

export { PEER_HEADER, statePeerThroughHeader };

/*
 * Reportable callers must be globally routable, so they come from 11.0.0.0/8 and 2a01:4f8::/32 rather than the
 * documentation ranges the other suites use, which are never reported. Nothing connects to them; they only
 * name the caller.
 */
let used = 0;
export function attacker(): string {
	used += 1;
	return `11.${(used >> 16) & 255}.${(used >> 8) & 255}.${used & 255}`;
}

export function attacker6(): string {
	used += 1;
	return `2a01:4f8:${used.toString(16)}:1::7`;
}

export function peerHeaders(peer: string): Record<string, string> {
	return { [PEER_HEADER]: peer };
}

/* A receiver standing in for FoxTrust's attack intake; anywhere else fails, as the network is never reached. */
export function attackReceiver(status = 204) {
	const state = { status, bodies: [] as unknown[], requests: 0 };
	spyOn(globalThis, 'fetch').mockImplementation(
		fetchAnswering(async (input, init) => {
			const url = input instanceof Request ? input.url : String(input);
			if (url !== ATTACK_DESTINATION) {
				throw new TypeError(`unexpected request to ${url}`);
			}
			state.requests += 1;
			state.bodies.push(
				JSON.parse(typeof init?.body === 'string' ? init.body : 'null')
			);
			return new Response(null, {
				status: state.status,
				...(state.status >= 300 && state.status < 400
					? { headers: { location: 'https://elsewhere.example/' } }
					: {})
			});
		})
	);
	return state;
}

/* A destination that never answers: the request ends only when its own signal aborts it. */
export function hangingAttackReceiver() {
	const state = { requests: 0 };
	spyOn(globalThis, 'fetch').mockImplementation(
		fetchAnswering(
			(_input, init) =>
				new Promise<Response>((_resolve, reject) => {
					state.requests += 1;
					init?.signal?.addEventListener('abort', () =>
						reject(new Error('aborted by its own signal'))
					);
				})
		)
	);
	return state;
}

const HOUR_MS = 60 * 60 * 1000;

/*
 * A process reports each hour once and its last reported hour only moves forward, so every case counts in an
 * hour of its own, later than any before it in the file.
 */
let hoursUsed = 0;
export function nextHour(): string {
	hoursUsed += 1;
	return new Date(
		Date.UTC(2026, 10, 2) + hoursUsed * 2 * HOUR_MS
	).toISOString();
}

/*
 * Counting happens on the reporting clock, held at the middle of `hourIso` so no case straddles an hour. The
 * process clock is left alone: interactions, tokens and the mail limit keep real time.
 */
export function inHour(hourIso: string): () => void {
	const at = new Date(new Date(hourIso).getTime() + HOUR_MS / 2);
	return setClockForTests(() => at);
}

/*
 * The pass that reports `hourIso`, five minutes into the next hour, past any instance's slot. Answers the
 * outcome and the report the sender was handed, or null when it was handed none.
 */
export async function closeHour(
	hourIso: string,
	send?: (report: AttackReport) => Promise<boolean>
): Promise<{ outcome: AttackPassOutcome; report: AttackReport | null }> {
	const at = new Date(new Date(hourIso).getTime() + HOUR_MS + 5 * 60 * 1000);
	let report: AttackReport | null = null;
	const undo = setClockForTests(() => at);
	try {
		const outcome = await attackReportPass(
			at,
			async (sent) => {
				report = sent;
				return send ? send(sent) : true;
			},
			{ ignoreSlot: true }
		);
		return { outcome, report };
	} finally {
		undo();
	}
}

/* The entry for `address` in `report`, or undefined. */
export function entryFor(report: AttackReport | null, address: string) {
	return report?.addresses.find((entry) => entry.address === address);
}

/* Every class's allowance set to `max` for one case; answers the undo. */
export function withRateLimit(max: number): () => void {
	const keys = [
		'rateLimit.strict.max',
		'rateLimit.ordinary.max',
		'rateLimit.public.max'
	] as const;
	const before = keys.map((key) => ApplicationConfig[key]);
	ApplicationConfig['rateLimit.enabled'] = true;
	for (const key of keys) ApplicationConfig[key] = max;
	resetRateLimiter();
	return () => {
		ApplicationConfig['rateLimit.enabled'] = false;
		keys.forEach((key, i) => {
			ApplicationConfig[key] = before[i];
		});
		resetRateLimiter();
	};
}

export function send(
	path: string,
	peer: string,
	init: {
		method?: string;
		headers?: Record<string, string>;
		body?: string;
	} = {}
): Promise<Response> {
	statePeerThroughHeader();
	return elysia.handle(
		new Request(`${ISSUER}${path}`, {
			method: init.method ?? 'GET',
			headers: { ...(init.headers ?? {}), ...peerHeaders(peer) },
			body: init.body
		})
	);
}

export const SIGN_IN_CLIENT = 'attack-app';
export const MACHINE_CLIENT = 'attack-machine';

let scimBase = '/scim/v2';

/*
 * A project people sign in to, with mail configured so reset requests and sign-ups are served, and a second
 * project with a path of its own, because only an addressed project serves SCIM.
 */
export async function signInProject(): Promise<string> {
	const slug = `attack${Math.random().toString(36).slice(2, 8)}`;
	await getBucketStore().create({
		ownerGroupId: UNASSIGNED_GROUP_ID,
		name: `SCIM ${slug}`,
		slug
	});
	scimBase = `/${slug}/scim/v2`;
	const bucket = await getBucketStore().create({
		ownerGroupId: UNASSIGNED_GROUP_ID,
		name: `Attack Bucket ${slug}`,
		emailVerificationRequired: true,
		verificationMethod: 'link'
	});
	await bindClientToBucket(SIGN_IN_CLIENT, bucket._id);
	await getSmtpSettingsStore().set({
		host: 'smtp.example.test',
		port: 587,
		secure: false,
		username: '',
		password: '',
		fromName: 'Accounts',
		fromEmail: 'accounts@example.test'
	});
	return bucket._id;
}

export async function startInteraction(peer: string) {
	const auth = new AuthorizationRequest({
		client_id: SIGN_IN_CLIENT,
		scope: 'openid'
	});
	statePeerThroughHeader();
	const { response } = await agent.auth.get({
		query: auth.params,
		headers: peerHeaders(peer)
	});
	const uid = getHeader(response, 'location').split('/')[2];
	const cookie = response.headers.get('set-cookie');
	if (!cookie) throw new Error('expected an interaction cookie from /auth');
	return { uid, cookie };
}

function form(fields: Record<string, string>): string {
	return new URLSearchParams(fields).toString();
}

const FORM = { 'content-type': 'application/x-www-form-urlencoded' };

export async function wrongPassword(
	peer: string,
	username = 'someone@x.io',
	password = 'not the password'
): Promise<Response> {
	const { uid, cookie } = await startInteraction(peer);
	return send(`/ui/${uid}/login`, peer, {
		method: 'POST',
		headers: { ...FORM, cookie },
		body: form({ username, password })
	});
}

export async function resetRequest(
	peer: string,
	email = 'reset@x.io'
): Promise<Response> {
	const { uid, cookie } = await startInteraction(peer);
	return send(`/ui/${uid}/forgot-password`, peer, {
		method: 'POST',
		headers: { ...FORM, cookie },
		body: form({ email })
	});
}

export function wrongClientSecret(
	peer: string,
	secret = 'a-wrong-secret'
): Promise<Response> {
	return send('/token', peer, {
		method: 'POST',
		headers: {
			...FORM,
			...AuthorizationRequest.basicAuthHeader(MACHINE_CLIENT, secret)
		},
		body: form({ grant_type: 'client_credentials', scope: 'api:read' })
	});
}

export function badScimToken(peer: string, token = 'guess'): Promise<Response> {
	return send(`${scimBase}/Users`, peer, {
		headers: { authorization: `Bearer ${token}` }
	});
}

export function scimWithoutCredential(peer: string): Promise<Response> {
	return send(`${scimBase}/Users`, peer);
}

export function badMcpToken(peer: string, token = 'guess'): Promise<Response> {
	return send('/mcp', peer, {
		method: 'POST',
		headers: {
			authorization: `Bearer ${token}`,
			'content-type': 'application/json',
			accept: 'application/json, text/event-stream'
		},
		body: JSON.stringify({
			jsonrpc: '2.0',
			id: 1,
			method: 'initialize',
			params: {
				protocolVersion: '2026-07-28',
				capabilities: {},
				clientInfo: { name: 'probe', version: '1.0.0' }
			}
		})
	});
}

export async function repeat(
	count: number,
	action: (i: number) => Promise<unknown>
): Promise<void> {
	for (let i = 0; i < count; i += 1) await action(i);
}
