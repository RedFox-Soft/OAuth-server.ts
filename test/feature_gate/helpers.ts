import { expect } from 'bun:test';

import { elysia } from '../../lib/index.ts';
import { ISSUER } from 'lib/configs/env.js';

// A path the server deliberately does not serve. Every off-state assertion compares against a live
// request to this path rather than a hard-coded body, so the eventual not-found-body cleanup
// (backlog task 14) cannot silently break these specs.
export const UNSERVED_PATH = '/_not_a_mounted_route';

export interface ProbeInit {
	readonly method: string;
	readonly headers?: Record<string, string>;
	readonly body?: string;
}

function request(path: string, init: ProbeInit): Request {
	return new Request(`${ISSUER}${path}`, {
		method: init.method,
		headers: init.headers,
		body: init.body
	});
}

export function send(path: string, init: ProbeInit): Promise<Response> {
	return elysia.handle(request(path, init));
}

function headerMap(res: Response): Record<string, string> {
	const out: Record<string, string> = {};
	for (const [name, value] of res.headers) {
		// Set by the HTTP layer per response, never equal between two calls, and invisible to the
		// question this helper answers.
		if (name === 'date') {
			continue;
		}
		out[name] = value;
	}
	return out;
}

export interface Equivalence {
	readonly status: number;
	readonly body: string;
	readonly headers: Record<string, string>;
}

async function snapshot(res: Response): Promise<Equivalence> {
	return {
		status: res.status,
		body: await res.text(),
		headers: headerMap(res)
	};
}

/*
 * The core off-state assertion: a request to a gated path while its capability is off must be
 * indistinguishable from the same shape of request to a path that is not served at all — status,
 * body and headers alike. Headers are included deliberately: the server sets `Cache-Control:
 * no-store` on every response from a global hook, and a gate that preempted that hook would leave a
 * one-header fingerprint distinguishing "disabled" from "absent".
 */
export async function expectUnservedEquivalent(
	path: string,
	init: ProbeInit
): Promise<Equivalence> {
	const gated = await snapshot(await send(path, init));
	const unserved = await snapshot(await send(UNSERVED_PATH, init));

	expect(gated.status).toBe(404);
	expect(gated).toEqual(unserved);

	return gated;
}
