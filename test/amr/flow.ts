import { expect } from 'bun:test';
import { elysia } from 'lib/index.ts';
import {
	getBucketStore,
	getProjectStore,
	getUserStore
} from 'lib/adapters/index.ts';
import { UNASSIGNED_GROUP_ID } from 'lib/admin/consts.ts';
import { decode as decodeJWT } from 'lib/helpers/jwt.ts';
import { isPlainObject } from 'lib/helpers/_/object.js';
import { encodeBase32, decodeBase32 } from 'lib/totp/base32.ts';
import { hotp, stepFor } from 'lib/totp/code.ts';
import epochTime from 'lib/helpers/epoch_time.ts';
import { AuthorizationRequest } from '../AuthorizationRequest.ts';
import { present } from 'test/shape.ts';
import { idTokenOf } from '../acr/response.ts';

export const PASSWORD = 'correct horse battery';
export const SECRET = encodeBase32(
	Buffer.from('12345678901234567890', 'ascii')
);

const form = { 'content-type': 'application/x-www-form-urlencoded' };

export function codeFor(secret = SECRET): string {
	return hotp(decodeBase32(secret), stepFor(epochTime()));
}

/* A bucket, and a project that routes the named clients' sign-ins to it. */
export async function seedBucket(
	name: string,
	clientIds: string[],
	fields: Record<string, unknown> = {}
): Promise<string> {
	const bucket = await getBucketStore().create({
		ownerGroupId: UNASSIGNED_GROUP_ID,
		name,
		...fields
	});
	const project = await getProjectStore().create({
		ownerGroupId: UNASSIGNED_GROUP_ID,
		name,
		slug: `${clientIds[0]}-${Math.random()}`
	});
	await getProjectStore().update(project._id, {
		bucketId: bucket._id,
		clientIds
	});
	return bucket._id;
}

/* An account, optionally holding an authenticator already. */
export async function seedUser(
	bucketId: string,
	{ enrolled = false }: { enrolled?: boolean } = {}
): Promise<string> {
	const email = `amr-${Math.random()}@x.io`;
	const user = await getUserStore(bucketId).create(
		email,
		await Bun.password.hash(PASSWORD),
		true
	);
	if (enrolled) {
		await getUserStore(bucketId).update(user._id, {
			totp: { secret: SECRET, enrolledAt: new Date(), lastStep: 0 }
		});
	}
	return email;
}

/*
 * A browser: it keeps the cookies it is given and sends them all back, so a second request rides
 * the session the first established.
 */
export class Browser {
	#jar = new Map<string, string>();

	#absorb(response: Response) {
		for (const set of response.headers.getSetCookie()) {
			const [pair] = set.split(';');
			const at = pair.indexOf('=');
			this.#jar.set(pair.slice(0, at), pair.slice(at + 1));
		}
		return response;
	}

	get cookie() {
		return [...this.#jar].map(([k, v]) => `${k}=${v}`).join('; ');
	}

	async request(path: string, init: RequestInit = {}) {
		return this.#absorb(
			await elysia.handle(
				new Request(`http://e.ly${path}`, {
					redirect: 'manual',
					...init,
					// Built rather than spread: a Headers instance spreads as an empty object.
					headers: withCookie(init.headers, this.cookie)
				})
			)
		);
	}

	post(path: string, fields: Record<string, string>) {
		return this.request(path, {
			method: 'POST',
			headers: form,
			body: new URLSearchParams(fields)
		});
	}

	async authorize(auth: AuthorizationRequest) {
		return this.#absorb(
			await auth.authorize({ headers: { cookie: this.cookie } })
		);
	}
}

export function uidOf(location: string | null): string {
	const uid = location?.split('/')[2];
	if (!uid) throw new Error(`expected an interaction, got ${String(location)}`);
	return uid;
}

export function codeOf(location: string | null): string {
	expect(location ?? '').toContain('/callback');
	return present(
		new URL(present(location, 'a redirect')).searchParams.get('code'),
		'an authorization code'
	);
}

/*
 * Sign in through the login form — and the code step when `second` is set — and answer the code
 * the client receives.
 */
export async function signIn(
	browser: Browser,
	auth: AuthorizationRequest,
	email: string,
	{ second = false }: { second?: boolean } = {}
): Promise<string> {
	const started = await browser.authorize(auth);
	const uid = uidOf(started.headers.get('location'));
	let res = await browser.post(`/ui/${uid}/login`, {
		username: email,
		password: PASSWORD
	});
	if (second) {
		res = await browser.post(`/ui/${uid}/totp`, { code: codeFor() });
	}
	return codeOf(res.headers.get('location'));
}

interface TokenResponse {
	data: unknown;
}

/* The `amr` an ID token carries, sorted — order has no meaning, so it is never asserted. */
export function amrOf(res: TokenResponse): string[] | undefined {
	const { amr } = decodeJWT(idTokenOf(res)).payload;
	if (amr === undefined) return undefined;
	if (!Array.isArray(amr)) throw new Error('expected amr to be an array');
	return amr.map(String).sort();
}

export function memberOf(res: TokenResponse, name: string): unknown {
	return isPlainObject(res.data) ? res.data[name] : undefined;
}

function withCookie(init: HeadersInit | undefined, cookie: string): Headers {
	const headers = new Headers(init);
	headers.set('cookie', cookie);
	return headers;
}
