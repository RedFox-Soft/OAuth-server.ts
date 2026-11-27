import { Elysia, t } from 'elysia';
import crypto from 'node:crypto';
import { configuration } from '../../configs/application.js';
import { ISSUER } from '../../configs/env.js';
import {
	getBucketStore,
	getUserStore,
	adminSessionStore
} from '../../adapters/index.js';
import {
	createAdminSession,
	sessionCookieAttributes,
	expiredSessionCookieAttributes
} from './session.js';
import {
	IdTokenRejected,
	verifyAdminIdToken,
	type VerifiedAdminIdToken
} from './verifyIdToken.js';
import { meets } from '../../helpers/acr_satisfaction.ts';
import epochTime from '../../helpers/epoch_time.js';
import { errorForCode } from '../../helpers/errors.js';
import { eventBus } from '../../event_bus.js';
import { routeNames, sessionCookieName } from '../../consts/param_list.js';
import { Session } from '../../models/session.js';
import { expiredSessionCookie } from '../../shared/session.js';
import { ADMIN_REQUEST_BUCKET } from '../../configs/issuer.js';
import { destroyProviderSession } from '../../shared/destroy_session.js';
import {
	ADMIN_CLIENT_ID,
	ADMIN_BUCKET_ID,
	ADMIN_SESSION_COOKIE
} from '../consts.js';
import { safeNext } from './next.js';
import { canSignIn } from '../../end_users/can_sign_in.js';
import { CREATE_PROMPT } from '../../consts/prompt_create.js';
import { followLink } from '../../totp/self_service.js';
import { prepareAdd, prepareRemove } from '../../passkeys/account.js';
import { adminConsoleHolder } from '../me_passkeys.js';

const REDIRECT_URI = `${ISSUER}/admin/callback`;

function base64url(buf: Buffer) {
	return buf.toString('base64url');
}

/*
 * What the provider session the authorization just used records about the sign-in (specs/080, specs/144): which
 * provider it came through (or null for a password/passkey sign-in), the reached authentication context, the methods,
 * and the sign-in timestamp. Reading from the provider session captures `phishing_resistant` even when the console did
 * not ask for `phr` yet (Spec 142 Rule B), so a super administrator who signs in with a passkey can then turn on the
 * console passkey requirement in that very session.
 */
async function providerSignInInfo(
	cookie: Record<string, { value: unknown }>
): Promise<{
	signedInWith: string | null;
	signInAcr: string | null;
	signInAmr: string[] | undefined;
	signInAt: number | undefined;
} | null> {
	const id = cookie[sessionCookieName(ADMIN_REQUEST_BUCKET)].value;
	if (typeof id !== 'string' || !id) return null;
	const session = await Session.tryFind(id);
	if (!session) return null;
	return {
		signedInWith: session.payload.upstream?.providerId ?? null,
		signInAcr:
			typeof session.payload.acr === 'string' ? session.payload.acr : null,
		signInAmr: Array.isArray(session.payload.amr)
			? [...session.payload.amr]
			: undefined,
		signInAt:
			typeof session.payload.loginTs === 'number'
				? session.payload.loginTs
				: undefined
	};
}

type StartContext = {
	cookie: Record<
		string,
		{ set: (attributes: Record<string, unknown>) => void }
	>;
	query: { next?: string; reauth?: string };
	redirect: (url: string, status: 302) => Response;
};

/*
 * Starts the console's sign-in leg. `create` asks the sign-in page to open on account creation
 * (`prompt=create`): the address a "create an account" link points at, so a newcomer is not shown a
 * password form for an account they do not have. When the administrators' project requires a passkey for
 * console sign-in (specs/144), `acr_values` requests the phishing-resistant context so the sign-in runs
 * the passkey ceremony and the ID token reports it; `reauth=1` forces a fresh sign-in (`prompt=login`).
 */
async function startSignIn(
	{ cookie, query, redirect }: StartContext,
	create: boolean
): Promise<Response> {
	const verifier = base64url(crypto.randomBytes(32));
	const challenge = base64url(
		crypto.createHash('sha256').update(verifier).digest()
	);
	const state = base64url(crypto.randomBytes(16));
	// Freshness, not CSRF: `state` binds the callback to the browser that started the
	// flow, `nonce` binds the identity token to this attempt — so a genuine token
	// captured from another sign-in cannot be replayed into this one.
	const nonce = base64url(crypto.randomBytes(32));
	cookie.admin_oauth.set({
		// Where to return after sign-in, validated here and again on the way out: the cookie is the
		// browser's to keep, so its contents are not trusted just because this route wrote them.
		value: JSON.stringify({
			verifier,
			state,
			nonce,
			next: safeNext(query.next)
		}),
		httpOnly: true,
		sameSite: 'lax',
		secure: true,
		path: '/admin',
		maxAge: 600
	});
	const adminBucket = await getBucketStore().find(ADMIN_BUCKET_ID);
	const requirePasskey = adminBucket?.consolePasskeyRequired === true;
	const reauth = query.reauth === '1' || query.reauth === 'true';
	const prompt = create ? CREATE_PROMPT : reauth ? 'login' : undefined;
	const url = new URL(`${ISSUER}${routeNames.authorization}`);
	url.search = new URLSearchParams({
		client_id: ADMIN_CLIENT_ID,
		response_type: 'code',
		redirect_uri: REDIRECT_URI,
		scope: 'openid',
		state,
		nonce,
		code_challenge: challenge,
		code_challenge_method: 'S256',
		...(prompt ? { prompt } : {}),
		...(requirePasskey
			? { acr_values: configuration.acrMap.phishing_resistant }
			: {})
	}).toString();
	return redirect(url.toString(), 302);
}

export const adminLogin = new Elysia({ name: 'admin-login' })
	.get('/admin/login', (context) => startSignIn(context, false))
	.get('/admin/signup', (context) => startSignIn(context, true))
	/*
	 * Follows the emailed confirmation link for adding or removing an administrator's own passkey after a fresh
	 * password sign-in (specs/144 contracts/admin-api.md §1). Bound to this browser's `_admin_session`, so a mail
	 * scanner prefetching the URL has no matching session and never consumes the single-use link.
	 */
	.get(
		'/admin/me/passkeys/confirm',
		async ({ query, cookie, redirect }) => {
			const sessionId = cookie[ADMIN_SESSION_COOKIE].value as
				string | undefined;
			if (!sessionId) {
				return redirect('/admin?account=passkeys&linkError=expired', 302);
			}
			const session = await adminSessionStore.find(sessionId);
			if (!session) {
				return redirect('/admin?account=passkeys&linkError=expired', 302);
			}
			const [user, bucket] = await Promise.all([
				getUserStore(ADMIN_BUCKET_ID).find(session.userId),
				getBucketStore().find(ADMIN_BUCKET_ID)
			]);
			if (!user || !canSignIn(user) || !bucket) {
				return redirect('/admin?account=passkeys&linkError=expired', 302);
			}
			const holder = adminConsoleHolder(session._id);
			const link = await followLink(
				query.token ?? '',
				holder,
				user._id,
				ADMIN_BUCKET_ID
			);
			if (!link) {
				return redirect('/admin?account=passkeys&linkError=expired', 302);
			}
			if (link.purpose === 'passkey_add') {
				await prepareAdd(
					bucket,
					user,
					{ uid: session._id, holder },
					'password_mail'
				);
				return redirect('/admin?account=passkeys&confirmed=add', 302);
			}
			if (link.purpose === 'passkey_remove' && link.passkeyId) {
				await prepareRemove(
					bucket,
					user,
					{ uid: session._id, holder },
					link.passkeyId
				);
				return redirect(
					`/admin?account=passkeys&confirmed=remove&passkey=${encodeURIComponent(link.passkeyId)}`,
					302
				);
			}
			return redirect('/admin?account=passkeys&linkError=expired', 302);
		},
		{ query: t.Object({ token: t.Optional(t.String()) }) }
	)
	.get(
		'/admin/callback',
		async ({ query, cookie, redirect, set }) => {
			// Elysia auto-parses JSON-looking cookie values into objects on read,
			// so the stored `{ verifier, state, nonce }` may arrive already deserialised.
			const rawSaved = cookie.admin_oauth.value;
			const saved =
				rawSaved === undefined || rawSaved === null || rawSaved === ''
					? null
					: ((typeof rawSaved === 'string'
							? JSON.parse(rawSaved)
							: rawSaved) as {
							verifier: string;
							state: string;
							nonce: string;
							next?: string;
						});
			cookie.admin_oauth.remove();
			if (!saved || saved.state !== query.state) {
				set.status = 400;
				return { error: 'invalid_state', message: 'state mismatch' };
			}
			/*
			 * A refused sign-in comes back here with `error` and no `code` (RFC 6749 §4.1.2.1). Shown on the shared
			 * error page by its own code, and only after the state check: before it, the text is whoever wrote the
			 * link's, on a page of this console.
			 */
			if (query.error !== undefined || query.code === undefined) {
				throw errorForCode(
					query.error ?? 'invalid_request',
					query.error === undefined
						? 'the authorization response carries neither a code nor an error'
						: query.error_description
				);
			}
			const res = await fetch(`${ISSUER}${routeNames.token}`, {
				method: 'POST',
				headers: { 'content-type': 'application/x-www-form-urlencoded' },
				body: new URLSearchParams({
					grant_type: 'authorization_code',
					code: query.code,
					redirect_uri: REDIRECT_URI,
					client_id: ADMIN_CLIENT_ID,
					code_verifier: saved.verifier
				})
			});
			if (!res.ok) {
				set.status = 401;
				return { error: 'token_exchange_failed', message: 'login failed' };
			}
			const tokens = (await res.json()) as {
				access_token: string;
				id_token?: string;
				refresh_token?: string;
			};

			let verified: VerifiedAdminIdToken;
			try {
				verified = await verifyAdminIdToken(tokens.id_token, {
					nonce: saved.nonce
				});
			} catch (err) {
				// One response for every cause: which check failed is not something a caller
				// gets to probe for. The reason goes to the event bus instead, where a
				// deployment can subscribe to it — and not to the console, because this route
				// is unauthenticated and an attacker-triggerable log write is a vector of its
				// own.
				eventBus.emit('admin.login.error', {
					reason: err instanceof IdTokenRejected ? err.reason : 'unverifiable'
				});
				set.status = 401;
				return { error: 'invalid_id_token', message: 'login failed' };
			}

			/*
			 * Defense in depth (specs/144 FR-017): even if `acr_values` were stripped from the authorization request,
			 * the callback checks the verified ID token's `acr` directly and refuses with the same constant-shape 401.
			 */
			const adminBucket = await getBucketStore().find(ADMIN_BUCKET_ID);
			if (
				adminBucket?.consolePasskeyRequired === true &&
				!meets(verified.acr, 'phishing_resistant')
			) {
				eventBus.emit('admin.login.error', { reason: 'acr' });
				set.status = 401;
				return { error: 'invalid_id_token', message: 'login failed' };
			}

			const user = await getUserStore(ADMIN_BUCKET_ID).find(verified.sub);
			// The same predicate as every sign-in door, so a locally locked administrator is refused here too.
			if (!user || !canSignIn(user)) {
				set.status = 403;
				return { error: 'not_admin', message: 'no admin account' };
			}
			const providerInfo = await providerSignInInfo(cookie);
			const session = await createAdminSession({
				userId: user._id,
				bucketId: ADMIN_BUCKET_ID,
				signedInWith: providerInfo?.signedInWith ?? null,
				signInAcr: providerInfo?.signInAcr ?? verified.acr,
				signInAmr: providerInfo?.signInAmr ?? verified.amr,
				signInAt: providerInfo?.signInAt ?? verified.authTime ?? epochTime(),
				tokens: {
					accessToken: tokens.access_token,
					idToken: tokens.id_token,
					refreshToken: tokens.refresh_token
				}
			});
			cookie[ADMIN_SESSION_COOKIE].set({
				value: session._id,
				...sessionCookieAttributes()
			});
			return redirect(safeNext(saved.next), 302);
		},
		{
			// The provider appends `iss` (RFC 9207 authorization-response issuer
			// identifier) to the redirect; the app runs with `normalize: false`, so a
			// strict { code, state } schema would 422 on the extra param. Accept it.
			// `code` is optional because a refusal carries `error` in its place.
			query: t.Object({
				code: t.Optional(t.String()),
				error: t.Optional(t.String()),
				error_description: t.Optional(t.String()),
				state: t.String(),
				iss: t.Optional(t.String())
			})
		}
	)
	/*
	 * Signing out of the console ends *both* sessions, server-side, in this one request.
	 *
	 * Destroying only the console's own session row left the provider session — a separate cookie,
	 * at a separate path — still carrying `accountId`. The console is a relying party on its own
	 * issuer, and the admin client is registered with consent not required, so the next visit to
	 * `/admin/login` sailed through `/auth` with no interaction and minted a fresh console session.
	 * Logout looked like it worked and changed nothing.
	 *
	 * Ending the provider session here rather than redirecting the browser through the RP-initiated
	 * `/logout` endpoint keeps sign-out working when an operator turns `rpInitiatedLogout.enabled`
	 * off, and spares the operator a confirmation interstitial on a button they already clicked.
	 * What it costs is now bounded, and used to not be. A provider session belongs to one user bucket,
	 * so this ends the administrators bucket's sign-in and the relying parties that had an SSO session
	 * *in that bucket* — which, on a normal deployment, is the console and nothing else. Before the
	 * session cookie carried its bucket, there was one session per browser and leaving the console
	 * signed an administrator out of every unrelated application they were using.
	 *
	 * Both cookies are cleared unconditionally, even when their store row has already gone, so a
	 * stale browser cookie can never outlive the record it points at.
	 */
	.post('/admin/api/logout', async ({ cookie }) => {
		const id = cookie[ADMIN_SESSION_COOKIE].value as string | undefined;
		if (id) await adminSessionStore.destroy(id);
		cookie[ADMIN_SESSION_COOKIE].set(expiredSessionCookieAttributes());

		/*
		 * The administrators bucket's sign-in, and only it. The console is a relying party on this
		 * server, so signing out of the console ends the provider session behind it — but that session
		 * belongs to one population, and ending every sign-in the browser holds would sign an
		 * administrator out of unrelated applications as a side effect of leaving the console.
		 */
		const adminBucketCookie = sessionCookieName(ADMIN_REQUEST_BUCKET);
		const providerSessionId = cookie[adminBucketCookie].value;
		if (typeof providerSessionId === 'string' && providerSessionId) {
			const session = await Session.tryFind(providerSessionId);
			if (session) await destroyProviderSession(session);
		}
		cookie[adminBucketCookie].set(expiredSessionCookie());

		return { ok: true };
	});
