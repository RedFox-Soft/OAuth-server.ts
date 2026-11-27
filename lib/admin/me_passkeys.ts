import { Elysia, t } from 'elysia';

import {
	getBucketStore,
	getPasskeyStore,
	getUserStore
} from '../adapters/index.js';
import type { Passkey, User, UserBucket } from '../adapters/types.js';
import { ISSUER } from '../configs/env.js';
import { meets } from '../helpers/acr_satisfaction.ts';
import epochTime from '../helpers/epoch_time.js';
import { mailDeliveryConfigured } from '../mail/mailer.js';
import {
	addAvailability,
	completeAdd,
	completeRemove,
	creationOptionsFor,
	isLastWayIn,
	liveAdd,
	liveRemove,
	ownPasskey,
	passkeyNameOf,
	passkeysOf,
	passkeyWorks,
	prepareAdd,
	renamePasskey,
	type AddProof,
	type PageSession
} from '../passkeys/account.js';
import { passkeysAccepted } from '../passkeys/accepted.js';
import { relyingPartyOf } from '../passkeys/relying_party.js';
import { passkeyView } from '../passkeys/ways_in.js';
import { FRESH_SECONDS } from '../totp/consts.js';
import { sendLink } from '../totp/self_service.js';
import { recordAdminAudit } from './audit/record.js';
import {
	AdminError,
	adminErrorBody,
	assertAuth,
	resolveAdmin,
	type AdminContext
} from './auth/rbac.js';
import { ADMIN_BUCKET_ID } from './consts.js';
import {
	assertConsoleStaysReachable,
	loadReachabilityState
} from './federation/reachability.js';

/*
 * Personal passkey management for any signed-in console administrator (specs/144 contracts/admin-api.md §1).
 *
 * Administrators have no `/account/security` page; their own passkeys live behind their authenticated console session
 * here and in the header account drawer. Excluded from the MCP surface because creating and confirming passkeys
 * requires an interactive browser WebAuthn ceremony bound to this console session.
 */

export const adminConsoleHolder = (sessionId: string): string =>
	`admin-console:${sessionId}`;

export type AdminFreshness = 'strong' | 'password' | 'any' | 'stale';

export function adminFreshnessOf(ctx: AdminContext): AdminFreshness {
	if (ctx.signInAt === null || epochTime() - ctx.signInAt > FRESH_SECONDS) {
		return 'stale';
	}
	const passkey =
		ctx.signInAmr.includes('pop') && ctx.signInAmr.includes('mfa');
	const code =
		ctx.signInAmr.includes('otp') && meets(ctx.signInAcr, 'multi_factor');
	if (passkey || code) return 'strong';
	if (ctx.signInAmr.includes('pwd')) return 'password';
	return 'any';
}

function strongAddProofOf(ctx: AdminContext): AddProof {
	return ctx.signInAmr.includes('pop') && ctx.signInAmr.includes('mfa')
		? 'passkey'
		: 'password_code';
}

function assertConsoleSession(ctx: AdminContext): PageSession {
	if (!ctx.sessionId || ctx.viaClientId) {
		throw new AdminError(
			403,
			'personal passkeys can only be managed from a console session'
		);
	}
	return { uid: ctx.sessionId, holder: adminConsoleHolder(ctx.sessionId) };
}

async function loadSelf(ctx: AdminContext): Promise<{
	bucket: UserBucket;
	user: User;
	session: PageSession;
}> {
	const session = assertConsoleSession(ctx);
	const [bucket, user] = await Promise.all([
		getBucketStore().find(ADMIN_BUCKET_ID),
		getUserStore(ADMIN_BUCKET_ID).find(ctx.userId)
	]);
	if (!bucket)
		throw new AdminError(500, "the administrators' project is missing");
	if (!user) throw new AdminError(404, 'no administrator account');
	return { bucket, user, session };
}

async function assertRemovingKeepsConsoleReachable(
	bucket: UserBucket,
	user: User,
	passkey: Passkey
): Promise<void> {
	if (!passkeyWorks(passkey, bucket)) return;
	const state = await loadReachabilityState();
	if (!state.superAdministrators.some((s) => s._id === user._id)) return;
	const nextCounts = new Map(state.superAdminPasskeyCounts);
	nextCounts.set(user._id, Math.max(0, (nextCounts.get(user._id) ?? 0) - 1));
	assertConsoleStaysReachable(
		{ ...state, superAdminPasskeyCounts: nextCounts },
		'Removing this passkey'
	);
}

function signalsFor(bucket: UserBucket, user: User, held: readonly Passkey[]) {
	if (!passkeysAccepted(bucket) || user.webauthnUserId === undefined) {
		return null;
	}
	const party = relyingPartyOf(bucket);
	return {
		rpId: party.rpId,
		userId: user.webauthnUserId,
		acceptedCredentialIds: held
			.filter((p) => p.rpId === party.rpId && p.copiedAt === undefined)
			.map((p) => p.credentialId),
		email: user.email,
		label: `${user.email} · ${party.name}`
	};
}

function availabilityMessage(
	availability: Awaited<ReturnType<typeof addAvailability>>
): string {
	switch (availability) {
		case 'not_accepted':
			return 'Passkeys are turned off for administrators.';
		case 'provider_only':
			return 'Accounts that sign in only through an identity provider cannot add a passkey.';
		case 'no_mail':
			return 'Mail delivery must be configured before you can add a passkey.';
		case 'unconfirmed':
			return 'Verify your email address before adding a passkey.';
		case 'full':
			return 'You already have the maximum of 20 passkeys.';
		case 'ready':
			return '';
	}
}

const AddPasskeyBody = t.Object({
	credential: t.String({ minLength: 1 }),
	name: t.Optional(t.String())
});

const RenamePasskeyBody = t.Object({
	name: t.String()
});

export const mePasskeyRoutes = new Elysia({ name: 'admin-me-passkeys' })
	.use(resolveAdmin)
	.onError(({ error, set }) => {
		if (error instanceof AdminError) {
			set.status = error.status;
			return adminErrorBody(error);
		}
	})
	.get('/admin/api/me/passkeys', async ({ admin }) => {
		const ctx = assertAuth(admin);
		const { bucket, user, session } = await loadSelf(ctx);
		const [held, mailReady, pendingAdd] = await Promise.all([
			passkeysOf(bucket, user),
			mailDeliveryConfigured(),
			liveAdd(user, bucket, session)
		]);
		const availability = await addAvailability(bucket, user, held.length);
		let liveRemoveId: string | null = null;
		for (const p of held) {
			if (await liveRemove(user, bucket, session, p._id)) {
				liveRemoveId = p._id;
				break;
			}
		}
		return {
			accepted: passkeysAccepted(bucket),
			passkeys: held.map((p) => passkeyView(p, bucket)),
			availability,
			freshness: adminFreshnessOf(ctx),
			verified: user.verified,
			mailReady,
			consolePasskeyRequired: bucket.consolePasskeyRequired === true,
			liveAdd: pendingAdd !== undefined,
			liveRemoveId,
			signals: signalsFor(bucket, user, held)
		};
	})
	.post('/admin/api/me/passkeys/add-link', async ({ admin, request, set }) => {
		const ctx = assertAuth(admin);
		const { bucket, user, session } = await loadSelf(ctx);
		const heldCount = await getPasskeyStore().countOf(bucket._id, user._id);
		const availability = await addAvailability(bucket, user, heldCount);
		if (availability !== 'ready') {
			throw new AdminError(409, availabilityMessage(availability));
		}
		const freshness = adminFreshnessOf(ctx);
		if (freshness === 'strong') {
			throw new AdminError(
				409,
				'Your recent sign-in is already strong enough; add a passkey directly.'
			);
		}
		if (freshness !== 'password') {
			throw new AdminError(
				409,
				'Sign in again with your password first, then request a confirmation link.'
			);
		}
		const sent = await sendLink(bucket, user, 'passkey_add', session.holder, {
			request,
			urlFor: (token) =>
				`${ISSUER}/admin/me/passkeys/confirm?token=${encodeURIComponent(token)}`
		});
		if (sent === 'throttled') {
			set.status = 429;
			return {
				error: 'rate_limited',
				message:
					'A confirmation link was sent recently. Check your inbox, or try again in a minute.'
			};
		}
		if (sent === 'mail_failed') {
			set.status = 502;
			return {
				error: 'delivery_failed',
				message: 'The confirmation email could not be sent. Try again later.'
			};
		}
		return { sent: true };
	})
	.post('/admin/api/me/passkeys/add/options', async ({ admin }) => {
		const ctx = assertAuth(admin);
		const { bucket, user, session } = await loadSelf(ctx);
		const heldCount = await getPasskeyStore().countOf(bucket._id, user._id);
		const availability = await addAvailability(bucket, user, heldCount);
		if (availability !== 'ready') {
			throw new AdminError(409, availabilityMessage(availability));
		}
		const freshness = adminFreshnessOf(ctx);
		let ceremony = await liveAdd(user, bucket, session);
		if (freshness === 'strong') {
			ceremony = await prepareAdd(bucket, user, session, strongAddProofOf(ctx));
		} else if (!ceremony) {
			throw new AdminError(
				409,
				freshness === 'password'
					? 'Confirm from the email link sent to your address before creating a passkey.'
					: 'Sign in again before adding a passkey.'
			);
		}
		const options = await creationOptionsFor(bucket, user, ceremony);
		if (!options) {
			throw new AdminError(
				409,
				'Could not prepare passkey creation. Try again.'
			);
		}
		return { options };
	})
	.post(
		'/admin/api/me/passkeys/add',
		async ({ admin, body, request, set }) => {
			const ctx = assertAuth(admin);
			const { bucket, user, session } = await loadSelf(ctx);
			let name: string | undefined;
			if (body.name !== undefined && body.name.trim() !== '') {
				name = passkeyNameOf(body.name);
				if (name === undefined) {
					throw new AdminError(
						422,
						'Passkey name must be 1 to 64 characters without control characters.',
						{ field: 'name' }
					);
				}
			}
			const stored = await completeAdd(
				bucket,
				user,
				session,
				body.credential,
				request,
				{
					name,
					audit: () => recordAdminAudit(ctx, 'admin.passkey.add', ctx.userId)
				}
			);
			if (!stored.ok) {
				const messages: Record<typeof stored.reason, string> = {
					expired: 'That passkey setup expired. Start again.',
					no_user_verification:
						'Your device did not verify it was you (fingerprint, face or PIN). Use a device with screen lock or PIN.',
					exists: 'That passkey is already registered on this account.',
					full: 'You already have the maximum of 20 passkeys.',
					unavailable: 'Passkeys cannot be added right now.',
					failed: 'Passkey registration failed. Try again.'
				};
				throw new AdminError(409, messages[stored.reason]);
			}
			set.status = 201;
			return { passkey: passkeyView(stored.passkey, bucket) };
		},
		{ body: AddPasskeyBody }
	)
	.patch(
		'/admin/api/me/passkeys/:passkeyId',
		async ({ admin, params, body }) => {
			const ctx = assertAuth(admin);
			const { bucket, user } = await loadSelf(ctx);
			if (adminFreshnessOf(ctx) === 'stale') {
				throw new AdminError(409, 'Sign in again to rename a passkey.');
			}
			const outcome = await renamePasskey(
				bucket,
				user,
				params.passkeyId,
				body.name
			);
			if (outcome === 'gone') throw new AdminError(404, 'passkey not found');
			if (outcome === 'invalid') {
				throw new AdminError(
					422,
					'Passkey name must be 1 to 64 characters without control characters.',
					{ field: 'name' }
				);
			}
			const updated = await ownPasskey(bucket, user, params.passkeyId);
			if (!updated) throw new AdminError(404, 'passkey not found');
			return { passkey: passkeyView(updated, bucket) };
		},
		{ body: RenamePasskeyBody }
	)
	.post(
		'/admin/api/me/passkeys/:passkeyId/remove-link',
		async ({ admin, params, request, set }) => {
			const ctx = assertAuth(admin);
			const { bucket, user, session } = await loadSelf(ctx);
			const passkey = await ownPasskey(bucket, user, params.passkeyId);
			if (!passkey) throw new AdminError(404, 'passkey not found');
			if (await isLastWayIn(bucket, user, passkey)) {
				throw new AdminError(
					409,
					'You cannot remove your only remaining way to sign in to the console.'
				);
			}
			await assertRemovingKeepsConsoleReachable(bucket, user, passkey);
			const freshness = adminFreshnessOf(ctx);
			if (freshness === 'strong') {
				throw new AdminError(
					409,
					'Your recent sign-in is already strong enough; remove the passkey directly.'
				);
			}
			if (freshness !== 'password') {
				throw new AdminError(
					409,
					'Sign in again with your password first, then request a confirmation link.'
				);
			}
			const sent = await sendLink(
				bucket,
				user,
				'passkey_remove',
				session.holder,
				{
					request,
					passkeyId: passkey._id,
					urlFor: (token) =>
						`${ISSUER}/admin/me/passkeys/confirm?token=${encodeURIComponent(token)}`
				}
			);
			if (sent === 'throttled') {
				set.status = 429;
				return {
					error: 'rate_limited',
					message:
						'A confirmation link was sent recently. Check your inbox, or try again in a minute.'
				};
			}
			if (sent === 'mail_failed') {
				set.status = 502;
				return {
					error: 'delivery_failed',
					message: 'The confirmation email could not be sent. Try again later.'
				};
			}
			return { sent: true };
		}
	)
	.delete('/admin/api/me/passkeys/:passkeyId', async ({ admin, params }) => {
		const ctx = assertAuth(admin);
		const { bucket, user, session } = await loadSelf(ctx);
		const passkey = await ownPasskey(bucket, user, params.passkeyId);
		if (!passkey) throw new AdminError(404, 'passkey not found');
		if (await isLastWayIn(bucket, user, passkey)) {
			throw new AdminError(
				409,
				'You cannot remove your only remaining way to sign in to the console.'
			);
		}
		await assertRemovingKeepsConsoleReachable(bucket, user, passkey);
		const strong = adminFreshnessOf(ctx) === 'strong';
		const outcome = await completeRemove(
			bucket,
			user,
			session,
			passkey._id,
			strong,
			{
				audit: () => recordAdminAudit(ctx, 'admin.passkey.remove', ctx.userId)
			}
		);
		if (!outcome.ok) {
			if (outcome.reason === 'gone')
				throw new AdminError(404, 'passkey not found');
			if (outcome.reason === 'last') {
				throw new AdminError(
					409,
					'You cannot remove your only remaining way to sign in to the console.'
				);
			}
			throw new AdminError(
				409,
				'Confirm from the email link or sign in again with a passkey or authenticator code before removing this passkey.'
			);
		}
		return { removed: true };
	});
