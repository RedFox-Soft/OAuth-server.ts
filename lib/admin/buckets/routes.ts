import { Elysia } from 'elysia';
import {
	getBucketStore,
	getProjectStore,
	getUserStore
} from '../../adapters/index.js';
import {
	assertAuth,
	assertActiveGroup,
	assertBucketAccess,
	AdminError,
	adminErrorBody,
	resolveAdmin,
	type AdminContext
} from '../auth/rbac.js';
import type { UserBucket } from '../../adapters/types.js';
import { presentAll } from '../federation/service.js';
import { ADMIN_BUCKET_ID, isUndeletableBucket } from '../consts.js';
import { cascadeForAccount } from '../../helpers/cascade.js';
import { emailScopedId } from '../../helpers/email_scoped_id.js';
import { recordAdminAudit } from '../audit/record.js';
import nanoid from '../../helpers/nanoid.js';
import { loadBucketForUsers, loadBucketForEdit } from './access.js';
import {
	assertSomeWayToSignIn,
	prospectiveBucket
} from '../federation/validate.js';
import {
	ChangeBucketAddressBody,
	CreateBucketBody,
	UpdateBucketBody,
	DeleteBucketQuery
} from './schema.js';
import { isReservedBucketName } from '../../consts/reserved_names.js';
import {
	normaliseHost,
	validateBucketHost
} from '../../consts/request_host.js';
import { ApplicationConfig } from '../../configs/application.js';
import { ISSUER } from '../../configs/env.js';
import {
	forgetBucketAddresses,
	isCanonicalHost
} from '../auth/bucketAddress.js';

/*
 * What the slug's pattern cannot check: that this address is free to take.
 *
 * Two refusals, and they are refused rather than resolved because a slug is the path component of an
 * issuer identifier. A reserved slug would shadow one of the server's own endpoints; a duplicate would
 * give two populations one identifier, which is the one thing an issuer identifier may not be. Both
 * are stated with the rule they broke, because an operator who typed `auth` has no way to guess the
 * list otherwise.
 *
 * Case is not normalised here, only compared: the schema pattern admits lowercase only, so a
 * differently-cased slug never reaches this function — it is refused a step earlier, which is what
 * tells the operator the rule instead of silently moving their bucket to an address they did not type.
 */
async function assertSlugAvailable(slug: string) {
	if (isReservedBucketName(slug)) {
		throw new AdminError(
			409,
			`'${slug}' is reserved for this server's own addresses and cannot be a bucket slug`
		);
	}
	if (await getBucketStore().findBySlug(slug)) {
		throw new AdminError(409, `slug '${slug}' is already taken`);
	}
}

/*
 * The address a bucket is being given, judged before anything is written.
 *
 * Exactly one form, never both and never neither. Refused rather than resolved by precedence: a rule
 * that silently prefers the slug is a rule nobody reads, and the operator who supplied a hostname would
 * believe it took effect while their bucket answered somewhere else entirely.
 */
async function resolveAddress(body: {
	slug?: string;
	host?: string;
}): Promise<{ slug?: string; host?: string }> {
	if (body.slug !== undefined && body.host !== undefined) {
		throw new AdminError(
			400,
			'a bucket is addressed by a path segment or a hostname, not both — supply one'
		);
	}
	if (body.slug === undefined && body.host === undefined) {
		throw new AdminError(
			400,
			'a bucket needs an address: supply a slug or a hostname'
		);
	}

	if (body.slug !== undefined) {
		await assertSlugAvailable(body.slug);
		return { slug: body.slug };
	}

	return { host: await assertHostAvailable(body.host as string) };
}

/*
 * What the hostname's shape rules cannot check: that this name is this deployment's to give, and free.
 *
 * Every refusal names the rule it broke, for the reason `assertSlugAvailable` states about reserved
 * slugs — an operator who typed the deployment's own hostname has no way to guess the rule otherwise.
 */
async function assertHostAvailable(value: string): Promise<string> {
	const judged = validateBucketHost(value);
	if (!judged.ok) {
		throw new AdminError(
			400,
			`'${value}' is not usable as an address: ${judged.reason}`
		);
	}
	const host = judged.host;

	if (isCanonicalHost(host)) {
		throw new AdminError(
			409,
			`'${host}' is this deployment's own address and cannot be a bucket's`
		);
	}
	/*
	 * Names the operator reserved for whatever else lives in their domain. Read live rather than at
	 * module load, so an operator who notices a collision can close it without a restart — and compared
	 * in normalised form, because a reservation typed with different case than the request would
	 * otherwise be a reservation that does not hold.
	 */
	if (
		(ApplicationConfig['buckets.reservedHostnames'] as string[]).some(
			(reserved) => normaliseHost(reserved) === host
		)
	) {
		throw new AdminError(
			409,
			`'${host}' is reserved for this deployment and cannot be a bucket's address`
		);
	}
	const holder = await getBucketStore().findByHost(host);
	if (holder) {
		throw new AdminError(
			409,
			`hostname '${host}' is already taken by the bucket '${holder.name}'`
		);
	}
	return host;
}

/*
 * The clients that will stop validating tokens when this bucket's address changes.
 *
 * Named before the change rather than counted, because "14 clients" tells an operator nothing they can
 * act on and a list of client ids is what they take to whoever owns each one. Read through the projects
 * that point at the bucket, which is where a client's membership is recorded.
 */
async function clientsLosingTheirIssuer(bucketId: string): Promise<string[]> {
	const projects = await getProjectStore().list();
	return projects
		.filter((project) => project.bucketId === bucketId)
		.flatMap((project) => project.clientIds ?? [])
		.sort();
}

/*
 * A bucket as a reader may see it: identical except that every configured provider's `clientSecret` is
 * masked.
 *
 * `lib/admin/federation/service.ts` states the rule these routes were breaking — the secret is
 * write-only, masked "on every read, for every role including super-admin". It held on the federation
 * routes and not here, because a bucket document *contains* its providers and these handlers returned it
 * whole. So `GET /admin/api/buckets` handed every provider secret to any authenticated administrator, and
 * `GET /admin/api/buckets/:id` handed a bucket's secrets to anyone with the broader
 * `loadBucketForUsers` access — a project manager, not only the bucket's own.
 *
 * Found by the MCP surface's secrecy sweep (test/mcp/secrecy.spec.ts), which is why that sweep iterates
 * every published read rather than the ones somebody thought to check.
 */
function presentBucket<T extends Pick<UserBucket, 'federation'>>(bucket: T): T {
	if (!bucket.federation?.length) return bucket;
	return { ...bucket, federation: presentAll(bucket) as T['federation'] };
}

/*
 * What an operator needs to know about a hostname they have assigned, and nothing they would be wrong
 * to believe.
 *
 * The record to create is *instruction*, which stays true; whether it exists is a claim about the world
 * this server cannot make. So the address section states the record, and reports arrivals as the one
 * observable fact — a request reached this host, which either happened or did not.
 *
 * Deliberately no `verified` flag. Auth0 and Logto both carry one, and both can: they issue the
 * certificate, so they own a loop that re-checks it. This server issues none, so a flag written once
 * would be believed indefinitely while the name behind it was repointed.
 */
function withAddressGuidance<
	T extends Pick<UserBucket, 'host' | 'hostFirstSeenAt' | 'hostLastSeenAt'>
>(bucket: T): T | (T & { address: Record<string, unknown> }) {
	if (!bucket.host) return bucket;
	return {
		...bucket,
		address: {
			host: bucket.host,
			requestsArrived: bucket.hostLastSeenAt !== undefined,
			firstArrivalAt: bucket.hostFirstSeenAt ?? null,
			lastArrivalAt: bucket.hostLastSeenAt ?? null,
			/*
			 * Named concretely rather than described. "Point this name at the deployment" sends an operator
			 * to look something up; a record they can copy does not.
			 */
			dnsRecord: {
				name: bucket.host,
				type: 'CNAME',
				value: new URL(ISSUER).hostname
			},
			stillToDo:
				bucket.hostLastSeenAt === undefined
					? 'No request has reached this hostname yet. Create the DNS record above and obtain a TLS certificate for the name — neither is done by this server, and it cannot tell you whether either has been done, only whether a request has arrived.'
					: 'A TLS certificate is still required for this name; this server does not issue one and cannot confirm that one exists.'
		}
	};
}

/*
 * A second factor on a bucket that accepts no passwords is inert, not wrong: the requirement governs
 * the password door, and there is no password door. Recording the intended posture before opening one
 * is a reasonable order to do things in, so this says so rather than refusing — a 422 here would make
 * an operator turn password login on, set the flag, and turn it back off to express what they meant.
 *
 * Only on the write paths. A read that carried it would repeat the same sentence on every poll of a
 * federation-only bucket, which trains an operator to ignore it.
 */
function withInertTotpAdvisory<
	T extends Pick<UserBucket, 'totpRequired' | 'passwordLogin'>
>(bucket: T): T | (T & { advisory: string }) {
	if (!bucket.totpRequired || bucket.passwordLogin !== false) return bucket;
	return {
		...bucket,
		advisory:
			'totpRequired has no effect while passwordLogin is off — it governs password sign-in, and federated sign-in is never gated by it'
	};
}

export const bucketRoutes = new Elysia({ name: 'admin-buckets' })
	.use(resolveAdmin)
	.onError(({ error, set }) => {
		if (error instanceof AdminError) {
			set.status = error.status;
			return adminErrorBody(error);
		}
	})
	.get('/admin/api/buckets', async ({ admin }) => {
		const ctx = assertAuth(admin as AdminContext | null);
		const store = getBucketStore();
		/*
		 * Listing has to agree with access, or the console shows an administrator fewer buckets than it
		 * will let them open. `assertBucketUserAccess` admits a bucket backing a project the caller's
		 * group owns, so the list has to admit it too — it did not before this feature, and a bucket you
		 * could administer but never see was the result.
		 */
		let all;
		if (ctx.roles.includes('super_admin')) {
			all = await store.list();
		} else {
			const owned = await store.listByGroup(ctx.activeGroupId);
			const projects = await getProjectStore().listByGroup(ctx.activeGroupId);
			const backing = projects
				.map((p) => p.bucketId)
				.filter((id): id is string => id !== null);
			const missing = backing.filter((id) => !owned.some((b) => b._id === id));
			const extra = (
				await Promise.all(missing.map((id) => store.find(id)))
			).filter((b): b is NonNullable<typeof b> => b !== null);
			all = [...owned, ...extra];
		}
		return all.filter((b) => b._id !== ADMIN_BUCKET_ID).map(presentBucket);
	})
	.post(
		'/admin/api/buckets',
		async ({ admin, body, set }) => {
			const ctx = assertAuth(admin as AdminContext | null);
			// No role gate: the authority is membership of the group the bucket will belong to.
			const ownerGroupId = assertActiveGroup(ctx);
			/*
			 * A new bucket cannot be created unreachable. Providers are added through their own routes, so at
			 * creation there are none — which makes `passwordLogin: false` here always a lockout.
			 */
			assertSomeWayToSignIn({
				passwordLogin: body.passwordLogin !== false,
				federation: []
			});
			/*
			 * Before the audit entry, for the reason stated on the sign-in guard above: an entry describing
			 * a bucket a 409 refused to create would record an address that never existed.
			 */
			const address = await resolveAddress(body);
			/*
			 * Naming a hostname is an instance-level act, never a group-level one. A project administrator
			 * may create buckets in their own group; letting them name one would put a name in the
			 * operator's own domain under their control — an escalation out of the group boundary, and out
			 * of whatever else that domain is used for.
			 */
			if (address.host !== undefined && !ctx.roles.includes('super_admin')) {
				throw new AdminError(
					403,
					'only an administrator of this instance may give a bucket a hostname of its own'
				);
			}
			// The id is allocated here, not by the store, so the audit entry can name the bucket that is
			// about to exist — audit-first has nothing to point at otherwise.
			const bucketId = nanoid();
			await recordAdminAudit(ctx, 'bucket.create', bucketId, { ownerGroupId });
			const bucket = await getBucketStore().create({
				_id: bucketId,
				name: body.name,
				...address,
				roles: body.roles ?? [],
				ownerGroupId,
				passwordLogin: body.passwordLogin,
				registrationOpen: body.registrationOpen,
				emailVerificationRequired: body.emailVerificationRequired,
				verificationMethod: body.verificationMethod,
				totpRequired: body.totpRequired
			});
			/* A new address exists; the resolver's positive cache must be able to see it. */
			forgetBucketAddresses();
			set.status = 201;
			// No advisory is reachable here: the guard above proves a new bucket accepts passwords, so
			// the requirement can never be inert at creation.
			return presentBucket(bucket);
		},
		{ body: CreateBucketBody }
	)
	.get('/admin/api/buckets/:id', async ({ admin, params }) => {
		const ctx = assertAuth(admin as AdminContext | null);
		return withAddressGuidance(
			presentBucket(await loadBucketForUsers(ctx, params.id))
		);
	})
	.patch(
		'/admin/api/buckets/:id',
		async ({ admin, params, body }) => {
			const ctx = assertAuth(admin as AdminContext | null);
			const bucket = await loadBucketForEdit(ctx, params.id);
			/*
			 * Checked before the audit entry and the write: an entry describing a change a 409 refused would
			 * state that an operator closed a bucket's password door when they did not. The provider routes
			 * enforce the same rule from the other direction, through the same function.
			 */
			assertSomeWayToSignIn(prospectiveBucket(bucket, body));
			/*
			 * Recorded whatever the request changed. This used to fire only for a registration or
			 * verification field, so renaming a bucket or reassigning its managers left no trace at all
			 * — while still being an exercised privilege over who can administer a bucket's users.
			 */
			await recordAdminAudit(ctx, 'bucket.update', params.id, {
				attributes: Object.keys(body),
				ownerGroupId: bucket.ownerGroupId
			});
			const updated = await getBucketStore().update(params.id, body);
			if (!updated) throw new AdminError(404, 'bucket not found');
			return withInertTotpAdvisory(presentBucket(updated));
		},
		{ body: UpdateBucketBody }
	)
	/*
	 * Moving a bucket to a different address — its own route, its own audit action, and `high` on the
	 * agent surface.
	 *
	 * Deliberately not a field on the PATCH body above, and the comment on `slug` in `UpdateBucketBody`
	 * is the argument: changing an address changes the bucket's issuer identifier, so every client
	 * integrated with it stops validating tokens on the next request. Admitting it there would give that
	 * the same weight as renaming a label — one audit action for both, one `ordinary` classification
	 * covering both, and the two-call confirmation gate would never see it.
	 */
	.post(
		'/admin/api/buckets/:id/address',
		async ({ admin, params, body, set }) => {
			const ctx = assertAuth(admin as AdminContext | null);

			/*
			 * Instance-level, whichever form is being moved to. A group administrator who could rename a
			 * bucket's address could break every client integrated with it, and one who could name a
			 * hostname would reach into the operator's domain.
			 */
			if (!ctx.roles.includes('super_admin')) {
				throw new AdminError(
					403,
					'only an administrator of this instance may change a bucket address'
				);
			}

			/*
			 * Before the bucket is loaded, so the answer cannot depend on who is asking — the order the
			 * delete route below settled on for the same reason. The console authenticates against the
			 * instance's own issuer, so moving the administrators bucket would lock every operator out of
			 * the surface that could move it back.
			 */
			if (isUndeletableBucket(params.id)) {
				throw new AdminError(
					403,
					'this bucket is served at the root and its address cannot be changed'
				);
			}

			const bucket = await getBucketStore().find(params.id);
			if (!bucket) throw new AdminError(404, 'bucket not found');

			const address = await resolveAddress(body);

			/*
			 * What will break, named before anything changes. An operator who has not seen this list has
			 * not been told what the change costs, which is why the write refuses without `confirm`.
			 */
			const affected = await clientsLosingTheirIssuer(params.id);
			const preview = {
				from: bucket.host ?? bucket.slug ?? null,
				to: address.host ?? address.slug ?? null,
				clientsNeedingReconfiguration: affected,
				consequence:
					'the issuer identifier changes, so every client listed stops validating tokens until it is reconfigured; the previous address stops answering and everyone signed in signs in again'
			};

			if (body.confirm !== true) {
				set.status = 409;
				return { ...preview, confirmationRequired: true };
			}

			await recordAdminAudit(ctx, 'bucket.address.change', params.id, {
				from: preview.from,
				to: preview.to
			});

			const moved = await getBucketStore().setAddress(params.id, address);
			if (!moved) throw new AdminError(404, 'bucket not found');

			/*
			 * The one place this operation can leave a bucket answering at its old address. The resolver
			 * caches by both forms, and a stale entry there is exactly the second issuer identifier the
			 * move exists to avoid.
			 */
			forgetBucketAddresses();
			return { ...preview, moved: true, bucket: presentBucket(moved) };
		},
		{ body: ChangeBucketAddressBody }
	)
	.delete(
		'/admin/api/buckets/:id',
		async ({ admin, params, query }) => {
			const ctx = assertAuth(admin as AdminContext | null);
			/*
			 * First, before the bucket is even loaded, so the answer cannot depend on whether it happens
			 * to be empty or on who is asking. This route does not go through `loadBucketForEdit`, which
			 * is where `assertNotReserved` lives, so until 051 it reached no reserved-bucket guard at all
			 * and an empty administrators' or default bucket was deletable by a super administrator.
			 */
			if (isUndeletableBucket(params.id)) {
				throw new AdminError(
					403,
					'this bucket is part of the server itself and cannot be deleted'
				);
			}
			const bucket = await getBucketStore().find(params.id);
			if (!bucket) throw new AdminError(404, 'bucket not found');
			assertBucketAccess(ctx, bucket);
			/*
			 * Before the election is even considered, and unclearable by it. What this protects is
			 * outside the bucket: a project left pointing at a bucket that no longer exists is a broken
			 * tenant, which is not something the bucket's own contents can consent away.
			 */
			if ((await getProjectStore().countByBucket(params.id)) > 0) {
				throw new AdminError(409, 'bucket is assigned to one or more projects');
			}
			/*
			 * `list()` does not filter, which is what makes a deactivated account count — deactivation is
			 * a sign-in decision, not absence, and the account is still there to be destroyed. Only the
			 * count is reported and only a count is accepted back: a bucket can hold thousands of
			 * accounts, their identifiers are not the caller's business, and an administrator is not
			 * asked to decide about people by name.
			 */
			const store = getUserStore(params.id);
			const accounts = await store.list();
			if (accounts.length > 0) {
				if (query.cascade === undefined) {
					throw new AdminError(409, 'bucket still holds end-users', {
						blockers: [{ kind: 'enduser', count: accounts.length }]
					});
				}
				if (query.expect !== accounts.length) {
					throw new AdminError(
						409,
						'the bucket end-users changed since you reviewed them',
						{ blockers: [{ kind: 'enduser', count: accounts.length }] }
					);
				}
			}

			/*
			 * One entry carrying a count, never one per account: a bucket-sized deletion writing a row
			 * per person would bury everything else an operator needs to investigate, and would say
			 * nothing the bucket's identity does not already say — a cascade is all-or-nothing over what
			 * it held. After the guards and before the destruction, by the trail's own contract.
			 */
			await recordAdminAudit(ctx, 'bucket.delete', params.id, {
				...(accounts.length > 0
					? { cascade: { endusers: accounts.length } }
					: {})
			});

			/*
			 * The email is read before the row goes, per account, because the email-scoped areas are
			 * addressed by `${bucketId}:${email}` and nothing else records it. Destroy first and those
			 * records are unreachable — skipped in silence, with no error anywhere to notice. The
			 * already-computed id in `cascadeForAccount`'s signature is what makes that ordering
			 * impossible to get wrong here.
			 */
			const failedAreas: string[] = [];
			for (const account of accounts) {
				const scopedId = account.email
					? emailScopedId(params.id, account.email)
					: null;
				await store.destroy(account._id);
				const swept = await cascadeForAccount(account._id, scopedId);
				failedAreas.push(...swept.failedAreas);
			}

			await getBucketStore().destroy(params.id);
			/* The address is gone; a cached entry would keep answering for a bucket that no longer exists. */
			forgetBucketAddresses();
			/* The half that was missing: without this a deleted bucket left its `user_<bucket>` area behind
			 * for good, indexes and all. Safe here and only here, because the loop above emptied it. */
			await store.destroyArea();

			if (failedAreas.length > 0) {
				throw new AdminError(
					500,
					`bucket deleted, but records of its end-users survive in: ${[...new Set(failedAreas)].join(', ')}`,
					{ failedAreas: [...new Set(failedAreas)] }
				);
			}
			return { ok: true, endUsersDestroyed: accounts.length };
		},
		{ query: DeleteBucketQuery }
	);
