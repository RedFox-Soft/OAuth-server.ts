import { Elysia } from 'elysia';
import {
	getActivityStore,
	getBucketKeysStore,
	getBucketStore,
	getBucketGroupStore,
	getContainerOwnershipStore,
	getGroupStore,
	getProjectStore,
	getProtectedResourceStore,
	getProvisioningConnectionStore,
	getUserStore
} from '../../adapters/index.js';
import { destroyConnectionsOf } from '../../provisioning/service.js';
import {
	assertAuth,
	assertActiveGroup,
	assertGroupOwner,
	AdminError,
	adminErrorBody,
	projectReach,
	projectsOfCallerGroups,
	reachOf,
	resolveAdmin,
	type AdminContext
} from '../auth/rbac.js';
import {
	bucketCan,
	bucketFactsWanted,
	holdsBucket,
	meCan,
	NO_PROJECT_REACH,
	reachesProject,
	type BucketCan,
	type BucketDependents,
	type BucketFacts,
	type ProjectReach
} from '../auth/can.js';
import type { Project, UserBucket } from '../../adapters/types.js';
import { isUniqueValueTaken } from '../../adapters/conflicts.js';
import { presentAll } from '../federation/service.js';
import { ADMIN_BUCKET_ID, isUndeletableBucket, reservedOf } from '../consts.js';
import { cascadeForAccount } from '../../helpers/cascade.js';
import { emailScopedId } from '../../helpers/email_scoped_id.js';
import { recordAdminAudit } from '../audit/record.js';
import nanoid from '../../helpers/nanoid.js';
import {
	ensureBucketKey,
	invalidateBucketKeys
} from '../../keys/issuer_keys.js';
import { namespaceOf, ROOT_NAMESPACE } from '../../resources/namespace.js';
import {
	applyMove,
	DeclarationsConflict,
	planMove,
	type MovePlan
} from '../resources/move.js';
import { loadBucketForSettings, loadBucketForEdit } from './access.js';
import {
	adminBucketAdvisory,
	assertAdminBucketChange
} from './admin_bucket.js';
import { sameExpect, signInCounts, signInPreview } from './sign_in_preview.js';
import {
	assertSomeWayToSignIn,
	prospectiveBucket
} from '../federation/validate.js';
import {
	ChangeBucketAddressBody,
	CreateBucketBody,
	MoveBucketOwnerBody,
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
import { now } from '../../activity/clock.js';
import { monthOf } from '../../activity/periods.js';
import { readPeriod } from '../../activity/read.js';
import { addressOf, issuerFor } from '../../configs/issuer.js';
import { callbackUri } from '../../federation/flow.js';
import { mailDeliveryConfigured } from '../../mail/mailer.js';
import { getClientView } from '../clients/service.js';
import { groupLabel } from '../groups/label.js';
import {
	forgetBucketAddresses,
	isAddressable,
	isCanonicalHost
} from '../auth/bucketAddress.js';
import {
	describeGroup,
	loadDestination,
	sourceGroupOf
} from '../ownership/destination.js';

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
			`'${slug}' is reserved for this server's own addresses and cannot be a bucket slug`,
			{ field: 'slug' }
		);
	}
	if (await getBucketStore().findBySlug(slug)) {
		throw new AdminError(409, `slug '${slug}' is already taken`, {
			field: 'slug'
		});
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
			`'${value}' is not usable as an address: ${judged.reason}`,
			{ field: 'host' }
		);
	}
	const host = judged.host;

	if (isCanonicalHost(host)) {
		throw new AdminError(
			409,
			`'${host}' is this deployment's own address and cannot be a bucket's`,
			{ field: 'host' }
		);
	}
	/*
	 * Names the operator reserved for whatever else lives in their domain. Read live rather than at
	 * module load, so an operator who notices a collision can close it without a restart — and compared
	 * in normalised form, because a reservation typed with different case than the request would
	 * otherwise be a reservation that does not hold.
	 */
	if (
		ApplicationConfig['buckets.reservedHostnames'].some(
			(reserved) => normaliseHost(reserved) === host
		)
	) {
		throw new AdminError(
			409,
			`'${host}' is reserved for this deployment and cannot be a bucket's address`,
			{ field: 'host' }
		);
	}
	const holder = await getBucketStore().findByHost(host);
	if (holder) {
		throw new AdminError(
			409,
			`hostname '${host}' is already taken by the bucket '${holder.name}'`,
			{ field: 'host' }
		);
	}
	return host;
}

/*
 * The same refusal, for the window the lookup above cannot cover.
 *
 * That lookup reads and the write happens after it, so two operators assigning one hostname both read
 * "free" and both write; the datastore's own uniqueness constraint is what makes the guarantee true,
 * and it reports in its own terms. Left unhandled, the loser of that race gets a 500 and a recorded
 * defect for a refusal this API has a status code for — which is the outcome `UniqueValueTaken` was
 * introduced to prevent and, until now, did not, because nothing caught it.
 *
 * No holder is named here. Naming one costs a second read on a path reached only by a race, and the
 * operator's next step — choose another name — is the same either way.
 */
async function refusingATakenHostname<T>(write: () => Promise<T>): Promise<T> {
	try {
		return await write();
	} catch (error) {
		if (isUniqueValueTaken(error)) {
			throw new AdminError(409, `hostname '${error.value}' is already taken`, {
				field: 'host'
			});
		}
		throw error;
	}
}

/* As stored: a project document written before `clientIds` existed has none. */
function clientIdsOf(project: {
	clientIds?: readonly string[];
}): readonly string[] {
	return project.clientIds ?? [];
}

interface AddressChangeCounts {
	applications: number;
	connections: number;
	providers: number;
	resources: number;
}

interface AddressChangePreview {
	from: string;
	to: string;
	applications: {
		clientId: string;
		name: string | null;
		projectId: string;
		projectName: string;
	}[];
	connections: { id: string; displayName: string }[];
	providers: { id: string; displayName: string; newCallback: string }[];
	resources: { identifier: string; projectId: string; projectName: string }[];
	namespaceMove: boolean;
	expect: AddressChangeCounts;
	consequence: string;
}

/*
 * Everything an address change reaches, named before the change (specs/081 FR-013).
 *
 * Named rather than counted, because "14 clients" tells an operator nothing they can act on: each
 * application with the project it belongs to is what they take to whoever owns it, each identity provider
 * with the callback address its upstream registration must be given, each provisioning connection whose
 * directory must be re-pointed, and each declared resource whose tokens will carry the new issuer. Read
 * through the projects that point at the bucket, which is where an application's membership is recorded.
 */
async function addressChangePreview(
	bucket: UserBucket,
	address: { slug?: string; host?: string }
): Promise<AddressChangePreview> {
	const target = { _id: bucket._id, ...address };
	const projects = (await getProjectStore().list())
		.filter((project) => project.bucketId === bucket._id)
		.sort((a, b) => a.name.localeCompare(b.name));

	const applications: AddressChangePreview['applications'] = [];
	for (const project of projects) {
		for (const clientId of [...clientIdsOf(project)].sort()) {
			const view = await getClientView(clientId);
			applications.push({
				clientId,
				name: view?.clientName ?? null,
				projectId: project._id,
				projectName: project.name
			});
		}
	}
	/*
	 * A SCIM connection's base URL and token audience are both derived from the address, so a customer's
	 * directory stops provisioning until its administrator re-enters them.
	 */
	const connections = (
		await getProvisioningConnectionStore().listByBucket(bucket._id)
	).map((c) => ({ id: c._id, displayName: c.displayName }));
	/* An upstream matches `redirect_uri` by exact string, so each registration needs the new callback. */
	const providers = bucket.federation.map((provider) => ({
		id: provider.id,
		displayName: provider.displayName,
		newCallback: callbackUri(target)
	}));
	const resources = (
		await Promise.all(
			projects.map(async (project) =>
				(await getProtectedResourceStore().listByProject(project._id)).map(
					(resource) => ({
						identifier: resource.identifier,
						projectId: project._id,
						projectName: project.name
					})
				)
			)
		)
	).flat();

	return {
		from: issuerFor(bucket),
		to: issuerFor(target),
		applications,
		connections,
		providers,
		resources,
		namespaceMove: namespaceOf(bucket) === ROOT_NAMESPACE,
		expect: {
			applications: applications.length,
			connections: connections.length,
			providers: providers.length,
			resources: resources.length
		},
		consequence:
			'the issuer identifier changes, so every application listed stops validating tokens until it is reconfigured, every identity provider listed refuses sign-in until its upstream registration has the new callback address, and every provisioning connection listed stops until its directory is re-pointed; the previous address stops answering and everyone signed in signs in again'
	};
}

function sameCounts(
	expected: AddressChangeCounts | undefined,
	actual: AddressChangeCounts
): boolean {
	return (
		expected !== undefined &&
		expected.applications === actual.applications &&
		expected.connections === actual.connections &&
		expected.providers === actual.providers &&
		expected.resources === actual.resources
	);
}

/* How a bucket is addressed, and the issuer and discovery addresses a client is configured with. */
function addressing(bucket: Pick<UserBucket, '_id' | 'slug' | 'host'>): {
	addressForm: ReturnType<typeof addressOf>['kind'];
	issuer: string | null;
	discoveryUrl: string | null;
} {
	const addressForm = addressOf(bucket).kind;
	/*
	 * Null rather than the id-derived identifier `issuerFor` falls back to: a bucket with no address of its
	 * own is not routed at that path, so its "issuer" would answer 404 to the client given it.
	 */
	if (addressForm === 'unaddressed') {
		return { addressForm, issuer: null, discoveryUrl: null };
	}
	const issuer = issuerFor(bucket);
	return {
		addressForm,
		issuer,
		discoveryUrl: `${issuer}/.well-known/openid-configuration`
	};
}

/* Counted across the instance, so an owner is never told a bucket is unused while another group's project uses it. */
async function dependentsOf(
	bucket: Pick<UserBucket, '_id' | 'federation'>
): Promise<BucketDependents> {
	const [projects, connections] = await Promise.all([
		getProjectStore().countByBucket(bucket._id),
		getProvisioningConnectionStore().listByBucket(bucket._id)
	]);
	return {
		projects,
		providers: bucket.federation.length,
		connections: connections.length
	};
}

/* The facts this caller's rights on this bucket depend on, read only where they can change the answer. */
async function bucketFacts(
	ctx: AdminContext,
	bucket: Pick<
		UserBucket,
		'_id' | 'ownerGroupId' | 'slug' | 'host' | 'federation'
	>
): Promise<BucketFacts> {
	const wanted = bucketFactsWanted(ctx, bucket);
	const [dependents, accounts] = await Promise.all([
		wanted.dependents ? dependentsOf(bucket) : undefined,
		wanted.accounts
			? getUserStore(bucket._id)
					.tally()
					.then((tally) => tally.total)
			: undefined
	]);
	return {
		...(dependents === undefined ? {} : { dependents }),
		...(accounts === undefined ? {} : { accounts })
	};
}

/*
 * Why an address change is refused, in the terms the caller can act on: an owner is told what depends on
 * the bucket, because removing it — or asking an instance administrator — is their next step.
 */
function addressRefusal(
	ctx: AdminContext,
	bucket: UserBucket,
	facts: BucketFacts
): string {
	if (isUndeletableBucket(bucket._id)) {
		return 'this bucket is served at the root and its address cannot be changed';
	}
	const dependents = facts.dependents;
	if (
		dependents &&
		dependents.projects + dependents.providers + dependents.connections > 0
	) {
		return `Used by ${countOf(dependents.projects, 'project')}, ${countOf(dependents.providers, 'identity provider')} and ${countOf(dependents.connections, 'provisioning connection')}: only an instance administrator can change this bucket's address now.`;
	}
	if (bucketFactsWanted(ctx, bucket).dependents || ctx.superAdmin) {
		return 'this bucket address cannot be changed';
	}
	return addressOf(bucket).kind === 'host'
		? 'only an administrator of this instance may change the address of a bucket served at its own hostname'
		: 'only an owner of the bucket group or an administrator of this instance may change a bucket address';
}

function countOf(n: number, noun: string): string {
	return `${n} ${noun}${n === 1 ? '' : 's'}`;
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
function presentBucket<T extends Pick<UserBucket, '_id' | 'federation'>>(
	bucket: T
): T & { reserved?: 'administrators' } {
	/*
	 * The console's own bucket says so on the response, so the console and an agent learn it from what
	 * they were sent rather than by knowing the id.
	 */
	const marked =
		reservedOf(bucket._id) === 'administrators'
			? { ...bucket, reserved: 'administrators' as const }
			: bucket;
	if (!marked.federation.length) return marked;
	return { ...marked, federation: presentAll(bucket) };
}

/*
 * What a bucket's rights are decided from, gathered once per request so a list states every row's rights
 * from the same reads: the caller's reach through their projects, and the projects they can see by bucket.
 */
interface RightsFacts {
	readonly access: ProjectReach;
	readonly visibleProjects: ReadonlyMap<string, readonly Project[]>;
}

async function rightsFacts(ctx: AdminContext): Promise<RightsFacts> {
	const projects = ctx.superAdmin
		? await getProjectStore().list()
		: await projectsOfCallerGroups(ctx);
	const visibleProjects = new Map<string, Project[]>();
	for (const project of projects) {
		if (!project.bucketId || !reachesProject(ctx, project)) continue;
		visibleProjects.set(project.bucketId, [
			...(visibleProjects.get(project.bucketId) ?? []),
			project
		]);
	}
	return {
		access: ctx.superAdmin ? NO_PROJECT_REACH : reachOf(projects),
		visibleProjects
	};
}

/*
 * The caller's rights on a bucket, and the state that would refuse a right they hold — so the console hides
 * what it may not do and disables, with the reason, what it may do but not yet.
 *
 * Only the projects the caller can reach are named. A bucket whose projects sit in another group is
 * reachable only through data older than the rule that a project and its bucket share a group, and naming
 * them would tell one tenant what another calls its work; the deletion's own 409 still refuses it.
 */
function withRights<
	T extends Pick<UserBucket, '_id' | 'ownerGroupId' | 'slug' | 'host'>
>(
	ctx: AdminContext,
	bucket: T,
	facts: RightsFacts,
	state: BucketFacts
): T & {
	can: BucketCan;
	blockers: {
		usedByProjects: { id: string; name: string }[];
		addressable: boolean;
		/*
		 * The state the two state-dependent rights were decided from (specs/081), so the console can say why
		 * one is false; null where it was not read, because it could not change this caller's answer.
		 */
		dependents: BucketDependents | null;
		accounts: number | null;
	};
} {
	return {
		...bucket,
		can: bucketCan(ctx, bucket, facts.access, state),
		blockers: {
			usedByProjects: (facts.visibleProjects.get(bucket._id) ?? []).map(
				(project) => ({ id: project._id, name: project.name })
			),
			addressable: isAddressable(bucket),
			dependents: state.dependents ?? null,
			accounts: state.accounts ?? null
		}
	};
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
	if (!bucket.totpRequired || bucket.passwordLogin) return bucket;
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
			// The identifiers in the way, so an operator knows which declaration to remove or rename.
			return error instanceof DeclarationsConflict
				? { ...adminErrorBody(error), conflicts: error.conflicts }
				: adminErrorBody(error);
		}
	})
	.get('/admin/api/buckets', async ({ admin }) => {
		const ctx = assertAuth(admin);
		const store = getBucketStore();
		/*
		 * Listing has to agree with access, or the console shows an administrator fewer buckets than it
		 * will let them open. The `read` right admits a bucket backing a project the caller's
		 * group owns, so the list has to admit it too — it did not before this feature, and a bucket you
		 * could administer but never see was the result.
		 */
		let all;
		if (ctx.superAdmin) {
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
		/*
		 * A super administrator configures the administrators' bucket like any other, so it is listed for
		 * them. For anyone else it stays out of the list, as it is out of reach.
		 */
		const listed = all.filter(
			(b) => ctx.superAdmin || b._id !== ADMIN_BUCKET_ID
		);
		const [facts, holding, states] = await Promise.all([
			rightsFacts(ctx),
			getProvisioningConnectionStore().bucketsHolding(),
			Promise.all(listed.map((b) => bucketFacts(ctx, b)))
		]);
		const held = new Set(holding);
		return listed.map((b, i) => {
			const { addressForm, issuer } = addressing(b);
			return {
				...withRights(ctx, presentBucket(b), facts, states[i] ?? {}),
				addressForm,
				issuer,
				/*
				 * An arrival is the one fact this server can observe about a hostname; a host nobody has
				 * reached is the row an operator has still to finish setting up.
				 */
				hostReached: b.host !== undefined && b.hostLastSeenAt !== undefined,
				held: held.has(b._id)
			};
		});
	})
	.post(
		'/admin/api/buckets',
		async ({ admin, body, set }) => {
			const ctx = assertAuth(admin);
			/*
			 * No role gate: the authority is membership of the group the bucket will belong to — the active
			 * group, or one the caller names (specs/087), held to the rules a move into it is held to.
			 */
			const ownerGroupId =
				body.groupId === undefined
					? assertActiveGroup(ctx)
					: (await loadDestination(ctx, body.groupId))._id;
			/*
			 * Naming a hostname is an instance-level act, never a group-level one. A project administrator
			 * may create buckets in their own group; letting them name one would put a name in the
			 * operator's own domain under their control — an escalation out of the group boundary, and out
			 * of whatever else that domain is used for.
			 *
			 * Decided before the hostname is judged, so a caller without the right is refused for that and
			 * not told whether the name they tried is free.
			 */
			if (body.host !== undefined && !meCan(ctx).createHost) {
				throw new AdminError(
					403,
					'only an administrator of this instance may give a bucket a hostname of its own'
				);
			}
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
			// The id is allocated here, not by the store, so the audit entry can name the bucket that is
			// about to exist — audit-first has nothing to point at otherwise.
			const bucketId = nanoid();
			await recordAdminAudit(ctx, 'bucket.create', bucketId, { ownerGroupId });
			const bucket = await refusingATakenHostname(() =>
				getBucketStore().create({
					_id: bucketId,
					name: body.name,
					...address,
					ownerGroupId,
					passwordLogin: body.passwordLogin,
					/*
					 * Closed unless asked for (specs/083): a bucket's people arrive through its administrators, its
					 * identity providers and its directories, and a door anyone can walk through is a decision to
					 * state at creation, not a default to notice later. Only the route defaults it — a stored bucket
					 * without the field keeps reading as it always has.
					 */
					registrationOpen: body.registrationOpen ?? false,
					emailVerificationRequired: body.emailVerificationRequired,
					verificationMethod: body.verificationMethod,
					totpRequired: body.totpRequired
				})
			);
			/* A new address exists; the resolver's positive cache must be able to see it. */
			forgetBucketAddresses();
			/*
			 * An addressable bucket is an issuer from this moment, so it gets its signing key now rather
			 * than on the first sign-in. Not undone if this fails: the bucket exists, the failure reaches the
			 * admin plane as the fault it is, and the bucket's first use creates the key anyway.
			 */
			await ensureBucketKey(bucketId);
			set.status = 201;
			// No advisory is reachable here: the guard above proves a new bucket accepts passwords, so
			// the requirement can never be inert at creation.
			return presentBucket(bucket);
		},
		{ body: CreateBucketBody }
	)
	.get('/admin/api/buckets/:id', async ({ admin, params }) => {
		const ctx = assertAuth(admin);
		const bucket = await loadBucketForSettings(ctx, params.id, 'read');
		const [facts, state] = await Promise.all([
			rightsFacts(ctx),
			bucketFacts(ctx, bucket)
		]);
		/*
		 * The projects named are those the caller can reach, for the reason `withRights` gives; each with how
		 * many applications it holds, which is what a change to this bucket's sign-in reaches through it.
		 */
		const projects = (facts.visibleProjects.get(bucket._id) ?? []).map(
			(project) => ({
				id: project._id,
				name: project.name,
				clientCount: clientIdsOf(project).length
			})
		);
		return {
			...withAddressGuidance(
				withRights(ctx, presentBucket(bucket), facts, state)
			),
			/*
			 * Sent by the server because the console cannot derive it: ISSUER is kept out of the browser
			 * bundle (lib/configs/issuer.ts).
			 */
			...addressing(bucket),
			projects
		};
	})
	/*
	 * What a bucket's overview counts (specs/081 FR-018): computed per request and never stored. Governed by
	 * `read`, as the bucket itself is; the active-user figure only with `readActivity`, the right that
	 * governs the activity page it summarises.
	 */
	.get('/admin/api/buckets/:id/summary', async ({ admin, params }) => {
		const ctx = assertAuth(admin);
		const bucket = await loadBucketForSettings(ctx, params.id, 'read');
		const readsActivity = bucketCan(ctx, bucket, NO_PROJECT_REACH).readActivity;
		const [counts, groups, connections, mail, figure] = await Promise.all([
			signInCounts(bucket),
			getBucketGroupStore().query(
				{ bucketId: bucket._id },
				{ startIndex: 1, count: 0 }
			),
			getProvisioningConnectionStore().listByBucket(bucket._id),
			mailDeliveryConfigured(),
			readsActivity ? readPeriod(bucket._id, monthOf(now())) : null
		]);
		const enabled = bucket.federation.filter((provider) => provider.enabled);
		return {
			users: counts.total,
			unverified: counts.unverified,
			withoutAuthenticator: counts.withoutAuthenticator,
			withoutLinkedIdentity: counts.withoutLinkedIdentity,
			/*
			 * What the sign-in tab shows under each switch (specs/083), counted as the change's preview counts
			 * them: who has no link to an enabled provider, and who signs in with a password but holds no
			 * authenticator.
			 */
			withoutEnabledLink: counts.withoutEnabledLink,
			passwordWithoutAuthenticator: counts.passwordWithoutAuthenticator,
			/* The default bucket only: the projects whose sign-in lands there, those naming no bucket included. */
			...(counts.projects === undefined ? {} : { projects: counts.projects }),
			userGroups: groups.totalResults,
			connections: connections.length,
			held: connections.filter((c) => c.hold !== undefined).length,
			providers: {
				enabled: enabled.length,
				/* A provider that creates accounts on first sign-in is a door anyone at the upstream can open. */
				creating: enabled.filter((provider) => provider.provisioning === 'jit')
					.length
			},
			/*
			 * Absent rather than zero before counting began, as the activity page answers a month it cannot
			 * count: a zero would read as "nobody signed in".
			 */
			...(figure ? { activeThisMonth: figure.total } : {}),
			mailDeliveryConfigured: mail
		};
	})
	/*
	 * The resource namespace a bucket's projects declare into (specs/085), read from the projects using it —
	 * which is where a declaration's namespace comes from — rather than from a store query by namespace.
	 *
	 * An addressable bucket is a namespace of its own, so every declaration in it is listed. A bucket served
	 * at the root shares the root namespace with every other root-served bucket and every project with no
	 * bucket, so only its own projects' declarations are listed: listing the whole root would show one
	 * tenant what another declares.
	 */
	.get('/admin/api/buckets/:id/resources', async ({ admin, params }) => {
		const ctx = assertAuth(admin);
		const bucket = await loadBucketForSettings(ctx, params.id, 'read');
		const namespace = namespaceOf(bucket);
		const projects = (await getProjectStore().list()).filter(
			(project) => project.bucketId === bucket._id
		);
		const resources = (
			await Promise.all(
				projects.map(async (project) =>
					(await getProtectedResourceStore().listByProject(project._id))
						.filter((resource) => resource.namespace === namespace)
						.map((resource) => ({
							identifier: resource.identifier,
							name: resource.name,
							projectId: project._id,
							projectName: project.name
						}))
				)
			)
		)
			.flat()
			.sort((a, b) =>
				a.identifier < b.identifier ? -1 : a.identifier > b.identifier ? 1 : 0
			);
		return {
			namespace: namespace === ROOT_NAMESPACE ? 'root' : 'bucket',
			resources
		};
	})
	.patch(
		'/admin/api/buckets/:id',
		async ({ admin, params, body, status }) => {
			const ctx = assertAuth(admin);
			const bucket = await loadBucketForSettings(ctx, params.id, 'edit');
			const { confirm, expect, ...changes } = body;
			/*
			 * Checked before the audit entry and the write: an entry describing a change a 409 refused would
			 * state that an operator closed a bucket's password door when they did not. The provider routes
			 * enforce the same rule from the other direction, through the same function.
			 */
			assertSomeWayToSignIn(prospectiveBucket(bucket, changes));
			/*
			 * Requiring verification sends a message to everyone unverified at their next sign-in, and refuses
			 * them until they follow it. Without mail nobody can, so on any bucket the requirement would be a
			 * lock-out of every unverified person — refused before it is previewed, recorded or written.
			 */
			if (
				changes.emailVerificationRequired === true &&
				!bucket.emailVerificationRequired &&
				!(await mailDeliveryConfigured())
			) {
				throw new AdminError(
					409,
					'people could not receive the verification message: configure mail delivery first'
				);
			}
			if (params.id === ADMIN_BUCKET_ID) {
				await assertAdminBucketChange(ctx, bucket, changes);
			}
			/*
			 * After every refusal, so a preview is never offered for a change that would be refused anyway; and
			 * before the audit entry, so nothing is recorded for a change that was only described.
			 */
			const preview = await signInPreview(bucket, changes);
			if (preview) {
				if (confirm !== true) {
					return status(409, {
						confirmationRequired: true as const,
						...preview
					});
				}
				/*
				 * The consent is to the counts shown. Somebody who registered, or lost a link, while the preview
				 * was open is not covered by it, so the change is refused with the fresh one.
				 */
				if (!sameExpect(expect, preview.expect)) {
					return status(409, {
						error: 'admin_error' as const,
						message:
							expect === undefined
								? 'confirm with the counts of the preview you reviewed (expect)'
								: 'what this change affects changed since you reviewed it',
						...preview,
						confirmationRequired: true as const
					});
				}
			}
			/*
			 * Recorded whatever the request changed. This used to fire only for a registration or
			 * verification field, so renaming a bucket or reassigning its managers left no trace at all
			 * — while still being an exercised privilege over who can administer a bucket's users.
			 */
			await recordAdminAudit(ctx, 'bucket.update', params.id, {
				attributes: Object.keys(changes),
				ownerGroupId: bucket.ownerGroupId
			});
			const updated = await getBucketStore().update(params.id, changes);
			if (!updated) throw new AdminError(404, 'bucket not found');
			const presented = withInertTotpAdvisory(presentBucket(updated));
			const advisory =
				params.id === ADMIN_BUCKET_ID
					? adminBucketAdvisory(updated)
					: undefined;
			return { ...presented, ...(advisory ? { advisory } : {}) };
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
			const ctx = assertAuth(admin);

			/*
			 * Loaded as its settings are, so a caller who is not a super administrator gets the same refusal
			 * for a bucket that does not exist as for one they cannot read, and walking ids reveals nothing.
			 *
			 * Then the stated right, decided from the bucket as it is now (specs/081): a super administrator
			 * may change any bucket's address but the two served at the root — the console authenticates
			 * against the instance's own issuer, so moving the administrators bucket would lock every
			 * operator out of the surface that could move it back — and an owner of its group may change a
			 * path while nothing is integrated with it. Anything integrated breaks on the next request, so
			 * once something is, the change is instance-level.
			 */
			const bucket = await loadBucketForSettings(ctx, params.id, 'read');
			const facts = await bucketFacts(ctx, bucket);
			if (!bucketCan(ctx, bucket, NO_PROJECT_REACH, facts).changeAddress) {
				throw new AdminError(403, addressRefusal(ctx, bucket, facts));
			}
			/*
			 * A hostname reaches into the operator's domain, so naming one stays an instance-level act whatever
			 * the bucket's state — the right above is per bucket, not per target. Decided before the hostname
			 * is judged, so a caller without the right is not told whether the name they tried is free.
			 */
			if (body.host !== undefined && !meCan(ctx).createHost) {
				throw new AdminError(
					403,
					'only an administrator of this instance may give a bucket a hostname of its own'
				);
			}

			const address = await resolveAddress(body);

			/*
			 * What will break, named before anything changes. An operator who has not seen this list has
			 * not been told what the change costs, which is why the write refuses without `confirm`.
			 */
			const preview = await addressChangePreview(bucket, address);

			if (body.confirm !== true) {
				set.status = 409;
				return { ...preview, confirmationRequired: true };
			}
			/*
			 * The confirmation is of what was previewed. A project, provider or connection that arrived since
			 * would be broken by a consent given before it existed, so the commit is refused with the fresh
			 * preview — and for an owner, that is also the moment the change becomes an instance
			 * administrator's, which the next attempt's right check states.
			 */
			if (!sameCounts(body.expect, preview.expect)) {
				set.status = 409;
				return {
					error: 'admin_error' as const,
					message:
						body.expect === undefined
							? 'confirm with the counts of the preview you reviewed (expect)'
							: 'what this address change reaches changed since you reviewed it',
					...preview,
					confirmationRequired: true
				};
			}

			/*
			 * A legacy bucket gaining its first address leaves the shared root namespace for one of its own,
			 * and its projects' declarations have to come with it or they would stop resolving. A bucket
			 * that already had an address keeps its namespace, which is keyed by id, not by address.
			 */
			const moves: Array<{ projectId: string; plan: MovePlan }> = [];
			if (namespaceOf(bucket) === ROOT_NAMESPACE) {
				const to = namespaceOf({ ...bucket, ...address });
				const inBucket = (await getProjectStore().list()).filter(
					(project) => project.bucketId === params.id
				);
				for (const project of inBucket) {
					moves.push({
						projectId: project._id,
						plan: await planMove(ctx, project._id, ROOT_NAMESPACE, to)
					});
				}
			}

			await recordAdminAudit(ctx, 'bucket.address.change', params.id, {
				from: bucket.host ?? bucket.slug ?? null,
				to: address.host ?? address.slug ?? null,
				/* So the owning group reads the change in its own trail, not only a super administrator. */
				ownerGroupId: bucket.ownerGroupId
			});
			for (const { projectId, plan } of moves) {
				await applyMove(projectId, plan);
			}
			/*
			 * A legacy bucket gaining its first address becomes an issuer, and gets its key with it. A
			 * bucket that already had one keeps its keys: they are keyed by id, and a new issuer string for
			 * the same tenant is still that tenant.
			 */
			if (namespaceOf(bucket) === ROOT_NAMESPACE) {
				await ensureBucketKey(params.id);
			}

			const moved = await refusingATakenHostname(() =>
				getBucketStore().setAddress(params.id, address)
			);
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
	/*
	 * Moving a bucket, with every project using it, to another administrator group (specs/075).
	 *
	 * The bucket and its projects move as one, because two things compare their owners: consent is waived
	 * only where a client's project and the bucket it signs into share a group, and a project's group may
	 * administer the end users of the bucket it uses. Splitting them would change both without anyone
	 * deciding to.
	 *
	 * Taking a bucket away removes every other member's access to it, so the caller must own the group it
	 * leaves. Belonging to the destination is enough: any member may already create a bucket there.
	 */
	.put(
		'/admin/api/buckets/:id/owner',
		async ({ admin, params, body, set }) => {
			const ctx = assertAuth(admin);
			/*
			 * Before the bucket is loaded, as for an address change and a deletion. The administrators' bucket
			 * belongs to no tenant, and the default bucket is where every tenant's bucket-less project signs
			 * in: handing it to one group would hand that group everybody else's end users.
			 */
			if (isUndeletableBucket(params.id)) {
				throw new AdminError(
					403,
					'this bucket is part of the server itself and cannot be moved'
				);
			}
			const bucket = await loadBucketForEdit(ctx, params.id);
			/*
			 * The right before anything about the destination or the projects using the bucket, so a member
			 * who may not move it is told that rather than which group it would have left.
			 */
			if (!bucketCan(ctx, bucket, await projectReach(ctx)).move) {
				throw new AdminError(403, 'group owner required');
			}
			const destination = await loadDestination(ctx, body.groupId);
			const bound = (await getProjectStore().list()).filter(
				(project) => project.bucketId === bucket._id
			);
			const from = sourceGroupOf(
				[bucket.ownerGroupId, ...bound.map((project) => project.ownerGroupId)],
				destination._id
			);
			assertGroupOwner(ctx, from);

			const moving = bound.filter((project) => project.ownerGroupId === from);
			if (body.confirm !== true) {
				set.status = 409;
				return {
					confirmationRequired: true as const,
					from: await describeGroup(from),
					to: await describeGroup(destination._id),
					bucket: { id: bucket._id, name: bucket.name },
					projects: moving.map((project) => ({
						id: project._id,
						name: project.name
					})),
					consequence:
						'the bucket and these projects will be administered by the members of the destination group, and no longer by members of the source group only; end users, clients and sign-in addresses are not affected'
				};
			}

			await recordAdminAudit(ctx, 'bucket.owner.change', bucket._id, {
				ownerGroupId: destination._id,
				formerOwnerGroupId: from,
				attributes: ['ownerGroupId'],
				cascade: { projects: moving.length }
			});
			const result = await getContainerOwnershipStore().moveBucket(
				bucket._id,
				from,
				destination._id
			);
			if (result.status === 'conflict') {
				throw new AdminError(
					409,
					'the bucket changed while it was being moved; reload and try again'
				);
			}
			const names = new Map(
				bound.map((project) => [project._id, project.name])
			);
			return {
				bucket: { id: bucket._id, ownerGroupId: destination._id },
				projects: result.projectIds.map((id) => ({
					id,
					name: names.get(id) ?? id
				}))
			};
		},
		{ body: MoveBucketOwnerBody }
	)
	.delete(
		'/admin/api/buckets/:id',
		async ({ admin, params, query }) => {
			const ctx = assertAuth(admin);
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
			/*
			 * Loaded as its settings are, so a caller who is not a super administrator cannot tell a missing
			 * bucket from one they may not read.
			 */
			const bucket = await loadBucketForSettings(ctx, params.id, 'read');
			const store = getUserStore(params.id);
			/*
			 * Counted before the right is decided, because the right depends on it (specs/081): deleting a
			 * bucket that holds accounts deletes people, which is an owner's act, while an empty bucket stays
			 * deletable by any member of its group. Counted by the datastore, not by reading every account.
			 */
			const held = (await store.tally()).total;
			if (
				!bucketCan(ctx, bucket, NO_PROJECT_REACH, { accounts: held }).delete
			) {
				throw new AdminError(
					403,
					held > 0 && holdsBucket(ctx, bucket)
						? `This bucket holds ${countOf(held, 'account')}: only an owner of its group can delete it.`
						: 'no access to this bucket'
				);
			}
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
			const accounts = await store.list();
			/* An account that arrived since the count still counts: the right is decided over what is destroyed. */
			if (
				!bucketCan(ctx, bucket, NO_PROJECT_REACH, {
					accounts: accounts.length
				}).delete
			) {
				throw new AdminError(
					403,
					`This bucket holds ${countOf(accounts.length, 'account')}: only an owner of its group can delete it.`
				);
			}
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
					: {}),
				/* So the group that owned it reads the deletion in its own trail. */
				ownerGroupId: bucket.ownerGroupId
			});

			/*
			 * The email is read before the row goes, per account, because the email-scoped areas are
			 * addressed by `${bucketId}:${email}` and nothing else records it. Destroy first and those
			 * records are unreachable — skipped in silence, with no error anywhere to notice. The
			 * already-computed id in `cascadeForAccount`'s signature is what makes that ordering
			 * impossible to get wrong here.
			 */
			/*
			 * The bucket's usage history is kept (specs/076, FR-011): its tombstone first, before anything is
			 * destroyed, because without it a deleted bucket's figures could never be listed again — no loader
			 * finds the bucket once it is gone. If it cannot be written the deletion does not begin, which is
			 * the one moment refusing is clean; a repeated request finds the tombstone and proceeds. The open
			 * month and day are frozen in the same call, best effort — the closer catches up.
			 *
			 * Neither activity area is swept below, deliberately: they hold evidence of how many people used
			 * the bucket, and deleting the bucket must not erase it.
			 *
			 * The owner goes on the tombstone too (specs/077): the usage overview names a deleted bucket's
			 * customer from it once the group itself may be gone. A group cannot be deleted while it owns a
			 * bucket, so it is found here; if it somehow is not, its id stands in for its name rather than the
			 * deletion being refused over a label.
			 */
			try {
				const owner = await getGroupStore().find(bucket.ownerGroupId);
				await getActivityStore().retire(
					{
						_id: bucket._id,
						name: bucket.name,
						...(bucket.slug === undefined ? {} : { slug: bucket.slug }),
						createdAt: bucket.createdAt
					},
					{
						groupId: bucket.ownerGroupId,
						label: owner ? groupLabel(owner) : bucket.ownerGroupId
					},
					now()
				);
			} catch (error) {
				console.error("activity: could not keep a deleted bucket's history", {
					bucketId: params.id,
					error
				});
				throw new AdminError(
					500,
					"the bucket's usage history could not be kept; nothing was deleted"
				);
			}

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
			/*
			 * Its keys go with it. They sign for an issuer that no longer exists, and leaving the private
			 * halves behind would keep key material nobody can manage any more.
			 */
			await getBucketKeysStore().destroyByBucket(params.id);
			invalidateBucketKeys(params.id);
			/*
			 * Its SCIM provisioning connections go too, and every token they obtained with them: a token
			 * outliving its bucket would fail at the SCIM principal anyway, but a customer's directory should
			 * see its credential refused at the token endpoint, not answered with a token for nothing.
			 */
			for (const swept of await destroyConnectionsOf(params.id)) {
				failedAreas.push(...swept.failedAreas);
			}
			/* Its groups and every membership in them; nothing outside the bucket refers to either. */
			await getBucketGroupStore().destroyByBucket(params.id);
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
