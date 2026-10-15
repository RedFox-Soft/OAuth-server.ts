import { Elysia } from 'elysia';
import {
	getBucketStore,
	getBucketGroupStore,
	getContainerOwnershipStore,
	getGroupStore,
	getProtectedResourceStore,
	getProvisioningConnectionStore,
	getUserStore
} from '../../adapters/index.js';
import {
	assertAuth,
	assertActiveGroup,
	assertGroupOwner,
	AdminError,
	adminErrorBody,
	resolveAdmin,
	type AdminContext
} from '../auth/rbac.js';
import {
	bucketCan,
	bucketFactsWanted,
	holdsBucket,
	meCan,
	type AddressFormChoice,
	type BucketCan,
	type BucketDependents,
	type BucketFacts
} from '../auth/can.js';
import type { BucketAddressWrite, UserBucket } from '../../adapters/types.js';
import { isUniqueValueTaken } from '../../adapters/conflicts.js';
import { presentAll } from '../federation/service.js';
import {
	ADMIN_BUCKET_ID,
	UNASSIGNED_GROUP_ID,
	isUndeletableBucket,
	reservedOf
} from '../consts.js';
import { recordAdminAudit } from '../audit/record.js';
import nanoid from '../../helpers/nanoid.js';
import { ensureBucketKey } from '../../keys/issuer_keys.js';
import { purgeAtOf } from '../../consts/bucket_deletion.js';
import { destroyBucket } from './destroy.js';
import { scheduledForDeletion } from './scheduled_guard.js';
import { namespaceOf, ROOT_NAMESPACE } from '../../resources/namespace.js';
import {
	applyMove,
	DeclarationsConflict,
	planMove,
	type MovePlan
} from '../resources/move.js';
import { loadBucketForSettings, loadBucketForEdit } from './access.js';
import { visibleBuckets } from './visible.js';
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
import {
	hasEncodedLabelShape,
	isReservedBucketName,
	isReservedSubdomainLabel
} from '../../consts/reserved_names.js';
import {
	canonicalHostOf,
	normaliseHost,
	subdomainLabelOf,
	validateBucketHost
} from '../../consts/request_host.js';
import { ApplicationConfig } from '../../configs/application.js';
import { ISSUER } from '../../configs/env.js';
import { now } from '../../activity/clock.js';
import { monthOf } from '../../activity/periods.js';
import { readPeriod } from '../../activity/read.js';
import { bucketClients } from '../../plans/usage.js';
import { SLUG_DRAWS, drawSlug } from '../../plans/slug.js';
import { catalogue, planOf } from '../../plans/catalogue.js';
import {
	assertProjectRoom,
	mayNameSlug,
	newProjectPlan,
	refuseNamedSlug
} from '../../plans/enforce.js';
import { addressOf, hasOwnOrigin, issuerFor } from '../../configs/issuer.js';
import { callbackUri } from '../../federation/flow.js';
import { mailDeliveryConfigured } from '../../mail/mailer.js';
import { listClientView } from '../clients/service.js';
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
import { planViewOf, plansShownTo } from '../../plans/view.js';

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
/*
 * A display name as stored: trimmed, and refused when nothing is left — an end user's page headed by
 * whitespace names nothing. `null` (cleared) passes through for the update route to remove the field.
 */
function acceptedDisplayName(
	value: string | null | undefined
): string | null | undefined {
	if (value === undefined || value === null) return value;
	const trimmed = value.trim();
	if (!trimmed) {
		throw new AdminError(400, 'the name shown to users cannot be blank', {
			field: 'displayName'
		});
	}
	return trimmed;
}

async function assertSlugAvailable(slug: string) {
	if (isReservedBucketName(slug)) {
		throw new AdminError(
			409,
			`'${slug}' is reserved for this server's own addresses and cannot be a project slug`,
			{ field: 'slug' }
		);
	}
	if (await getBucketStore().findBySlug(slug)) {
		throw new AdminError(409, `slug '${slug}' is already taken`, {
			field: 'slug'
		});
	}
}

/* The host a project subdomain sits beneath (specs/101): `acme` is served at `acme.<this>`. */
const INSTANCE_HOST = canonicalHostOf(ISSUER);

interface AddressBody {
	slug?: string;
	host?: string;
	addressForm?: 'path' | 'subdomain';
}

/*
 * Exactly one form, never both and never neither. Refused rather than resolved by precedence: a rule that
 * silently prefers the slug is a rule nobody reads, and the operator who supplied a hostname would believe it
 * took effect while their bucket answered somewhere else entirely. Judged before the right to the form, so a
 * malformed body is told what is malformed rather than what it may not choose.
 */
function assertOneForm(body: AddressBody): void {
	if (body.slug !== undefined && body.host !== undefined) {
		throw new AdminError(
			400,
			'a project is addressed by a path segment or a hostname, not both — supply one'
		);
	}
	if (body.slug === undefined && body.host === undefined) {
		throw new AdminError(
			400,
			'a project needs an address: supply a slug or a hostname'
		);
	}
	if (body.host !== undefined && body.addressForm !== undefined) {
		throw new AdminError(
			400,
			'a hostname is a form of its own; addressForm goes with a slug',
			{ field: 'addressForm' }
		);
	}
}

/* The form a body asks for. A slug with no form is a path, whatever the setting (specs/101 FR-025). */
function requestedForm(body: AddressBody): AddressFormChoice {
	if (body.host !== undefined) return 'host';
	return body.addressForm ?? 'path';
}

/*
 * Whether this caller may give a project this form. Decided before any name is judged, so a caller without
 * the right is refused for that and not told whether the name they tried is free.
 *
 * Naming a hostname is an instance-level act, never a team's: it would put a name in the operator's own domain
 * under the team's control. Between path and subdomain the operator decides, through `projects.addressForms`.
 */
function assertMayChooseForm(ctx: AdminContext, form: AddressFormChoice): void {
	const allowed = meCan(ctx).addressForms;
	if (allowed.includes(form)) return;
	if (form === 'host') {
		throw new AdminError(
			403,
			'only an administrator of this instance may give a project a hostname of its own'
		);
	}
	const only = allowed.includes('subdomain') ? 'a subdomain' : 'a path';
	throw new AdminError(
		403,
		`this instance lets teams address a project by ${only} only (projects.addressForms); an administrator of this instance can give it another form`,
		{ field: 'addressForm' }
	);
}

/*
 * The address a bucket is being given, judged before anything is written. `keeping` is the bucket being moved,
 * whose own slug is not "taken" when it moves between path and subdomain under the same name.
 */
async function resolveAddress(
	body: AddressBody,
	keeping?: UserBucket
): Promise<BucketAddressWrite> {
	if (body.host !== undefined) {
		return { host: await assertHostAvailable(body.host, keeping?._id) };
	}
	const slug = body.slug as string;
	const subdomain = body.addressForm === 'subdomain';
	if (keeping?.slug === slug) {
		if (Boolean(keeping.subdomain) === subdomain) {
			throw new AdminError(409, 'this project already has that address', {
				field: 'slug'
			});
		}
	} else {
		await assertSlugAvailable(slug);
	}
	if (!subdomain) return { slug };
	await assertSubdomainAvailable(slug, keeping?._id);
	return { slug, subdomain: true };
}

/*
 * A generated name is judged by every rule a named one is — reserved, taken, a colliding subdomain — and drawn again
 * when one refuses it (specs/102).
 */
async function generatedAddress(
	body: AddressBody
): Promise<BucketAddressWrite> {
	for (let draw = 0; draw < SLUG_DRAWS; draw += 1) {
		try {
			return await resolveAddress({ ...body, slug: drawSlug() });
		} catch (error) {
			if (error instanceof AdminError && error.field === 'slug') continue;
			throw error;
		}
	}
	throw new AdminError(
		500,
		'no free address name could be drawn for the project'
	);
}

/*
 * What a slug must also be to serve as a subdomain of this instance (specs/101). Every refusal names the rule
 * it broke. Asked of every caller, super administrators included: these protect names in the operator's own
 * domain, not a team's quota.
 */
async function assertSubdomainAvailable(
	slug: string,
	exceptId?: string
): Promise<void> {
	if (INSTANCE_HOST === null) {
		throw new AdminError(
			409,
			"this instance's address has no host a project subdomain can sit beneath",
			{ field: 'addressForm' }
		);
	}
	if (isReservedSubdomainLabel(slug)) {
		throw new AdminError(
			409,
			`'${slug}' is reserved for this deployment's own services and cannot be a project subdomain`,
			{ field: 'slug' }
		);
	}
	if (hasEncodedLabelShape(slug)) {
		throw new AdminError(
			400,
			`'${slug}' cannot be a subdomain: a label with '--' as its third and fourth characters may be shown by browsers as other characters`,
			{ field: 'slug' }
		);
	}
	const name = `${slug}.${INSTANCE_HOST}`;
	if (
		ApplicationConfig['projects.reservedHostnames'].some(
			(reserved) => normaliseHost(reserved) === name
		)
	) {
		throw new AdminError(
			409,
			`'${name}' is reserved for this deployment and cannot be a project's address`,
			{ field: 'slug' }
		);
	}
	/*
	 * A hostname given before subdomains existed may already be this name. It keeps it: the resolver asks for
	 * hostnames first, so the name has one holder either way, and refusing here says so instead of creating a
	 * project that would never answer.
	 */
	const holder = await getBucketStore().findByHost(name);
	if (holder && holder._id !== exceptId) {
		throw new AdminError(
			409,
			`'${name}' is already the address of the project '${holder.name}'`,
			{ field: 'slug' }
		);
	}
}

/*
 * What the hostname's shape rules cannot check: that this name is this deployment's to give, and free.
 *
 * Every refusal names the rule it broke, for the reason `assertSlugAvailable` states about reserved
 * slugs — an operator who typed the deployment's own hostname has no way to guess the rule otherwise.
 */
async function assertHostAvailable(
	value: string,
	exceptId?: string
): Promise<string> {
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
			`'${host}' is this deployment's own address and cannot be a project's`,
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
		ApplicationConfig['projects.reservedHostnames'].some(
			(reserved) => normaliseHost(reserved) === host
		)
	) {
		throw new AdminError(
			409,
			`'${host}' is reserved for this deployment and cannot be a project's address`,
			{ field: 'host' }
		);
	}
	const holder = await getBucketStore().findByHost(host);
	if (holder && holder._id !== exceptId) {
		throw new AdminError(
			409,
			`hostname '${host}' is already taken by the project '${holder.name}'`,
			{ field: 'host' }
		);
	}
	/*
	 * A name one label beneath this instance is the subdomain a slug would take (specs/101): a slug and
	 * `<slug>.<instance host>` are one name, so a hostname may not claim a slug another project holds — in
	 * whichever form, because a path project can move to its subdomain later.
	 */
	const label = subdomainLabelOf(host, INSTANCE_HOST);
	if (label !== null) {
		const slugHolder = await getBucketStore().findBySlug(label);
		if (slugHolder && slugHolder._id !== exceptId) {
			throw new AdminError(
				409,
				`'${host}' is the subdomain of the project '${slugHolder.name}'`,
				{ field: 'host' }
			);
		}
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
async function refusingATakenName<T>(write: () => Promise<T>): Promise<T> {
	try {
		return await write();
	} catch (error) {
		if (isUniqueValueTaken(error)) {
			const slug = error.field === 'slug';
			throw new AdminError(
				409,
				`${slug ? 'slug' : 'hostname'} '${error.value}' is already taken`,
				{ field: slug ? 'slug' : 'host' }
			);
		}
		throw error;
	}
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
	applications: { clientId: string; name: string | null }[];
	connections: { id: string; displayName: string }[];
	providers: { id: string; displayName: string; newCallback: string }[];
	resources: { identifier: string; name: string }[];
	namespaceMove: boolean;
	expect: AddressChangeCounts;
	consequence: string;
}

/*
 * Everything an address change reaches, named before the change (specs/081 FR-013).
 *
 * Named rather than counted, because "14 clients" tells an operator nothing they can act on: each
 * application is what they take to whoever owns it, each identity provider with the callback address its
 * upstream registration must be given, each provisioning connection whose directory must be re-pointed, and
 * each declared resource whose tokens will carry the new issuer.
 */
async function addressChangePreview(
	bucket: UserBucket,
	address: BucketAddressWrite
): Promise<AddressChangePreview> {
	const target = { _id: bucket._id, ...address };
	const applications: AddressChangePreview['applications'] = [];
	for (const { clientId } of await bucketClients(bucket._id)) {
		const view = await listClientView(clientId);
		applications.push({ clientId, name: view?.clientName ?? null });
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
		await getProtectedResourceStore().listByBucket(bucket._id)
	).map((resource) => ({
		identifier: resource.identifier,
		name: resource.name
	}));

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

/* Every application counts here, a self-registered one included: its integration breaks like any other. */
async function dependentsOf(
	bucket: Pick<UserBucket, '_id' | 'federation'>
): Promise<BucketDependents> {
	const [applications, connections] = await Promise.all([
		bucketClients(bucket._id),
		getProvisioningConnectionStore().listByBucket(bucket._id)
	]);
	return {
		applications: applications.length,
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
		return 'this project is served at the root and its address cannot be changed';
	}
	const dependents = facts.dependents;
	if (
		dependents &&
		dependents.applications + dependents.providers + dependents.connections > 0
	) {
		return `Used by ${countOf(dependents.applications, 'application')}, ${countOf(dependents.providers, 'identity provider')} and ${countOf(dependents.connections, 'provisioning connection')}: only an instance administrator can change this project's address now.`;
	}
	if (bucketFactsWanted(ctx, bucket).dependents || ctx.superAdmin) {
		return 'this project address cannot be changed';
	}
	return addressOf(bucket).kind === 'host'
		? 'only an administrator of this instance may change the address of a project served at its own hostname'
		: "only an owner of the project's team or an administrator of this instance may change a project address";
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
 * whole. So `GET /admin/api/projects` handed every provider secret to any authenticated administrator, and
 * `GET /admin/api/projects/:id` handed a bucket's secrets to anyone with the broader
 * `loadBucketForUsers` access, not only the bucket's editors.
 *
 * Found by the MCP surface's secrecy sweep (test/mcp/secrecy.spec.ts), which is why that sweep iterates
 * every published read rather than the ones somebody thought to check.
 */
function presentBucket<
	T extends Pick<UserBucket, '_id' | 'federation' | 'deletion' | 'ownerGroupId'>
>(
	bucket: T
): Omit<T, 'ownerGroupId'> & {
	ownerTeamId: string;
	reserved?: 'administrators';
} {
	/*
	 * The console's own bucket says so on the response, so the console and an agent learn it from what
	 * they were sent rather than by knowing the id.
	 */
	const marked =
		reservedOf(bucket._id) === 'administrators'
			? { ...bucket, reserved: 'administrators' as const }
			: bucket;
	/* The edge calls the owning group a team (specs/100); storage keeps `ownerGroupId`. */
	const { ownerGroupId, ...shown } = withoutPurgeClaim(marked);
	const project = { ...shown, ownerTeamId: ownerGroupId };
	if (!project.federation.length) return project;
	return { ...project, federation: presentAll(bucket) };
}

/*
 * A scheduled bucket says when it stops and when it goes (specs/090 FR-031); how far a destruction has got is
 * the destruction's own bookkeeping, and nobody reading the bucket acts on it.
 */
function withoutPurgeClaim<T extends Pick<UserBucket, 'deletion'>>(
	bucket: T
): T {
	if (!bucket.deletion?.purge) return bucket;
	const { purge: _purge, ...deletion } = bucket.deletion;
	return { ...bucket, deletion };
}

/*
 * The caller's rights on a bucket, and the state that would refuse a right they hold — so the console hides
 * what it may not do and disables, with the reason, what it may do but not yet.
 */
function withRights<
	T extends Pick<UserBucket, '_id' | 'ownerGroupId' | 'slug' | 'host'>
>(
	ctx: AdminContext,
	bucket: T,
	state: BucketFacts
): T & {
	can: BucketCan;
	blockers: {
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
		can: bucketCan(ctx, bucket, state),
		blockers: {
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
	T extends Pick<
		UserBucket,
		'_id' | 'slug' | 'host' | 'subdomain' | 'hostFirstSeenAt' | 'hostLastSeenAt'
	>
>(bucket: T): T | (T & { address: Record<string, unknown> }) {
	if (!hasOwnOrigin(bucket)) return bucket;
	const host = new URL(issuerFor(bucket)).hostname;
	/*
	 * A subdomain is covered by the instance's one wildcard record and certificate (specs/101), so the record
	 * named is that one, marked shared: creating a record per project would be wrong advice.
	 */
	const shared = addressOf(bucket).kind === 'subdomain';
	return {
		...bucket,
		address: {
			host,
			requestsArrived: bucket.hostLastSeenAt !== undefined,
			firstArrivalAt: bucket.hostFirstSeenAt ?? null,
			lastArrivalAt: bucket.hostLastSeenAt ?? null,
			/*
			 * Named concretely rather than described. "Point this name at the deployment" sends an operator
			 * to look something up; a record they can copy does not.
			 */
			dnsRecord: {
				name: shared ? `*.${INSTANCE_HOST ?? ''}` : host,
				type: 'CNAME',
				value: new URL(ISSUER).hostname,
				shared
			},
			stillToDo: shared
				? bucket.hostLastSeenAt === undefined
					? "No request has reached this subdomain yet. It is served through this instance's wildcard DNS record and wildcard TLS certificate, which the operator sets up once for every project; until both exist, this address cannot be reached."
					: "This subdomain is served through this instance's wildcard DNS record and wildcard TLS certificate; nothing is needed for this project alone."
				: bucket.hostLastSeenAt === undefined
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

/* One bucket as `GET /admin/api/projects/:id` answers it, and as a restore answers with what it brought back. */
async function bucketDetail(ctx: AdminContext, bucket: UserBucket) {
	const [state, applications, apis] = await Promise.all([
		bucketFacts(ctx, bucket),
		bucketClients(bucket._id),
		getProtectedResourceStore().listByBucket(bucket._id)
	]);
	return {
		...withAddressGuidance(presentBucket(withRights(ctx, bucket, state))),
		/*
		 * Sent by the server because the console cannot derive it: ISSUER is kept out of the browser
		 * bundle (lib/configs/issuer.ts).
		 */
		...addressing(bucket),
		/* What a change to this bucket's sign-in reaches: its applications and the APIs they call. */
		applications: applications.length,
		apis: apis.length
	};
}

/*
 * The checks a deletion has always applied, in their order and with their messages (specs/090 FR-002),
 * shared by scheduling a deletion and by Delete now, which applies them again over the bucket as it is then
 * (FR-021). `scheduled` is the state the operation needs the bucket in, judged after the right — so a caller
 * without the right is refused for that, as the stated rights say, and not told the bucket's state.
 */
async function deletionChecked(
	ctx: AdminContext,
	id: string,
	query: { cascade?: 'endusers'; expect?: number },
	scheduled: boolean
): Promise<{ bucket: UserBucket; accounts: number }> {
	/*
	 * First, before the bucket is even loaded, so the answer cannot depend on whether it happens to be
	 * empty or on who is asking. This route does not go through `loadBucketForEdit`, which is where
	 * `assertNotReserved` lives, so until 051 it reached no reserved-bucket guard at all and an empty
	 * administrators' or default bucket was deletable by a super administrator.
	 */
	if (isUndeletableBucket(id)) {
		throw new AdminError(
			403,
			'this project is part of the server itself and cannot be deleted'
		);
	}
	/*
	 * Loaded as its settings are, so a caller who is not a super administrator cannot tell a missing
	 * bucket from one they may not read.
	 */
	const bucket = await loadBucketForSettings(ctx, id, 'read');
	const store = getUserStore(id);
	/*
	 * Counted before the right is decided, because the right depends on it (specs/081): deleting a
	 * bucket that holds accounts deletes people, which is an owner's act, while an empty bucket stays
	 * deletable by any member of its group. Counted by the datastore, not by reading every account.
	 */
	const held = (await store.tally()).total;
	if (!bucketCan(ctx, bucket, { accounts: held }).delete) {
		throw new AdminError(
			403,
			held > 0 && holdsBucket(ctx, bucket)
				? `This project holds ${countOf(held, 'account')}: only an owner of its team can delete it.`
				: 'no access to this project'
		);
	}
	if (scheduled && !bucket.deletion) {
		throw new AdminError(409, 'This project is not scheduled for deletion.');
	}
	/* Only by a race: the scheduled-bucket guard refuses a reader before the handler runs. */
	if (!scheduled && bucket.deletion) {
		throw scheduledForDeletion(bucket.deletion.purgeAt);
	}
	/*
	 * Before the election is even considered, and unclearable by it. An application an administrator
	 * registered here, or an API declared here, is somebody's integration: it is removed on purpose, one by
	 * one, never as a side effect of the people in the bucket going. A self-registered application blocks
	 * nothing — nobody here vouched for it (specs/099).
	 */
	const [applications, apis] = await Promise.all([
		bucketClients(id, true),
		getProtectedResourceStore().listByBucket(id)
	]);
	if (applications.length > 0 || apis.length > 0) {
		throw new AdminError(409, 'project still holds applications or APIs', {
			blockers: [
				...(applications.length > 0
					? [
							{
								kind: 'client' as const,
								count: applications.length,
								ids: applications.map((client) => client.clientId)
							}
						]
					: []),
				...(apis.length > 0
					? [{ kind: 'resource' as const, count: apis.length }]
					: [])
			]
		});
	}
	/*
	 * `list()` does not filter, which is what makes a deactivated account count — deactivation is
	 * a sign-in decision, not absence, and the account is still there to be destroyed. Only the
	 * count is reported and only a count is accepted back: a bucket can hold thousands of
	 * accounts, their identifiers are not the caller's business, and an administrator is not
	 * asked to decide about people by name.
	 */
	const accounts = (await store.list()).length;
	/* An account that arrived since the count still counts: the right is decided over what is destroyed. */
	if (!bucketCan(ctx, bucket, { accounts }).delete) {
		throw new AdminError(
			403,
			`This project holds ${countOf(accounts, 'account')}: only an owner of its team can delete it.`
		);
	}
	if (accounts > 0) {
		if (query.cascade === undefined) {
			throw new AdminError(409, 'project still holds end-users', {
				blockers: [{ kind: 'enduser', count: accounts }]
			});
		}
		if (query.expect !== accounts) {
			throw new AdminError(
				409,
				'the project end-users changed since you reviewed them',
				{ blockers: [{ kind: 'enduser', count: accounts }] }
			);
		}
	}
	return { bucket, accounts };
}

/* Whether a destruction holds the bucket now — a restore or a second Delete now would race it. */
function destructionUnderway(bucket: UserBucket, at: Date): boolean {
	const until = bucket.deletion?.purge?.claimedUntil;
	return until !== undefined && until.getTime() >= at.getTime();
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
	.get('/admin/api/projects', async ({ admin }) => {
		const ctx = assertAuth(admin);
		/* The same set the held-connections count is taken over (lib/admin/buckets/visible.ts). */
		const listed = await visibleBuckets(ctx);
		const [holding, states] = await Promise.all([
			getProvisioningConnectionStore().listHeld(),
			Promise.all(listed.map((b) => bucketFacts(ctx, b)))
		]);
		/* One held connection per bucket is enough to link to; the oldest hold, so the link is stable. */
		const heldIn = new Map<string, string>();
		for (const connection of [...holding].sort(
			(a, b) => a.hold.since.getTime() - b.hold.since.getTime()
		)) {
			if (!heldIn.has(connection.bucketId)) {
				heldIn.set(connection.bucketId, connection._id);
			}
		}
		return listed.map((b, i) => {
			const heldConnectionId = heldIn.get(b._id);
			const { addressForm, issuer } = addressing(b);
			return {
				...presentBucket(withRights(ctx, b, states[i] ?? {})),
				addressForm,
				issuer,
				/*
				 * An arrival is the one fact this server can observe about a hostname; a host nobody has
				 * reached is the row an operator has still to finish setting up.
				 */
				hostReached: hasOwnOrigin(b) && b.hostLastSeenAt !== undefined,
				held: heldConnectionId !== undefined,
				/* The held connection an "On hold" mark links to (specs/088 US5). */
				...(heldConnectionId ? { heldConnectionId } : {})
			};
		});
	})
	.post(
		'/admin/api/projects',
		async ({ admin, body, set }) => {
			const ctx = assertAuth(admin);
			/*
			 * No role gate: the authority is membership of the group the bucket will belong to — the active
			 * group, or one the caller names (specs/087), held to the rules a move into it is held to.
			 */
			const ownerGroupId =
				body.teamId === undefined
					? assertActiveGroup(ctx)
					: (await loadDestination(ctx, body.teamId))._id;
			/*
			 * The plan the project will be on (specs/102): the default, recorded at creation whether or not plans
			 * are enforced, so that making another plan the default later moves no existing project. A project of
			 * the System team has none.
			 */
			const plan =
				ownerGroupId === UNASSIGNED_GROUP_ID ? null : await newProjectPlan();
			const generated = !mayNameSlug(ctx, plan);
			if (generated && body.slug !== undefined && plan) refuseNamedSlug(plan);
			if (!generated || body.host !== undefined) assertOneForm(body);
			assertMayChooseForm(ctx, requestedForm(body));
			if (plan) {
				const group = await getGroupStore().find(ownerGroupId);
				if (group) {
					await assertProjectRoom(ctx, group, {
						ownerGroupId,
						planId: plan.id
					});
				}
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
			const address =
				generated && body.host === undefined
					? await generatedAddress(body)
					: await resolveAddress(body);
			const displayName = acceptedDisplayName(body.displayName) ?? undefined;
			// The id is allocated here, not by the store, so the audit entry can name the bucket that is
			// about to exist — audit-first has nothing to point at otherwise.
			const bucketId = nanoid();
			await recordAdminAudit(ctx, 'bucket.create', bucketId, { ownerGroupId });
			const bucket = await refusingATakenName(() =>
				getBucketStore().create({
					_id: bucketId,
					name: body.name,
					...(displayName ? { displayName } : {}),
					...address,
					ownerGroupId,
					...(plan ? { planId: plan.id } : {}),
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
	.get('/admin/api/projects/:id', async ({ admin, params }) => {
		const ctx = assertAuth(admin);
		const bucket = await loadBucketForSettings(ctx, params.id, 'read');
		return bucketDetail(ctx, bucket);
	})
	/*
	 * What a bucket's overview counts (specs/081 FR-018): computed per request and never stored. Governed by
	 * `read`, as the bucket itself is; the active-user figure only with `readActivity`, the right that
	 * governs the activity page it summarises.
	 */
	.get('/admin/api/projects/:id/summary', async ({ admin, params }) => {
		const ctx = assertAuth(admin);
		const bucket = await loadBucketForSettings(ctx, params.id, 'read');
		const readsActivity = bucketCan(ctx, bucket).readActivity;
		const [counts, groups, connections, mail, figure, applications, apis] =
			await Promise.all([
				signInCounts(bucket),
				getBucketGroupStore().query(
					{ bucketId: bucket._id },
					{ startIndex: 1, count: 0 }
				),
				getProvisioningConnectionStore().listByBucket(bucket._id),
				mailDeliveryConfigured(),
				readsActivity ? readPeriod(bucket._id, monthOf(now())) : null,
				bucketClients(bucket._id),
				getProtectedResourceStore().listByBucket(bucket._id)
			]);
		const enabled = bucket.federation.filter((provider) => provider.enabled);
		/* The project's plan, its use and its warnings (specs/102); null for a System project, which has none. */
		const plan = plansShownTo(ctx)
			? { plan: await planViewOf(bucket, figure?.total ?? null) }
			: {};
		return {
			...plan,
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
			applications: applications.length,
			apis: apis.length,
			groups: groups.totalResults,
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
			mailDeliveryConfigured: mail,
			/*
			 * Whether any provider button can appear on any sign-in page of this instance. The Sign-in tab's preview
			 * (specs/091) draws the page with the same rule the server renders it with, and this is the one input
			 * of that rule a browser cannot otherwise know.
			 */
			federationEnabled: ApplicationConfig['federation.enabled']
		};
	})
	.patch(
		'/admin/api/projects/:id',
		async ({ admin, params, body, status }) => {
			const ctx = assertAuth(admin);
			const bucket = await loadBucketForSettings(ctx, params.id, 'edit');
			const { confirm, expect, displayName, ...rest } = body;
			/*
			 * Present with no value when the request cleared it, so the store removes the field rather than
			 * leaving the old name in place.
			 */
			const changes =
				displayName === undefined
					? rest
					: {
							...rest,
							displayName: acceptedDisplayName(displayName) ?? undefined
						};
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
			if (!updated) throw new AdminError(404, 'project not found');
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
		'/admin/api/projects/:id/address',
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
			if (!bucketCan(ctx, bucket, facts).changeAddress) {
				throw new AdminError(403, addressRefusal(ctx, bucket, facts));
			}
			/*
			 * The right above is per bucket; which form it may move to is per target. A hostname stays an
			 * instance-level act whatever the bucket's state, and between path and subdomain the operator
			 * decides through `projects.addressForms` (specs/101).
			 */
			assertOneForm(body);
			assertMayChooseForm(ctx, requestedForm(body));

			/*
			 * On a plan without a custom slug the name stays the one the project was given; moving between path and
			 * subdomain under it is still the team's to do (specs/102).
			 */
			if (body.slug !== undefined && body.slug !== bucket.slug) {
				const plan = planOf(bucket, await catalogue());
				if (plan && !mayNameSlug(ctx, plan)) refuseNamedSlug(plan);
			}
			const address = await resolveAddress(body, bucket);

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
			 * The confirmation is of what was previewed. An application, provider or connection that arrived since
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
			 * and its declarations have to come with it or they would stop resolving. A bucket that already
			 * had an address keeps its namespace, which is keyed by id, not by address.
			 */
			const move: MovePlan | null =
				namespaceOf(bucket) === ROOT_NAMESPACE
					? await planMove(
							ctx,
							params.id,
							ROOT_NAMESPACE,
							namespaceOf({ ...bucket, ...address })
						)
					: null;

			/*
			 * Whole issuers, not names: a path `acme` and a subdomain `acme` carry the same slug, and an entry
			 * recording only the name could not tell a move between them from no move at all (specs/101).
			 */
			await recordAdminAudit(ctx, 'bucket.address.change', params.id, {
				from: preview.from,
				to: preview.to,
				/* So the owning group reads the change in its own trail, not only a super administrator. */
				ownerGroupId: bucket.ownerGroupId
			});
			if (move) await applyMove(params.id, move);
			/*
			 * A legacy bucket gaining its first address becomes an issuer, and gets its key with it. A
			 * bucket that already had one keeps its keys: they are keyed by id, and a new issuer string for
			 * the same tenant is still that tenant.
			 */
			if (namespaceOf(bucket) === ROOT_NAMESPACE) {
				await ensureBucketKey(params.id);
			}

			const moved = await refusingATakenName(() =>
				getBucketStore().setAddress(params.id, address)
			);
			if (!moved) throw new AdminError(404, 'project not found');

			/*
			 * The one place this operation can leave a bucket answering at its old address. The resolver
			 * caches by both forms, and a stale entry there is exactly the second issuer identifier the
			 * move exists to avoid.
			 */
			forgetBucketAddresses();
			return { ...preview, moved: true, project: presentBucket(moved) };
		},
		{ body: ChangeBucketAddressBody }
	)
	/*
	 * Moving a bucket, with everything it holds, to another administrator group (specs/075). Its
	 * applications and APIs belong to it by reference, so they follow with no write of their own and no
	 * state in which part of a bucket is in one group and part in another (specs/099).
	 *
	 * Taking a bucket away removes every other member's access to it, so the caller must own the group it
	 * leaves. Belonging to the destination is enough: any member may already create a bucket there.
	 */
	.put(
		'/admin/api/projects/:id/owner',
		async ({ admin, params, body, set }) => {
			const ctx = assertAuth(admin);
			/*
			 * Before the bucket is loaded, as for an address change and a deletion. The administrators' bucket
			 * belongs to no tenant, and the default bucket is the instance's own: handing it to one group would
			 * hand that group everybody else's end users.
			 */
			if (isUndeletableBucket(params.id)) {
				throw new AdminError(
					403,
					'this project is part of the server itself and cannot be moved'
				);
			}
			const bucket = await loadBucketForEdit(ctx, params.id);
			/*
			 * The right before anything about the destination, so a member who may not move it is told that
			 * rather than which group it would have left.
			 */
			if (!bucketCan(ctx, bucket).move) {
				throw new AdminError(403, 'team owner required');
			}
			const destination = await loadDestination(ctx, body.teamId);
			const from = sourceGroupOf([bucket.ownerGroupId], destination._id);
			assertGroupOwner(ctx, from);
			/* Before the preview, so a move the plan would refuse is never offered for confirmation (specs/102). */
			await assertProjectRoom(ctx, destination, bucket);

			const [applications, apis] = await Promise.all([
				bucketClients(bucket._id, true),
				getProtectedResourceStore().listByBucket(bucket._id)
			]);
			if (body.confirm !== true) {
				set.status = 409;
				return {
					confirmationRequired: true as const,
					from: await describeGroup(from),
					to: await describeGroup(destination._id),
					project: { id: bucket._id, name: bucket.name },
					applications: applications.length,
					apis: apis.length,
					consequence:
						'the project, with its applications and APIs, will be administered by the members of the destination team, and no longer by members of the source team; end users, clients and sign-in addresses are not affected'
				};
			}

			await recordAdminAudit(ctx, 'bucket.owner.change', bucket._id, {
				ownerGroupId: destination._id,
				formerOwnerGroupId: from,
				attributes: ['ownerGroupId'],
				cascade: { applications: applications.length, apis: apis.length }
			});
			const result = await getContainerOwnershipStore().moveBucket(
				bucket._id,
				from,
				destination._id
			);
			if (result.status === 'conflict') {
				throw new AdminError(
					409,
					'the project changed while it was being moved; reload and try again'
				);
			}
			/*
			 * A System-team project carries no plan; leaving that team it is put on the default, as a new project
			 * is, so every project outside it records one (specs/102).
			 */
			if (
				bucket.planId === undefined &&
				destination._id !== UNASSIGNED_GROUP_ID
			) {
				await getBucketStore().setPlan(bucket._id, (await newProjectPlan()).id);
			}
			return { project: { id: bucket._id, ownerTeamId: destination._id } };
		},
		{ body: MoveBucketOwnerBody }
	)
	/*
	 * Deleting a bucket schedules its destruction thirty days out (specs/090), and changes nothing inside it:
	 * every door answers as though the bucket did not exist, every session and token stays stored, and a
	 * restore puts it back exactly as it was. The destruction itself is the purge route's, or the hourly
	 * pass's when the date comes (lib/admin/buckets/destroy.ts).
	 *
	 * Every check a deletion applied when it destroyed at once still applies here, in the same order and with
	 * the same messages, because the destruction this schedules runs later with nobody there to ask.
	 */
	.delete(
		'/admin/api/projects/:id',
		async ({ admin, params, query }) => {
			const ctx = assertAuth(admin);
			const { bucket, accounts } = await deletionChecked(
				ctx,
				params.id,
				query,
				false
			);
			const scheduledAt = now();
			const purgeAt = purgeAtOf(scheduledAt);

			/*
			 * One entry carrying a count, never one per account, for the reason the destruction gives; with the
			 * date the bucket will be destroyed, so the trail says what this deletion set in motion. After the
			 * guards and before the change, by the trail's own contract.
			 */
			await recordAdminAudit(ctx, 'bucket.delete', params.id, {
				...(accounts > 0 ? { cascade: { endusers: accounts } } : {}),
				/* So the group that owned it reads the deletion in its own trail. */
				ownerGroupId: bucket.ownerGroupId,
				purgeAt
			});
			const scheduled = await getBucketStore().scheduleDeletion(params.id, {
				scheduledAt,
				purgeAt,
				scheduledBy: { userId: ctx.userId, email: ctx.email }
			});
			if (!scheduled?.deletion) {
				const current = await getBucketStore().find(params.id);
				throw current?.deletion
					? scheduledForDeletion(current.deletion.purgeAt)
					: new AdminError(404, 'project not found');
			}
			/* Every door at its address closes now on this instance; the address caches' minute bounds the rest. */
			forgetBucketAddresses();
			return {
				scheduled: {
					scheduledAt: scheduled.deletion.scheduledAt,
					purgeAt: scheduled.deletion.purgeAt
				}
			};
		},
		{ query: DeleteBucketQuery }
	)
	/*
	 * Restoring a scheduled bucket (specs/090 US2): it answers again as it did, with every session and token
	 * still unexpired valid again. The right to restore is the right to delete, over the accounts it holds
	 * now (FR-014). A directory that tried to provision while it was off may need a resync; nothing here can
	 * replay what it was refused.
	 */
	.post('/admin/api/projects/:id/restore', async ({ admin, params }) => {
		const ctx = assertAuth(admin);
		const bucket = await loadBucketForSettings(ctx, params.id, 'read');
		const held = (await getUserStore(params.id).tally()).total;
		if (!bucketCan(ctx, bucket, { accounts: held }).delete) {
			throw new AdminError(
				403,
				held > 0 && holdsBucket(ctx, bucket)
					? `This project holds ${countOf(held, 'account')}: only an owner of its team can restore it.`
					: 'no access to this project'
			);
		}
		/* Before the audit entry, so a restore that changes nothing is not recorded (FR-015). */
		if (!bucket.deletion) {
			throw new AdminError(409, 'This project is not scheduled for deletion.');
		}
		if (destructionUnderway(bucket, now())) {
			throw new AdminError(409, 'This project is already being deleted.');
		}
		/* A scheduled project counts toward nobody until it is back (specs/102). */
		const team = await getGroupStore().find(bucket.ownerGroupId);
		if (team) await assertProjectRoom(ctx, team, bucket);
		await recordAdminAudit(ctx, 'bucket.restore', params.id, {
			ownerGroupId: bucket.ownerGroupId,
			/* The schedule this restore cancelled. */
			scheduledAt: bucket.deletion.scheduledAt
		});
		/* The store decides the race with a destruction that began since the read above. */
		const restored = await getBucketStore().cancelDeletion(params.id, now());
		if (!restored) {
			throw new AdminError(409, 'This project is already being deleted.');
		}
		forgetBucketAddresses();
		return bucketDetail(ctx, restored);
	})
	/*
	 * Delete now (specs/090 US4): destroys a scheduled bucket at once rather than at its date, by the procedure
	 * the hourly pass runs. The deletion's checks are applied again, over what the bucket holds now — the
	 * consent to destroy people is to the count reviewed, and the right depends on it.
	 */
	.post(
		'/admin/api/projects/:id/purge',
		async ({ admin, params, query }) => {
			const ctx = assertAuth(admin);
			const { bucket } = await deletionChecked(ctx, params.id, query, true);
			if (destructionUnderway(bucket, now())) {
				throw new AdminError(409, 'This project is already being deleted.');
			}
			const outcome = await destroyBucket(
				bucket,
				{ kind: 'admin', ctx },
				{ due: false }
			);
			if (!outcome.claimed) {
				const current = await getBucketStore().find(params.id);
				if (!current) throw new AdminError(404, 'project not found');
				throw new AdminError(
					409,
					current.deletion
						? 'This project is already being deleted.'
						: 'This project is not scheduled for deletion.'
				);
			}
			if (outcome.failedAreas.length > 0) {
				throw new AdminError(
					500,
					`project deleted, but records of its end-users survive in: ${outcome.failedAreas.join(', ')}`,
					{ failedAreas: outcome.failedAreas }
				);
			}
			return { ok: true, endUsersDestroyed: outcome.endUsersDestroyed };
		},
		{ query: DeleteBucketQuery }
	);
