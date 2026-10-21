import type { UserBucket } from '../../../adapters/types.js';
import type { BucketBlockers, BucketCan } from '../frame/can.js';
import type { AddressFormChoice } from '../frame/me.js';
import type { PlanView } from '../planText.js';

/* What a person reads for each address form a project can be given, in the dialogs that offer them (specs/101). */
export const ADDRESS_FORM_CHOICE: Record<AddressFormChoice, string> = {
	subdomain: 'Subdomain',
	path: 'Path',
	host: 'Hostname of its own'
};

/*
 * The project as the API presents it (specs/081 data-model §1): the stored record under its edge names
 * (specs/100: the owning team is `ownerTeamId`, never the stored `ownerGroupId`) plus what the server derives
 * for the console — the address form, the issuer and discovery addresses (derived on the server, whose scheme
 * and paths the browser bundle does not know), how many applications and APIs it holds, and for an origin of
 * its own, whether requests have arrived.
 */
export interface BucketView extends Omit<
	UserBucket,
	'deletion' | 'ownerGroupId'
> {
	ownerTeamId: string;
	reserved?: 'administrators';
	/* Present while the project is scheduled for deletion (specs/090); dates arrive as ISO strings. */
	deletion?: BucketDeletionView;
	can?: Partial<BucketCan>;
	blockers?: Partial<
		BucketBlockers & {
			dependents: {
				applications: number;
				providers: number;
				connections: number;
			} | null;
			accounts: number | null;
		}
	>;
	addressForm?: 'root' | 'path' | 'subdomain' | 'host' | 'unaddressed';
	issuer?: string | null;
	discoveryUrl?: string | null;
	/* What its sign-in pages call it: the display name, else the host people sign in at. */
	shownName?: string;
	/* What it holds besides its people (specs/099). */
	applications?: number;
	apis?: number;
	/* How agent hosts get a client identity here (spec 107). */
	agentClients?: {
		urlClientIds: boolean;
		selfRegistration: 'open' | 'token' | 'off';
	};
	/* Whether this instance runs token exchange and the JWT bearer grant (specs/108). */
	assertionGrants?: { tokenExchange: boolean; jwtBearer: boolean };
	address?: {
		host: string;
		requestsArrived: boolean;
		firstArrivalAt?: string;
		lastArrivalAt?: string;
		/*
		 * `shared` marks the instance's wildcard record, which covers every subdomain project at once, as
		 * opposed to the record a hostname of its own needs (specs/101).
		 */
		dnsRecord: { name: string; type: string; value: string; shared?: boolean };
		stillToDo?: string;
	};
}

export interface BucketDeletionView {
	scheduledAt: string;
	purgeAt: string;
	scheduledBy?: { userId: string; email?: string };
}

/* GET /admin/api/projects/:id/summary (data-model §3). */
export interface BucketSummary {
	users: number;
	unverified: number;
	withoutAuthenticator: number;
	withoutLinkedIdentity: number;
	/* No link to an enabled identity provider: who passwords off would leave without a way in (specs/083). */
	withoutEnabledLink: number;
	/* Signs in with a password and holds no authenticator: who an authenticator requirement would ask. */
	passwordWithoutAuthenticator: number;
	applications?: number;
	apis?: number;
	groups: number;
	connections: number;
	held: number;
	providers: { enabled: number; creating: number };
	activeThisMonth?: number;
	mailDeliveryConfigured: boolean;
	/* The instance's `federation.enabled`: the preview's one input the console cannot read elsewhere (specs/091). */
	federationEnabled: boolean;
	/*
	 * The project's plan (specs/102): null for a System project, absent for a tenant while plans are off. A super
	 * administrator always reads it, and is never held to it.
	 */
	plan?: PlanView | null;
}

/* The address change's preview (data-model §6). */
export interface AddressPreview {
	from: string;
	to: string;
	applications: { clientId: string; name: string | null }[];
	connections: { id: string; displayName: string }[];
	providers: { id: string; displayName: string; newCallback: string }[];
	resources: { identifier: string; name: string }[];
	namespaceMove: boolean;
	expect: {
		applications: number;
		connections: number;
		providers: number;
		resources: number;
	};
	consequence: string;
}
