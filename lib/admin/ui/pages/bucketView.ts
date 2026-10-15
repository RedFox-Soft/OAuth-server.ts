import type { UserBucket } from '../../../adapters/types.js';
import type { BucketBlockers, BucketCan } from '../frame/can.js';

/*
 * The project as the API presents it (specs/081 data-model §1): the stored record under its edge names
 * (specs/100: the owning team is `ownerTeamId`, never the stored `ownerGroupId`) plus what the server derives
 * for the console — the address form, the issuer and discovery addresses (the browser bundle never learns the
 * server's own address), how many applications and APIs it holds, and for a host, whether requests have
 * arrived.
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
	addressForm?: 'root' | 'path' | 'host' | 'unaddressed';
	issuer?: string | null;
	discoveryUrl?: string | null;
	/* What it holds besides its people (specs/099). */
	applications?: number;
	apis?: number;
	address?: {
		host: string;
		requestsArrived: boolean;
		firstArrivalAt?: string;
		lastArrivalAt?: string;
		dnsRecord: { name: string; type: string; value: string };
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
