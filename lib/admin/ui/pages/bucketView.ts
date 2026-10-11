import type { UserBucket } from '../../../adapters/types.js';
import type { BucketBlockers, BucketCan } from '../frame/can.js';

/*
 * The bucket as the API presents it (specs/081 data-model §1): the stored record plus what the server derives
 * for the console — the address form, the issuer and discovery addresses (the browser bundle never learns the
 * server's own address), the projects using it, and for a host, whether requests have arrived.
 */
export interface BucketView extends UserBucket {
	reserved?: 'administrators';
	can?: Partial<BucketCan>;
	blockers?: Partial<
		BucketBlockers & {
			dependents: {
				projects: number;
				providers: number;
				connections: number;
			} | null;
			accounts: number | null;
		}
	>;
	addressForm?: 'root' | 'path' | 'host' | 'unaddressed';
	issuer?: string | null;
	discoveryUrl?: string | null;
	projects?: { id: string; name: string; clientCount: number }[];
	address?: {
		host: string;
		requestsArrived: boolean;
		firstArrivalAt?: string;
		lastArrivalAt?: string;
		dnsRecord: { name: string; type: string; value: string };
		stillToDo?: string;
	};
}

/* GET /admin/api/buckets/:id/summary (data-model §3). */
export interface BucketSummary {
	users: number;
	unverified: number;
	withoutAuthenticator: number;
	withoutLinkedIdentity: number;
	userGroups: number;
	connections: number;
	held: number;
	providers: { enabled: number; creating: number };
	activeThisMonth?: number;
	mailDeliveryConfigured: boolean;
}

/* The address change's preview (data-model §6). */
export interface AddressPreview {
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
	expect: {
		applications: number;
		connections: number;
		providers: number;
		resources: number;
	};
	consequence: string;
}
