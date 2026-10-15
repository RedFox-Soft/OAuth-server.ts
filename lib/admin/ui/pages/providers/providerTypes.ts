import type { FederationProvider } from '../../../../federation/types.js';

/* A provider as the list presents it: the address to paste into its logout settings rides along when it applies. */
export type PresentedProvider = FederationProvider & {
	globalTokenRevocationEndpoint?: string;
	backChannelLogoutEndpoint?: string;
};

/*
 * One provider as its page reads it (specs/084 R1): the settings, plus what the page needs to explain them,
 * all from the server — the callback the bucket uses, which logout signals this provider can send at all and
 * whether the instance accepts them, the directory bound to it, and how many people sign in through it.
 */
export type ProviderDetail = PresentedProvider & {
	callbackUri: string;
	callbackStability: 'stable' | 'provisional';
	recognised: string | null;
	logoutSignals: { globalTokenRevocation: boolean; backChannelLogout: boolean };
	capabilities: {
		globalTokenRevocation: boolean;
		backChannelLogout: boolean;
		/* Try sign-in needs the callback route, which exists only while federation is on (specs/088). */
		trySignIn: boolean;
	};
	boundConnection: { id: string; displayName: string } | null;
	linkedUsers: number;
	recommendedCorrelation: {
		claim: string;
		attribute: 'externalId' | 'userName';
	};
	warnings: string[];
};

/*
 * What the server says it takes to connect a recognised provider to this bucket.
 *
 * This replaced a browser-side map of form prefills. The prefills were honest about having no runtime
 * effect, but they were a second copy of facts the server now holds — and a copy only the console could
 * read, so an agent got none of it. Everything below is fetched, including the one value nobody can guess.
 */
export interface Guidance {
	catalogueId: string;
	displayName: string;
	consoleUrl: string;
	steps: string[];
	credentialLabels: { clientId: string; clientSecret: string };
	/* Every value this provider asks for, in its own wording. Two for some, four for others. */
	requiredValues: {
		name: string;
		label: string;
		secret: boolean;
		hint: string;
	}[];
	/* A question that must be answered before those values mean anything. Only one provider asks one. */
	choices: {
		name: string;
		question: string;
		options: { value: string | null; label: string; consequence: string }[];
	}[];
	clientIdHint: string;
	callbackUri: string;
	callbackStability: 'stable' | 'provisional';
	javascriptOrigins: string[];
	alreadyConnected: boolean;
	existingProviderId?: string;
}

export function federationApi(bucketId: string, providerId?: string): string {
	const base = `/admin/api/projects/${encodeURIComponent(bucketId)}/federation`;
	return providerId === undefined
		? base
		: `${base}/${encodeURIComponent(providerId)}`;
}

/*
 * Whether turning this provider off — or deleting it — would leave the bucket with no way in: no password
 * sign-in and no other enabled provider. The server refuses it either way; asked here so the control says
 * why before anyone presses it. The console's own bucket has a stricter guard the server alone applies.
 */
export function isLastDoor(
	bucket: {
		passwordLogin?: boolean;
		federation?: { id: string; enabled: boolean }[];
	},
	providerId: string
): boolean {
	if (bucket.passwordLogin !== false) return false;
	return !(bucket.federation ?? []).some(
		(p) => p.enabled && p.id !== providerId
	);
}
