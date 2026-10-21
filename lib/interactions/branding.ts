import { getBucketStore } from '../adapters/index.js';
import { ISSUER } from '../configs/env.js';
import { shownNameOf } from '../configs/issuer.js';
import type { UserBucket } from '../adapters/types.js';
import { isLoopbackRedirect } from '../client_metadata_document/identifier.js';
import { Client, clientProvenance } from '../models/client.js';
import type { ProvenanceTier } from '../models/client/provenance.js';
import type { Interaction } from '../models/interaction.js';
import { readLogo } from '../models/client/logo.js';
import { sanitiseClientName } from './clientName.js';
import type { SignInFace } from './signInMasthead.js';
import {
	paintedAccent,
	readPrimaryColor,
	type PaintedAccent
} from '../html/theme/accent.js';

export interface SignInBranding {
	tier: ProvenanceTier;
	// Whether the client's own logo and colour may be shown on this sign-in's pages.
	showsBranding: boolean;
	accent?: PaintedAccent;
}

/*
 * Whether an application may look like itself on the pages of one sign-in (specs/106) — its colour on every
 * page, its logo on the consent page. Decided once per sign-in from facts, never per page from whichever
 * warning a page happens to show: login and two-step pages show no warnings at all, and on the consent page
 * the administrator-rights warning outranks the device and own-device ones, so a test on the shown warning let
 * a logo onto a device-flow consent.
 *
 *  - this-organization only: anyone can register an app and call it anything, so a face is shown only for an
 *    app an administrator of the bucket being signed into stands behind (specs/094).
 *  - never in a device flow: a familiar face is what makes a phished device code convincing.
 *  - never for an app whose redirects all stay on the person's own computer: the answer goes to whatever
 *    program listens there, which the face would vouch for.
 */
export async function brandingFor(
	client: Client | undefined,
	bucket: Pick<UserBucket, '_id'> | null | undefined,
	interaction: Interaction
): Promise<SignInBranding> {
	if (!client) return { tier: 'self-registered', showsBranding: false };
	const tier = await clientProvenance(client, bucket);
	const loopbackOnly =
		client.redirectUris.length > 0 &&
		client.redirectUris.every(isLoopbackRedirect);
	const showsBranding =
		tier === 'this-organization' &&
		!interaction.payload.deviceCode &&
		!loopbackOnly;
	const colour = showsBranding
		? readPrimaryColor(client.primaryColor)
		: undefined;
	const accent = colour ? paintedAccent(colour) : undefined;
	return { tier, showsBranding, ...(accent ? { accent } : {}) };
}

/*
 * How a page of this sign-in looks and what it says it leads to, for a page that has not already read the
 * client and the bucket. The application is named under the rule that decides its colour, and for the same
 * reason: a name on a sign-in page is a claim the page makes for the app, and these pages carry no warning that
 * could qualify it. Anyone can register "Acme Payroll"; only the project's own administrators can make the page
 * say "Sign in to Acme Payroll".
 */
export async function signInLook(
	interaction: Interaction,
	signsInto: string
): Promise<{ accent?: PaintedAccent; face: SignInFace }> {
	const clientId = interaction.payload.params?.client_id;
	const client = clientId ? await Client.tryFind(clientId) : undefined;
	const bucket = await getBucketStore().find(signsInto);
	const { showsBranding, accent } = await brandingFor(
		client,
		bucket,
		interaction
	);
	const name = showsBranding
		? sanitiseClientName(client?.clientName)
		: undefined;
	const logo = name && clientId ? await readLogo(clientId) : undefined;
	return {
		...(accent ? { accent } : {}),
		face: {
			service: bucket ? shownNameOf(bucket) : new URL(ISSUER).host,
			...(name ? { app: { name, ...(logo ? { logo } : {}) } } : {})
		}
	};
}
