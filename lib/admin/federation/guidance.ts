import { callbackUri } from '../../federation/flow.js';
import { isServedAtTheRoot } from '../consts.js';
import {
	KNOWN_PROVIDERS,
	matchesKnownProvider
} from '../../consts/known_providers.js';
import type { KnownProvider } from '../../consts/known_providers.js';
import type { UserBucket } from '../../adapters/types.js';

/*
 * What an administrator has to do, and supply, to connect a recognised provider to *this* bucket.
 *
 * The whole reason this exists is one field. Everything else here is catalogue text that could have been
 * printed in a manual; `callbackUri` could not, because it depends on whether the bucket is served at the
 * root and on the slug an operator chose. It has never been shown anywhere in the console, and registering
 * it wrongly is the single most common way a federated sign-in fails — on the upstream's own page, to an
 * end user, leaving no trace on this server at all.
 *
 * Nothing here is secret and nothing here is a configured provider, which is what lets this be published
 * to an agent without raising the secrecy question at all.
 */

export type CallbackStability = 'stable' | 'provisional';

export interface ProviderGuidance {
	catalogueId: string;
	displayName: string;
	consoleUrl: string;
	steps: string[];
	credentialLabels: { clientId: string; clientSecret: string };
	/*
	 * Every value this provider in particular asks for, in the order an administrator meets them — two for
	 * Google and GitHub, three for Microsoft, four for Apple. Published rather than implied so that neither
	 * the console nor an agent has to know anything about a named provider to ask for the right things.
	 */
	requiredValues: {
		name: string;
		label: string;
		secret: boolean;
		hint: string;
	}[];
	/*
	 * A question that has to be answered before the values make sense. Only one provider has one, and it is
	 * not a preference: the answer decides whether the button admits one company's staff or everyone in the
	 * world with an account there, so each option states its consequence and none is marked as a default.
	 */
	choices: {
		name: string;
		question: string;
		options: { value: string | null; label: string; consequence: string }[];
	}[];
	clientIdHint: string;
	callbackUri: string;
	callbackStability: CallbackStability;
	/*
	 * Empty, always, and present rather than omitted: the upstream's own form asks for them, so guidance
	 * that said nothing would leave an administrator guessing at a field this server does not use. Saying
	 * "leave it empty" is the answer; saying nothing is not.
	 */
	javascriptOrigins: string[];
	alreadyConnected: boolean;
	existingProviderId?: string;
}

type GuidanceBucket = Pick<UserBucket, '_id' | 'slug' | 'federation'>;

/*
 * `provisional` is not a nicety. `issuerFor` falls back to the bucket's record id when a non-root bucket
 * has no slug, so the address derived here is real, registerable — and silently invalidated the moment an
 * operator assigns a slug. That failure surfaces weeks later as a redirect_uri_mismatch on the upstream's
 * page, with nothing on this server to connect it to the slug that caused it. The only moment the warning
 * is useful is the moment the address is copied.
 */
function stabilityOf(bucket: GuidanceBucket): CallbackStability {
	if (isServedAtTheRoot(bucket._id)) return 'stable';
	return bucket.slug ? 'stable' : 'provisional';
}

/*
 * The two labels the console's existing credential fields read, derived from the one list rather than held
 * beside it. A provider that issues neither — Apple issues no client secret — yields an empty label, and
 * the console renders its fields from `requiredValues` instead.
 */
function credentialLabelsOf(entry: KnownProvider): {
	clientId: string;
	clientSecret: string;
} {
	const labelFor = (name: 'clientId' | 'clientSecret'): string =>
		entry.requiredValues.find((value) => value.name === name)?.label ?? '';
	return {
		clientId: labelFor('clientId'),
		clientSecret: labelFor('clientSecret')
	};
}

function guidanceFor(
	entry: KnownProvider,
	bucket: GuidanceBucket
): ProviderGuidance {
	/*
	 * Resolved fresh from the stored issuer, so a provider configured by hand is recognised on equal terms.
	 * Through the entry's own rule rather than by string equality, because one entry's issuer contains the
	 * organisation and so differs per deployment.
	 */
	const existing = (bucket.federation ?? []).find((provider) =>
		matchesKnownProvider(entry, provider.issuer)
	);

	return {
		catalogueId: entry.catalogueId,
		displayName: entry.displayName,
		consoleUrl: entry.consoleUrl,
		steps: [...entry.steps],
		credentialLabels: credentialLabelsOf(entry),
		requiredValues: entry.requiredValues.map((value) => ({ ...value })),
		choices: entry.choices.map((choice) => ({
			...choice,
			options: choice.options.map((option) => ({ ...option }))
		})),
		clientIdHint: entry.clientIdHint,
		callbackUri: callbackUri(bucket),
		callbackStability: stabilityOf(bucket),
		javascriptOrigins: [],
		alreadyConnected: Boolean(existing),
		...(existing ? { existingProviderId: existing.id } : {})
	};
}

export function guidanceForBucket(bucket: GuidanceBucket): ProviderGuidance[] {
	return KNOWN_PROVIDERS.map((entry) => guidanceFor(entry, bucket));
}
