/*
 * The identity providers this server recognises by name, and everything about connecting one that is the
 * same for every deployment.
 *
 * DATA, NOT BEHAVIOUR. Nothing here is a branch. A connection made through an entry stores exactly the
 * fields a hand-configured one stores, nothing records which route created it, and no sign-in decision can
 * therefore depend on it — which is Principle II ("behavioural differences MUST be driven by configuration
 * or adapter, never by conditional branches in business logic") satisfied by construction rather than by
 * review. The console's old PRESETS map made the same promise in a comment; this module makes it
 * unfalsifiable by having no runtime reachable from a provider's identity.
 *
 * The entries differ from one another in four ways that a fifth provider will differ in too, and each is
 * therefore stated as a field rather than discovered by a reader: which protocol the provider speaks, how
 * the credential presented to it is produced, how the user comes back, and which values the administrator
 * has to supply. `specs/053-apple-microsoft-github` added all four; before it the answers were the same
 * for the only entry and so were implicit.
 *
 * IMPORT-FREE, and that is load-bearing rather than tidy. `lib/interactions/loginPage.tsx` resolves a
 * provider's mark through this module, and that component is bundled into `public/loginClient.js` and runs
 * in a browser. An import reaching `lib/adapters/` would pull a datastore module — which, on MongoDB,
 * connects at module scope — into a browser bundle. Same rule as `lib/consts/storage_inventory.ts`, for a
 * different reason.
 */

/*
 * How a stored provider is recognised as this entry, and what issuer a new connection stores.
 *
 * `fixed` is the ordinary case. `templated` exists because Microsoft's issuer contains the organisation, so
 * no single string can equal every deployment's — and because the metadata Microsoft publishes for its
 * multi-organisation endpoints states the issuer as the literal placeholder `{tenantid}` rather than a URL.
 * An entry declaring `templated` is therefore saying two things at once: match me by pattern, and do not
 * expect my published issuer to equal the one configured. Both are consequences of the same fact, which is
 * why they are one field and not two.
 */
export type IssuerRule =
	| { readonly kind: 'fixed'; readonly issuer: string }
	| {
			readonly kind: 'templated';
			/* Carries a single `{tenant}` placeholder, substituted from the stored provider. */
			readonly template: string;
			readonly pattern: RegExp;
	  };

/*
 * Which protocol the provider speaks.
 *
 * `profile_api` names a reader rather than carrying one, so this module still holds no behaviour: the
 * readers live in `lib/federation/identity/` and are selected by a lookup on this name. A provider of this
 * kind publishes no metadata document, so its endpoints cannot be discovered and are stated here.
 */
export type ProviderProtocol =
	| { readonly kind: 'oidc' }
	| {
			readonly kind: 'profile_api';
			readonly authorizationEndpoint: string;
			readonly tokenEndpoint: string;
			readonly reader: 'github';
	  };

/*
 * How the credential this server presents to the provider is produced.
 *
 * `signed_assertion` is Apple's, and it is the reason this is a field at all: Apple issues no client
 * secret. It issues a signing key, from which a short-lived assertion is derived — and it rejects one
 * valid for more than `maxLifetimeSeconds`. Storing a derived value would therefore be storing something
 * that expires, which is an outage scheduled for a date nobody records.
 */
export type CredentialModel =
	| { readonly kind: 'secret' }
	| {
			readonly kind: 'signed_assertion';
			readonly audience: string;
			readonly algorithm: 'ES256';
			readonly maxLifetimeSeconds: number;
	  };

/*
 * Whether the provider is known to support binding the authorization code to the request that asked for it.
 *
 * Stated as data because **the published metadata under-reports it**: of the four entries here, three
 * support the binding and only one advertises a method for it. `unknown` is not a placeholder for research
 * nobody did — it is a real third state, and it means "send nothing", because a provider that rejects
 * parameters it does not recognise fails sign-in for all its users. A missing binding is a weakness; a
 * rejected authorization request is a total outage.
 */
export type CodeBinding = 'S256' | 'unknown';

/* Which stored field a value the administrator supplies ends up in. */
export type SuppliedValueName =
	'clientId' | 'clientSecret' | 'tenant' | 'teamId' | 'keyId' | 'signingKey';

export interface RequiredValue {
	readonly name: SuppliedValueName;
	/*
	 * What the provider itself calls this on its own screen. Deliberately the provider's wording and not
	 * ours: an administrator reading our name for a value while looking at theirs is translating, and that
	 * is where a secret gets pasted into an identifier field.
	 */
	readonly label: string;
	/* Whether it must never be read back. Drives the masking, so it is declared rather than inferred. */
	readonly secret: boolean;
	readonly hint: string;
}

/*
 * A question the administrator must answer before the values make sense.
 *
 * Only Microsoft has one, and it is not a preference: the answer decides whether the button admits one
 * company's staff or everyone in the world with an account there. `value: null` means the administrator
 * supplies the value themselves rather than picking a constant.
 */
export interface ProviderChoice {
	readonly name: SuppliedValueName;
	readonly question: string;
	readonly options: readonly {
		readonly value: string | null;
		readonly label: string;
		readonly consequence: string;
	}[];
}

export interface KnownProvider {
	/* What a create body names to connect this provider, and the key the login page's mark is looked up by. */
	readonly catalogueId: string;
	/* The slug the stored provider gets unless the caller names another. */
	readonly defaultProviderId: string;
	readonly displayName: string;
	/*
	 * The button's wording, fixed by the provider's own branding requirements and deliberately NOT read
	 * from `displayName` — an administrator may rename a provider to anything, and a branded button whose
	 * text an operator can edit is one that stops complying the first time somebody does.
	 */
	readonly buttonText: string;
	/*
	 * Also how a stored provider is recognised. Matching on the issuer rather than on a stored "came from
	 * the catalogue" flag is what lets a provider configured by hand years ago render with its mark, and is
	 * why this feature needs no migration.
	 */
	readonly issuerRule: IssuerRule;
	readonly protocol: ProviderProtocol;
	readonly credential: CredentialModel;
	/*
	 * How the user comes back. Apple's `form_post` is not a preference: it refuses the authorization
	 * request outright when an address or a name is asked for and the return is anything else.
	 */
	readonly returnMode: 'query' | 'form_post';
	readonly codeBinding: CodeBinding;
	readonly scopes: readonly string[];
	readonly emailClaim: string;
	/*
	 * Where the provider offers a second field that sometimes carries an address, in preference order after
	 * `emailClaim`. Empty for a provider that always answers in one place. A value found here is used only
	 * if it is actually an address — Microsoft documents that its fallback field "could be an email
	 * address, phone number, or a generic username".
	 */
	readonly fallbackEmailClaims: readonly string[];
	/*
	 * Which claim names the organisation an assertion came from, where the provider issues assertions for
	 * more than one from a single endpoint. Undefined for a provider that serves one population, for which
	 * the issuer already answers the question.
	 *
	 * This is what actually enforces a connection restricted to one organisation. The issuer cannot — for
	 * precisely the reason such an entry is templated — so without this the restriction would be advisory.
	 */
	readonly organisationClaim?: string;
	readonly emailTrusted: boolean;
	/*
	 * Suffix-shaped on purpose. It exists to catch the paste-into-the-wrong-box mistake — an API key, a
	 * project id, or the client *secret* — not to model the provider's internal identifier format. A
	 * pattern tight enough to reject a future issuance format would be a refusal an administrator can
	 * neither work around nor diagnose.
	 */
	readonly clientIdPattern: RegExp;
	/*
	 * What a correct one looks like, in an administrator's words. A refusal that only says "wrong" leaves
	 * somebody staring at four values on another company's screen with no way to tell which is which.
	 */
	readonly clientIdHint: string;
	readonly consoleUrl: string;
	/* In the order the provider's own screens present them. */
	readonly steps: readonly string[];
	/*
	 * Every value the administrator must supply, in the order they will meet them. This is the single
	 * source for what a connection asks for: two values for Google and GitHub, three for Microsoft, four
	 * for Apple. The console and the agent both read it, so neither has to know anything about a particular
	 * provider to ask for the right things.
	 */
	readonly requiredValues: readonly RequiredValue[];
	readonly choices: readonly ProviderChoice[];
}

const GOOGLE: KnownProvider = {
	catalogueId: 'google',
	defaultProviderId: 'google',
	displayName: 'Google',
	buttonText: 'Sign in with Google',
	issuerRule: { kind: 'fixed', issuer: 'https://accounts.google.com' },
	protocol: { kind: 'oidc' },
	credential: { kind: 'secret' },
	returnMode: 'query',
	/* Google is the one entry of the four that advertises a challenge method, so nothing here overrides it. */
	codeBinding: 'S256',
	scopes: ['openid', 'email', 'profile'],
	emailClaim: 'email',
	fallbackEmailClaims: [],
	/*
	 * The one value that departs from the cautious default a hand-configured provider gets, and it is a
	 * judgement about Google specifically: it verifies the addresses it asserts and reports that
	 * verification in `email_verified`, which is the signal the linking decision already requires to be
	 * `=== true`. An administrator can still turn it off.
	 */
	emailTrusted: true,
	clientIdPattern: /\.apps\.googleusercontent\.com$/,
	clientIdHint: 'a Google client id ends with .apps.googleusercontent.com',
	consoleUrl: 'https://console.cloud.google.com/apis/credentials',
	steps: [
		'In Google Cloud Console, select an existing project or create one for this deployment.',
		'Configure the OAuth consent screen if you have not already — choose External to let anyone with a Google account sign in, and fill in the support and developer contact addresses.',
		'Open Credentials, then Create credentials, and choose OAuth client ID.',
		'Choose Web application as the application type.',
		'Under Authorized redirect URIs, add the callback address shown below, exactly as it appears.',
		'Leave Authorized JavaScript origins empty. This server completes the sign-in from its own backend, so it needs none.',
		'Create the client, then copy the two values Google shows you into the fields below.'
	],
	requiredValues: [
		{
			name: 'clientId',
			label: 'Client ID',
			secret: false,
			hint: 'ends with .apps.googleusercontent.com'
		},
		{
			name: 'clientSecret',
			label: 'Client secret',
			secret: true,
			hint: 'shown once when the credential is created'
		}
	],
	choices: []
};

const MICROSOFT: KnownProvider = {
	catalogueId: 'microsoft',
	defaultProviderId: 'microsoft',
	displayName: 'Microsoft',
	buttonText: 'Sign in with Microsoft',
	/*
	 * The only templated entry, and the reason the field exists. Microsoft's issuer contains the
	 * organisation, so no fixed string can equal every deployment's — and the documents it publishes for
	 * its multi-organisation endpoints state the issuer as the literal placeholder `{tenantid}`, which no
	 * equality check can ever satisfy.
	 */
	issuerRule: {
		kind: 'templated',
		template: 'https://login.microsoftonline.com/{tenant}/v2.0',
		pattern: /^https:\/\/login\.microsoftonline\.com\/[^/]+\/v2\.0$/
	},
	protocol: { kind: 'oidc' },
	credential: { kind: 'secret' },
	returnMode: 'query',
	/*
	 * Advertises no challenge method while its own documentation recommends the binding "for all
	 * application types, both public and confidential clients". Stated here because inferring from the
	 * metadata would silently drop it.
	 */
	codeBinding: 'S256',
	scopes: ['openid', 'email', 'profile'],
	emailClaim: 'email',
	/*
	 * Microsoft documents that `email` is present by default only for guest accounts with an address, and
	 * that this fallback "could be an email address, phone number, or a generic username" — which is why
	 * the reader uses it only when the value actually looks like an address.
	 */
	fallbackEmailClaims: ['preferred_username'],
	/*
	 * What actually enforces a connection restricted to one organisation. Microsoft's own claims reference
	 * instructs an application to "use the GUID portion of the claim to restrict the set of tenants that
	 * can sign in" — so this is their instruction, not our preference.
	 */
	organisationClaim: 'tid',
	emailTrusted: true,
	/* An application id is a GUID. A secret is not, which is the mistake this catches. */
	clientIdPattern:
		/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i,
	clientIdHint:
		'a Microsoft Application (client) ID is a GUID, like 00001111-aaaa-2222-bbbb-3333cccc4444',
	consoleUrl:
		'https://entra.microsoft.com/#view/Microsoft_AAD_RegisteredApps/ApplicationsListBlade',
	steps: [
		'In the Microsoft Entra admin center, open App registrations and choose New registration.',
		'Name the application whatever your users should see on the consent screen.',
		'Under Supported account types, choose the option matching your answer to the question below — a single organisation, or accounts in any organisation and personal Microsoft accounts.',
		'Under Redirect URI, choose Web and enter the callback address shown below, exactly as it appears.',
		'Register the application, then copy the Application (client) ID and, if you chose one organisation, the Directory (tenant) ID from the Overview page.',
		'Open Certificates & secrets, choose New client secret, and copy its Value — not its Secret ID. It is shown only once.'
	],
	requiredValues: [
		{
			name: 'tenant',
			label: 'Directory (tenant) ID',
			secret: false,
			hint: "the organisation's directory id or verified domain, or `common` for any Microsoft account"
		},
		{
			name: 'clientId',
			label: 'Application (client) ID',
			secret: false,
			hint: 'a GUID, from the application Overview page'
		},
		{
			name: 'clientSecret',
			label: 'Client secret',
			secret: true,
			hint: 'the secret Value, shown once when created — not the Secret ID'
		}
	],
	choices: [
		{
			name: 'tenant',
			question: 'Who should be able to sign in with Microsoft?',
			options: [
				{
					value: null,
					label: 'Only people in one organisation',
					consequence:
						"Supply that organisation's directory id or verified domain. Anyone signing in from a different organisation is refused, whatever Microsoft says about them."
				},
				{
					value: 'common',
					label: 'Anyone with a Microsoft account',
					consequence:
						'Anyone in the world with a Microsoft account — work, school or personal — can sign in and, unless you close registration or restrict email domains, be given an account here.'
				}
			]
		}
	]
};

const APPLE: KnownProvider = {
	catalogueId: 'apple',
	defaultProviderId: 'apple',
	displayName: 'Apple',
	buttonText: 'Sign in with Apple',
	issuerRule: { kind: 'fixed', issuer: 'https://appleid.apple.com' },
	protocol: { kind: 'oidc' },
	/*
	 * The one entry that issues no secret. Apple issues a signing key, and the value presented at its token
	 * endpoint is an assertion derived from it which Apple refuses if it is valid for longer than the
	 * ceiling below. So a stored credential is an outage with a date on it, and this feature exists partly
	 * to make sure nobody stores one.
	 */
	credential: {
		kind: 'signed_assertion',
		audience: 'https://appleid.apple.com',
		algorithm: 'ES256',
		/* Apple's documented maximum: six months. Recorded so the minting code needs no magic number. */
		maxLifetimeSeconds: 15777000
	},
	/*
	 * Not a preference. Apple refuses the authorization request outright — a missing or unsupported
	 * parameter error — whenever a name or an address is among the scopes and the return is anything else.
	 */
	returnMode: 'form_post',
	/*
	 * Unresolved rather than unknown-by-omission: Apple advertises no challenge method, and the public
	 * record contradicts itself about whether it accepts one. `unknown` therefore means nothing is sent,
	 * which is the safe reading — a missing binding is a weakness, a rejected authorization request is a
	 * total outage. Settled empirically against a real credential; see specs/053 research D7.
	 */
	codeBinding: 'unknown',
	scopes: ['openid', 'email', 'name'],
	emailClaim: 'email',
	fallbackEmailClaims: [],
	/*
	 * Apple verifies the addresses it asserts and reports it in `email_verified`. It may supply a private
	 * relay address instead of the person's own; that is still an address Apple verified and routes, so it
	 * is treated as theirs.
	 */
	emailTrusted: true,
	/* A Services ID is reverse-domain. A Team ID or a key is not, which is the mistake this catches. */
	clientIdPattern: /^[A-Za-z0-9][A-Za-z0-9-]*(\.[A-Za-z0-9][A-Za-z0-9-]*)+$/,
	clientIdHint:
		'an Apple Services ID is reverse-domain, like com.example.auth — not your Team ID',
	consoleUrl:
		'https://developer.apple.com/account/resources/identifiers/list/serviceId',
	steps: [
		'In your Apple Developer account, open Certificates, Identifiers & Profiles, then Identifiers.',
		'Create an App ID for your application if you have none, and enable Sign In with Apple on it.',
		'Create a Services ID. Its identifier is reverse-domain — this is the value this server sends as the client id.',
		'Configure that Services ID: choose the App ID as its primary, add your domain, and add the callback address shown below under Return URLs, exactly as it appears.',
		'Open Keys, create a key, enable Sign In with Apple on it, and download the .p8 file. Apple lets you download it once.',
		'Copy the Key ID shown beside the key, and your Team ID from the top right of the page or your membership details.',
		'Paste the whole contents of the .p8 file below. This server signs the credential Apple asks for itself, so you never generate or renew one.'
	],
	requiredValues: [
		{
			name: 'clientId',
			label: 'Services ID',
			secret: false,
			hint: 'reverse-domain, like com.example.auth'
		},
		{
			name: 'teamId',
			label: 'Team ID',
			secret: false,
			hint: '10 characters, from your membership details'
		},
		{
			name: 'keyId',
			label: 'Key ID',
			secret: false,
			hint: '10 characters, shown beside the key you created'
		},
		{
			name: 'signingKey',
			label: 'Key file (.p8)',
			secret: true,
			hint: 'the whole contents of the downloaded file, including the BEGIN and END lines'
		}
	],
	choices: []
};

const GITHUB: KnownProvider = {
	catalogueId: 'github',
	defaultProviderId: 'github',
	displayName: 'GitHub',
	buttonText: 'Sign in with GitHub',
	/*
	 * A real https URL that satisfies the issuer rules, and GitHub's canonical identity — but **never
	 * fetched**, because this entry's protocol says there is nothing to discover. GitHub publishes no
	 * metadata for signing a person in.
	 *
	 * It does publish one OpenID Connect document, at `token.actions.githubusercontent.com`. That one
	 * describes machine identity for its own workflow runner: it has no authorization endpoint, and its
	 * only supported response is a bare assertion, so no human can be sent to it. It is not usable here and
	 * this is recorded so nobody reopens the question.
	 */
	issuerRule: { kind: 'fixed', issuer: 'https://github.com' },
	protocol: {
		kind: 'profile_api',
		authorizationEndpoint: 'https://github.com/login/oauth/authorize',
		tokenEndpoint: 'https://github.com/login/oauth/access_token',
		reader: 'github'
	},
	credential: { kind: 'secret' },
	returnMode: 'query',
	/* Supported since July 2025, `S256` only — and, publishing no metadata, stated here or nowhere. */
	codeBinding: 'S256',
	/*
	 * `openid` is absent because GitHub has no such scope. `user:email` is what permits the addresses read
	 * that an account with a private profile address depends on.
	 */
	scopes: ['read:user', 'user:email'],
	emailClaim: 'email',
	fallbackEmailClaims: [],
	/*
	 * Trusted for linking, and safe only because of what the reader guarantees: it sets the verification
	 * claim exclusively for an address GitHub itself marks verified, and refuses a sign-in where no such
	 * address exists. Without that, this value would be a route into somebody else's account.
	 */
	emailTrusted: true,
	/*
	 * Deliberately loose, and aimed at one specific mistake: a GitHub client *secret* is 40 hex characters,
	 * an identifier is shorter. GitHub has changed its identifier format more than once, so a pattern
	 * modelling the current one would refuse a future one for no reason.
	 */
	clientIdPattern: /^[A-Za-z0-9._-]{1,32}$/,
	clientIdHint:
		'a GitHub client id is the shorter of the two values, shown above the secret',
	consoleUrl: 'https://github.com/settings/developers',
	steps: [
		'Open Settings, then Developer settings, then OAuth Apps, and choose New OAuth App. For an organisation, do this in that organisation’s settings instead.',
		'Name the application whatever your users should see when they authorise it.',
		'Set the Homepage URL to wherever your users start.',
		'Set the Authorization callback URL to the callback address shown below, exactly as it appears.',
		'Register the application, then copy the Client ID.',
		'Choose Generate a new client secret and copy it. It is shown only once.'
	],
	requiredValues: [
		{
			name: 'clientId',
			label: 'Client ID',
			secret: false,
			hint: 'the shorter value, shown above the secret'
		},
		{
			name: 'clientSecret',
			label: 'Client secret',
			secret: true,
			hint: 'shown once when generated'
		}
	],
	choices: []
};

/*
 * Order matters only in one respect: it is the order the login page renders buttons in, and that order
 * must not depend on which provider an administrator connected last.
 */
export const KNOWN_PROVIDERS: readonly KnownProvider[] = [
	GOOGLE,
	MICROSOFT,
	APPLE,
	GITHUB
];

export function knownProvider(catalogueId: string): KnownProvider | undefined {
	return KNOWN_PROVIDERS.find((entry) => entry.catalogueId === catalogueId);
}

function issuerMatches(rule: IssuerRule, issuer: string): boolean {
	return rule.kind === 'fixed'
		? rule.issuer === issuer
		: rule.pattern.test(issuer);
}

/* Whether a stored provider's issuer is this entry's. Asked per entry by the guidance read. */
export function matchesKnownProvider(
	entry: KnownProvider,
	issuer: string
): boolean {
	return issuerMatches(entry.issuerRule, issuer);
}

/*
 * Which recognised provider a stored one is, if any. Undefined for an arbitrary upstream, which is the
 * common case and not an error.
 */
export function knownProviderByIssuer(
	issuer: string
): KnownProvider | undefined {
	return KNOWN_PROVIDERS.find((entry) =>
		issuerMatches(entry.issuerRule, issuer)
	);
}

/*
 * The issuer a new connection to this entry stores.
 *
 * Undefined when the entry needs a value the caller did not supply — a templated issuer cannot be built
 * without its parameter, and inventing one would store an issuer naming an organisation nobody chose.
 */
export function issuerForKnownProvider(
	entry: KnownProvider,
	values: { tenant?: string }
): string | undefined {
	if (entry.issuerRule.kind === 'fixed') return entry.issuerRule.issuer;
	if (!values.tenant) return undefined;
	return entry.issuerRule.template.replace('{tenant}', values.tenant);
}

/* For the refusal that names what a caller could have said instead. */
export function knownProviderIds(): string[] {
	return KNOWN_PROVIDERS.map((entry) => entry.catalogueId);
}
