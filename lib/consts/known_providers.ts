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
 * IMPORT-FREE, and that is load-bearing rather than tidy. `lib/interactions/loginPage.tsx` resolves a
 * provider's mark through this module, and that component is bundled into `public/loginClient.js` and runs
 * in a browser. An import reaching `lib/adapters/` would pull a datastore module — which, on MongoDB,
 * connects at module scope — into a browser bundle. Same rule as `lib/consts/storage_inventory.ts`, for a
 * different reason.
 */

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
	 * Also the key a stored provider is recognised by. Matching on the issuer rather than on a stored
	 * "came from the catalogue" flag is what lets a provider configured by hand years ago render with its
	 * mark, and is why this feature needs no migration.
	 */
	readonly issuer: string;
	readonly scopes: readonly string[];
	readonly emailClaim: string;
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
	/* What the provider calls the two values on its own screen, so an administrator is not translating. */
	readonly credentialLabels: {
		readonly clientId: string;
		readonly clientSecret: string;
	};
}

const GOOGLE: KnownProvider = {
	catalogueId: 'google',
	defaultProviderId: 'google',
	displayName: 'Google',
	buttonText: 'Sign in with Google',
	issuer: 'https://accounts.google.com',
	scopes: ['openid', 'email', 'profile'],
	emailClaim: 'email',
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
	credentialLabels: {
		clientId: 'Client ID',
		clientSecret: 'Client secret'
	}
};

export const KNOWN_PROVIDERS: readonly KnownProvider[] = [GOOGLE];

export function knownProvider(catalogueId: string): KnownProvider | undefined {
	return KNOWN_PROVIDERS.find((entry) => entry.catalogueId === catalogueId);
}

/*
 * Which recognised provider a stored one is, if any. Undefined for an arbitrary upstream, which is the
 * common case and not an error.
 */
export function knownProviderByIssuer(
	issuer: string
): KnownProvider | undefined {
	return KNOWN_PROVIDERS.find((entry) => entry.issuer === issuer);
}

/* For the refusal that names what a caller could have said instead. */
export function knownProviderIds(): string[] {
	return KNOWN_PROVIDERS.map((entry) => entry.catalogueId);
}
