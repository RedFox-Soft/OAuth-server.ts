// Signatures of every overridable behavior function, keyed by its canonical
// registry name. Uses type-only `typeof import(...)` so this module pulls in NO
// runtime code — the override registry can be imported (e.g. from the test
// preload) without dragging in the model graph that the addon modules load.
// An override may answer synchronously where the default is async: every caller awaits the result.
type Overridable<F> = F extends (...args: infer A) => infer R
	? (...args: A) => R | Awaited<R>
	: never;

export interface AddonImplementations {
	assertJwtClientAuthClaimsAndHeader: Overridable<
		(typeof import('./default.js'))['assertJwtClientAuthClaimsAndHeader']
	>;
	loadExistingGrant: Overridable<
		(typeof import('./account.js'))['loadExistingGrant']
	>;
	findAccount: Overridable<(typeof import('./account.js'))['findAccount']>;
	expiresWithSession: Overridable<
		(typeof import('./tokens.js'))['expiresWithSession']
	>;
	issueRefreshToken: Overridable<
		(typeof import('./tokens.js'))['issueRefreshToken']
	>;
	pairwiseIdentifier: Overridable<
		(typeof import('./tokens.js'))['pairwiseIdentifier']
	>;
	rotateRefreshToken: Overridable<
		(typeof import('./tokens.js'))['rotateRefreshToken']
	>;
	idFactory: Overridable<(typeof import('./tokens.js'))['idFactory']>;
	secretFactory: Overridable<(typeof import('./tokens.js'))['secretFactory']>;
	defaultResource: Overridable<
		(typeof import('./resources.js'))['defaultResource']
	>;
	useGrantedResource: Overridable<
		(typeof import('./resources.js'))['useGrantedResource']
	>;
	getResourceServerInfo: Overridable<
		(typeof import('./resources.js'))['getResourceServerInfo']
	>;
	sectorIdentifierUriValidate: Overridable<
		(typeof import('./claims.js'))['sectorIdentifierUriValidate']
	>;
	assertClaimsParameter: Overridable<
		(typeof import('./claims.js'))['assertClaimsParameter']
	>;
	assertJwtClaimsAndHeader: Overridable<
		(typeof import('./claims.js'))['assertJwtClaimsAndHeader']
	>;
	deviceInfo: Overridable<(typeof import('./interactions.js'))['deviceInfo']>;
	interactionPolicy: Overridable<
		(typeof import('./interactions.js'))['interactionPolicy']
	>;
	introspectionAllowedPolicy: Overridable<
		(typeof import('./introspection.js'))['introspectionAllowedPolicy']
	>;
	getCertificate: Overridable<(typeof import('./mtls.js'))['getCertificate']>;
	certificateAuthorized: Overridable<
		(typeof import('./mtls.js'))['certificateAuthorized']
	>;
	certificateSubjectMatches: Overridable<
		(typeof import('./mtls.js'))['certificateSubjectMatches']
	>;
	triggerAuthenticationDevice: Overridable<
		(typeof import('./ciba.js'))['triggerAuthenticationDevice']
	>;
	validateBindingMessage: Overridable<
		(typeof import('./ciba.js'))['validateBindingMessage']
	>;
	validateRequestContext: Overridable<
		(typeof import('./ciba.js'))['validateRequestContext']
	>;
	processLoginHintToken: Overridable<
		(typeof import('./ciba.js'))['processLoginHintToken']
	>;
	processLoginHint: Overridable<
		(typeof import('./ciba.js'))['processLoginHint']
	>;
	verifyUserCode: Overridable<(typeof import('./ciba.js'))['verifyUserCode']>;
	rarForAuthorizationCode: Overridable<
		(typeof import('./rar.js'))['rarForAuthorizationCode']
	>;
	rarForCodeResponse: Overridable<
		(typeof import('./rar.js'))['rarForCodeResponse']
	>;
	rarForRefreshTokenResponse: Overridable<
		(typeof import('./rar.js'))['rarForRefreshTokenResponse']
	>;
	rarForIntrospectionResponse: Overridable<
		(typeof import('./rar.js'))['rarForIntrospectionResponse']
	>;
}
