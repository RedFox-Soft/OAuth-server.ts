// Signatures of every overridable behavior function, keyed by its canonical
// registry name. Uses type-only `typeof import(...)` so this module pulls in NO
// runtime code — the override registry can be imported (e.g. from the test
// preload) without dragging in the model graph that the addon modules load.
export interface AddonImplementations {
	assertJwtClientAuthClaimsAndHeader: (typeof import('./default.js'))['assertJwtClientAuthClaimsAndHeader'];
	clientBasedCORS: (typeof import('./cors.js'))['clientBasedCORS'];
	loadExistingGrant: (typeof import('./account.js'))['loadExistingGrant'];
	findAccount: (typeof import('./account.js'))['findAccount'];
	expiresWithSession: (typeof import('./tokens.js'))['expiresWithSession'];
	issueRefreshToken: (typeof import('./tokens.js'))['issueRefreshToken'];
	pairwiseIdentifier: (typeof import('./tokens.js'))['pairwiseIdentifier'];
	rotateRefreshToken: (typeof import('./tokens.js'))['rotateRefreshToken'];
	idFactory: (typeof import('./tokens.js'))['idFactory'];
	secretFactory: (typeof import('./tokens.js'))['secretFactory'];
	defaultResource: (typeof import('./resources.js'))['defaultResource'];
	useGrantedResource: (typeof import('./resources.js'))['useGrantedResource'];
	getResourceServerInfo: (typeof import('./resources.js'))['getResourceServerInfo'];
	sectorIdentifierUriValidate: (typeof import('./claims.js'))['sectorIdentifierUriValidate'];
	assertClaimsParameter: (typeof import('./claims.js'))['assertClaimsParameter'];
	assertJwtClaimsAndHeader: (typeof import('./claims.js'))['assertJwtClaimsAndHeader'];
	deviceInfo: (typeof import('./interactions.js'))['deviceInfo'];
	interactionPolicy: (typeof import('./interactions.js'))['interactionPolicy'];
	introspectionAllowedPolicy: (typeof import('./introspection.js'))['introspectionAllowedPolicy'];
	getCertificate: (typeof import('./mtls.js'))['getCertificate'];
	certificateAuthorized: (typeof import('./mtls.js'))['certificateAuthorized'];
	certificateSubjectMatches: (typeof import('./mtls.js'))['certificateSubjectMatches'];
	triggerAuthenticationDevice: (typeof import('./ciba.js'))['triggerAuthenticationDevice'];
	validateBindingMessage: (typeof import('./ciba.js'))['validateBindingMessage'];
	validateRequestContext: (typeof import('./ciba.js'))['validateRequestContext'];
	processLoginHintToken: (typeof import('./ciba.js'))['processLoginHintToken'];
	processLoginHint: (typeof import('./ciba.js'))['processLoginHint'];
	verifyUserCode: (typeof import('./ciba.js'))['verifyUserCode'];
	rarForAuthorizationCode: (typeof import('./rar.js'))['rarForAuthorizationCode'];
	rarForCodeResponse: (typeof import('./rar.js'))['rarForCodeResponse'];
	rarForRefreshTokenResponse: (typeof import('./rar.js'))['rarForRefreshTokenResponse'];
	rarForIntrospectionResponse: (typeof import('./rar.js'))['rarForIntrospectionResponse'];
}
