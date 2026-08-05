export function buildUIPath(uid: string, step: string) {
	return `/ui/${uid}/${step}`;
}

/*
 * The `notice` argument exists so the redirect that carries it and the route that reads it are written
 * against the same constant (`NOTICE_VERIFY`). The defect this closes was a literal on one side and no
 * reader at all on the other.
 */
export function buildUILoginPath(uid: string, notice?: string) {
	const path = buildUIPath(uid, 'login');
	return notice ? `${path}?notice=${encodeURIComponent(notice)}` : path;
}

export function buildUIRegistrationPath(uid: string) {
	return buildUIPath(uid, 'registration');
}

export function buildUIForgotPasswordPath(uid: string) {
	return buildUIPath(uid, 'forgot-password');
}

/*
 * The two federated hops. Written here for the same reason `buildUILoginPath` is: the login page produces
 * these URLs and the routes consume them, and the defect that module exists to prevent was a literal on one
 * side with no reader on the other.
 *
 * The provider id is encoded even though it is slug-shaped by validation — the page renders whatever the
 * bucket holds, and a stored value is not a validated one.
 */
export function buildUIFederationStartPath(uid: string, providerId: string) {
	return `${buildUIPath(uid, 'federation')}/${encodeURIComponent(providerId)}/start`;
}

export function buildUIFederationCompletePath(uid: string, ref: string) {
	return `${buildUIPath(uid, 'federation')}/complete?ref=${encodeURIComponent(ref)}`;
}
