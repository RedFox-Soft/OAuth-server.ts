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
