export function buildUIPath(uid: string, step: string) {
	return `/ui/${uid}/${step}`;
}

export function buildUILoginPath(uid: string) {
	return buildUIPath(uid, 'login');
}

export function buildUIRegistrationPath(uid: string) {
	return buildUIPath(uid, 'registration');
}
