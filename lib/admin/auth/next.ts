/*
 * Where sign-in may send a person back to, after the console sent them to sign in.
 *
 * Only an address inside the console: a value the browser carries through the provider and back is a
 * value anyone can write, and an open redirect on the sign-in path would lend this server's name to a
 * phishing page. Anything that is not plainly a console page becomes the console's home.
 *
 * Checked twice — when the round-trip starts and when it ends — because the value travels in a cookie
 * between the two, and a cookie is not something the server wrote and can therefore trust on return.
 */
const HOME = '/admin';
const MAX_LENGTH = 2048;
const NOT_PAGES = [
	'/admin/api',
	'/admin/login',
	'/admin/signup',
	'/admin/callback'
];

export function safeNext(value: unknown): string {
	if (typeof value !== 'string') return HOME;
	if (value.length === 0 || value.length > MAX_LENGTH) return HOME;
	if (value !== HOME && !value.startsWith(`${HOME}/`)) return HOME;
	// `//` would let a later rewrite turn the path into a host; a backslash is read as a slash by browsers.
	if (value.includes('//') || value.includes('\\')) return HOME;
	// A control character cannot sit in a Location header; a dot segment climbs out of the console.
	for (let at = 0; at < value.length; at++) {
		const code = value.charCodeAt(at);
		if (code < 32 || code === 127) return HOME;
	}
	const path = value.split(/[?#]/, 1)[0] ?? '';
	// A URL parser reads `%2e` as a dot in a path segment, so the encoded spelling climbs out too.
	const climbs = path.split('/').some((segment) => {
		const dots = segment.toLowerCase().replaceAll('%2e', '.');
		return dots === '.' || dots === '..';
	});
	if (climbs) return HOME;
	for (const prefix of NOT_PAGES) {
		if (path === prefix || path.startsWith(`${prefix}/`)) return HOME;
	}
	return value;
}
