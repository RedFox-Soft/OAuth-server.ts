/*
 * The one HTML escaper, for the positions React does not cover.
 *
 * Every page this server renders goes through `renderToStaticMarkup`, which escapes its own
 * interpolations — except the document each renderer wraps that markup in, which is a template
 * string. `<title>` is the position that keeps arising there, and it is a real sink: the policy in
 * lib/html/csp.ts is derived *from* the finished document, so an injected inline script would be
 * hashed and then authorized by the very header meant to stop it. Escaping the wrapper is what keeps
 * that derivation sound.
 *
 * It lives here rather than beside the first caller that needed it because it now has four, across
 * lib/html and lib/interactions, and an escaper found in two places is an escaper that will differ in
 * two places.
 */
export function esc(value: string): string {
	return value
		.replace(/&/g, '&amp;')
		.replace(/</g, '&lt;')
		.replace(/>/g, '&gt;')
		.replace(/"/g, '&quot;');
}
