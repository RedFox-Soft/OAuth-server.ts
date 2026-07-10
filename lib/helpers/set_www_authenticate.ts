import omitBy from './_/omit_by.ts';

export default function setWWWAuthenticate(
	ctx: { set(name: string, value: string): void },
	scheme: string,
	fields: Record<string, string | undefined>
) {
	const wwwAuth = Object.entries(omitBy(fields, (v) => v === undefined))
		.map(([key, val]) => `${key}="${val.replace(/"/g, '\\"')}"`)
		.join(', ');

	ctx.set('WWW-Authenticate', `${scheme} ${wwwAuth}`);
}
