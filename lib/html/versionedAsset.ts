import { statSync } from 'node:fs';

/*
 * `staticPlugin` serves `public/` with a long max-age, so a page must address every asset it
 * references by that file's build time: a rebuilt file is refetched, an unchanged one stays cached.
 *
 * One owner for this. `lib/admin/ui/serverRender.tsx` open-coded it for `admin.js` while
 * `lib/interactions/serverRender.tsx` had nothing, so a rebuilt sign-in bundle could be served stale
 * for as long as the max-age — a defect invisible from either file alone.
 *
 * An absent file yields an unversioned address rather than `?v=`: the suite and a freshly started
 * server both run before `bun run build`, and an empty version is a cache key like any other.
 */
export function versionedAsset(name: string): string {
	try {
		const version = Math.trunc(statSync(`./public/${name}`).mtimeMs).toString(
			36
		);
		return `/public/${name}?v=${version}`;
	} catch {
		return `/public/${name}`;
	}
}
