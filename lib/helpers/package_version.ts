import { readFileSync } from 'node:fs';

/*
 * package.json's version, read at runtime rather than imported.
 *
 * An import would need `resolveJsonModule` plus a NodeNext import attribute, which is a tsconfig
 * change for one string. Resolved against this module's own URL so it survives being run from any
 * working directory, and the file is present in the container image (the Dockerfile copies it).
 */
export function packageVersion(): string | undefined {
	try {
		const path = new URL('../../package.json', import.meta.url);
		const parsed = JSON.parse(readFileSync(path, 'utf8')) as {
			version?: unknown;
		};
		return typeof parsed.version === 'string' && parsed.version.trim()
			? parsed.version.trim()
			: undefined;
	} catch {
		/*
		 * Not fatal, and deliberately silent. A missing or unreadable manifest means Sentry events go out
		 * without a release label and usage reports without a version, which is the documented fallback
		 * of both — it must never be the reason the server fails to start or a fault goes unreported.
		 */
		return undefined;
	}
}
