/*
 * Fails on a high or critical advisory against a package the published image contains.
 *
 *   bun scripts/audit_production.ts
 *
 * `bun audit` reads the whole lockfile and has no production-only mode, so a development tool's
 * advisory would gate a release that never ships it. This script installs the production set into
 * a temporary copy the way the Dockerfile does (`bun install --production`, which also installs
 * non-optional peers such as typescript), and keeps an advisory only when a version it names is
 * installed there.
 */

import { cp, mkdtemp, readdir, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { member } from '../lib/helpers/_/object.ts';

type Advisory = {
	url: string;
	title: string;
	severity: string;
	vulnerable_versions: string;
};

const GATED = new Set(['high', 'critical']);

async function installedPackages(
	nodeModules: string,
	found = new Map<string, Set<string>>()
) {
	let entries;
	try {
		entries = await readdir(nodeModules, { withFileTypes: true });
	} catch {
		return found;
	}
	for (const entry of entries) {
		if (!entry.isDirectory() || entry.name.startsWith('.')) continue;
		const dirs = entry.name.startsWith('@')
			? (await readdir(join(nodeModules, entry.name), { withFileTypes: true }))
					.filter((scoped) => scoped.isDirectory())
					.map((scoped) => join(nodeModules, entry.name, scoped.name))
			: [join(nodeModules, entry.name)];
		for (const dir of dirs) {
			try {
				const manifest: unknown = JSON.parse(
					await readFile(join(dir, 'package.json'), 'utf8')
				);
				const name = member(manifest, 'name');
				const version = member(manifest, 'version');
				// A manifest without both names no package; its nested node_modules are still walked.
				if (typeof name === 'string' && typeof version === 'string') {
					const versions = found.get(name) ?? new Set<string>();
					versions.add(version);
					found.set(name, versions);
				}
			} catch {
				continue;
			}
			await installedPackages(join(dir, 'node_modules'), found);
		}
	}
	return found;
}

async function run(cmd: string[], cwd: string) {
	const proc = Bun.spawn(cmd, { cwd, stdout: 'pipe', stderr: 'inherit' });
	const stdout = await new Response(proc.stdout).text();
	return { stdout, exitCode: await proc.exited };
}

const root = join(import.meta.dir, '..');
const work = await mkdtemp(join(tmpdir(), 'audit-production-'));
try {
	await cp(join(root, 'package.json'), join(work, 'package.json'));
	await cp(join(root, 'bun.lock'), join(work, 'bun.lock'));

	const install = await run(
		['bun', 'install', '--production', '--frozen-lockfile', '--ignore-scripts'],
		work
	);
	if (install.exitCode !== 0)
		throw new Error('bun install --production failed');

	// `bun audit` exits non-zero whenever it finds anything, so its exit code says nothing here.
	const audit = await run(['bun', 'audit', '--json'], work);
	const report = JSON.parse(audit.stdout || '{}') as Record<string, Advisory[]>;

	const installed = await installedPackages(join(work, 'node_modules'));
	const shipped: string[] = [];
	let ignored = 0;
	for (const [name, advisories] of Object.entries(report)) {
		for (const advisory of advisories) {
			if (!GATED.has(advisory.severity)) continue;
			const hit = [...(installed.get(name) ?? [])].find((version) =>
				Bun.semver.satisfies(version, advisory.vulnerable_versions)
			);
			if (hit)
				shipped.push(
					`${name}@${hit}  ${advisory.severity}: ${advisory.title}  ${advisory.url}`
				);
			else ignored++;
		}
	}

	const total = [...installed.values()].reduce(
		(sum, versions) => sum + versions.size,
		0
	);
	if (shipped.length > 0) {
		console.error(
			`${shipped.length} high or critical advisory in the production install:\n`
		);
		for (const line of shipped) console.error(`  ${line}`);
		process.exitCode = 1;
	} else {
		console.log(
			`No high or critical advisory in the ${total} packages a production install contains` +
				(ignored
					? ` (${ignored} against development-only packages ignored).`
					: '.')
		);
	}
} finally {
	await rm(work, { recursive: true, force: true });
}
