import { describe, it, expect, afterAll } from 'bun:test';
import * as fs from 'node:fs/promises';
import * as os from 'node:os';
import * as path from 'node:path';

// Not used here — the assertions all run in the child process. It loads the model/provider import
// graph from the same end every other spec does; without it this file's position in the run order
// lets the preload's addon import enter that graph first, which leaves base_token half-initialised
// (see the load-order anchor in lib/provider.ts). Removable once that cycle is gone.
import 'lib/provider.js';

/*
 * The server's key material is populated at boot, when configs/keys.ts resolves the jwksStore and
 * hands the result to configs/keystore.ts. Every other spec reaches the same state through the
 * harness's seedJwks() -> reloadJWKSKeys(), so none of them can tell a working boot from one that
 * loads no keys at all — a total failure (nothing can be signed, /jwks serves an empty set).
 *
 * So this runs in a clean child process: import the provider the way a deployment does, with no
 * reload and no test harness, and assert the keys are there. It is the only spec that observes the
 * boot path itself, which is what justifies the subprocess.
 *
 * The child starts on an empty in-memory store (the preload's fixture keys are not in its process),
 * so it also covers the auto-provisioning fallback in resolveKeys.
 */
const BOOT_SCRIPT = `
import * as path from 'node:path';
import { pathToFileURL } from 'node:url';

const at = (rel) => pathToFileURL(path.join(process.cwd(), rel)).href;

await import(at('lib/provider.ts'));
const ks = await import(at('lib/configs/keystore.ts'));

process.stdout.write(JSON.stringify({
	published: ks.publicJWKS.keys.length,
	held: [...ks.keystore].length,
	canSign: ks.keystore.selectForSign({ alg: 'RS256' }).length > 0
}));
`;

// Written outside the repo: inside it, the spec glob would try to run this as a test file, and the
// `lib/*` path alias would make the imports resolve differently than a deployment's would.
let scriptPath: string | undefined;

afterAll(async () => {
	if (scriptPath) await fs.rm(scriptPath, { force: true });
});

describe('signing keys are loaded at boot, without any reload', () => {
	it('a freshly booted process can sign and publishes its keys', async () => {
		const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'oidc-boot-'));
		scriptPath = path.join(dir, 'boot.ts');
		await fs.writeFile(scriptPath, BOOT_SCRIPT);

		const proc = Bun.spawn(['bun', 'run', scriptPath], {
			cwd: process.cwd(),
			// A deliberately minimal env, not `...process.env`: `bun test` exports state into the
			// environment that changes how a child `bun run` loads modules, which would stop this
			// from being the clean boot it is meant to observe.
			env: {
				PATH: process.env.PATH,
				SYSTEMROOT: process.env.SYSTEMROOT,
				NODE_ENV: 'test'
			},
			stdout: 'pipe',
			stderr: 'pipe'
		});

		const [stdout, stderr, exitCode] = await Promise.all([
			new Response(proc.stdout).text(),
			new Response(proc.stderr).text(),
			proc.exited
		]);

		expect({ exitCode, stderr }).toEqual({ exitCode: 0, stderr: '' });

		const booted = JSON.parse(stdout);
		// resolveKeys provisions a key on an empty store, so a booted server always holds at least
		// one signing key — it is never left unable to issue a token.
		expect(booted.held).toBeGreaterThan(0);
		expect(booted.published).toBe(booted.held);
		expect(booted.canSign).toBe(true);
	}, 30_000);
});
