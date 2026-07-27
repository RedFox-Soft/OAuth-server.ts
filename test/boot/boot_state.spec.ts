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
 * What a freshly booted server has, before anything reloads or reconfigures it.
 *
 * Two things are set up as modules load: configs/keys.ts resolves the jwksStore into
 * configs/keystore.ts, and configs/application.ts validates the settings and derives
 * `configuration` from them. Every other spec arrives at that state through the harness — seedJwks()
 * and reloadConfiguration() — so no other spec can tell a working boot from one that derives nothing
 * at all. Both failures are total: a server that cannot sign anything, or one whose every scope and
 * claim lookup comes up empty.
 *
 * Hence a clean child process: import the provider the way a deployment does, with no reload and no
 * test harness, and look at what it ended up with. That is what justifies the subprocess.
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
const app = await import(at('lib/configs/application.ts'));

process.stdout.write(JSON.stringify({
	published: ks.publicJWKS.keys.length,
	held: [...ks.keystore].length,
	canSign: ks.keystore.selectForSign({ alg: 'RS256' }).length > 0,
	scopes: [...app.configuration.scopes],
	grantTypes: [...app.configuration.grantTypes],
	claimsSupported: [...app.configuration.claimsSupported],
	openidClaims: Object.keys(app.configuration.claims.openid ?? {})
}));
`;

// Written outside the repo: inside it, the spec glob would try to run this as a test file, and the
// `lib/*` path alias would make the imports resolve differently than a deployment's would.
let scriptPath: string | undefined;

async function boot() {
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
	return JSON.parse(stdout);
}

// One boot, shared by the cases below: starting a process is the expensive part, and every
// assertion is about the same booted state.
const booted = await boot();

afterAll(async () => {
	if (scriptPath) await fs.rm(scriptPath, { force: true });
});

describe('a freshly booted server, with no reload and no harness', () => {
	it('holds signing keys and publishes them', () => {
		// resolveKeys provisions a key on an empty store, so a booted server always holds at least
		// one signing key — it is never left unable to issue a token.
		expect(booted.held).toBeGreaterThan(0);
		expect(booted.published).toBe(booted.held);
		expect(booted.canSign).toBe(true);
	});

	it('has its settings validated and derived', () => {
		// The derived values, not just any values: `openid` and its mandatory `sub` claim come from
		// the claims processing, and authorization_code from the grant-type collection.
		expect(booted.scopes).toContain('openid');
		expect(booted.grantTypes).toContain('authorization_code');
		expect(booted.claimsSupported).toContain('sub');
		expect(booted.openidClaims).toContain('sub');
	});
});
