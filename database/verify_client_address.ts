/*
 * How the server is reached replaces whether proxy headers are trusted (specs/115), against a real
 * datastore: an instance that turned the old setting off says "direct", an instance in use says "fly", a
 * fresh one keeps the default, a value already under the new key wins, and a second application changes
 * nothing. Shared by verify_mongodb.ts and verify_postgres.ts, which supply the raw reads and writes.
 *
 * The migration works on the one settings document, so this takes it over for the duration and puts back
 * what it found.
 */

type Doc = Record<string, unknown>;

export interface ClientAddressHooks {
	/* null removes the settings document. */
	writeSettings(config: Doc | null): Promise<void>;
	readSettings(): Promise<Doc | null>;
	/* Whether any administrator other than the one `addAdministrator` adds exists. */
	otherAdministratorsExist(): Promise<boolean>;
	addAdministrator(): Promise<void>;
	removeAdministrator(): Promise<void>;
	/* One application of the migration's half for this backend; answers its report lines. */
	apply(): Promise<unknown>;
}

type Check = (name: string, ok: boolean, detail?: string) => void;

const same = (a: unknown, b: unknown) =>
	JSON.stringify(a) === JSON.stringify(b);

export async function verifyClientAddress(
	hooks: ClientAddressHooks,
	check: Check
): Promise<void> {
	const original = await hooks.readSettings();
	try {
		await hooks.addAdministrator();

		await hooks.writeSettings({
			'rateLimit.trustedProxy': false,
			'mcp.enabled': true
		});
		await hooks.apply();
		check(
			'an instance that turned trusted proxy headers off is carried to direct',
			same(await hooks.readSettings(), {
				'mcp.enabled': true,
				'clientAddress.source': 'direct'
			}),
			JSON.stringify(await hooks.readSettings())
		);

		await hooks.writeSettings(null);
		await hooks.apply();
		const second = await hooks.apply();
		check(
			'an instance in use that never saved a setting is carried to fly, and a second application writes nothing',
			same(await hooks.readSettings(), { 'clientAddress.source': 'fly' }) &&
				same(second, ['clientAddress.source left at its default']),
			`${JSON.stringify(await hooks.readSettings())}; second run ${JSON.stringify(second)}`
		);

		await hooks.writeSettings({
			'rateLimit.trustedProxy': true,
			'clientAddress.source': 'cloudflare'
		});
		await hooks.apply();
		check(
			'a value already under clientAddress.source wins and the old key goes',
			same(await hooks.readSettings(), {
				'clientAddress.source': 'cloudflare'
			}),
			JSON.stringify(await hooks.readSettings())
		);

		await hooks.removeAdministrator();
		if (await hooks.otherAdministratorsExist()) {
			check(
				'a fresh database keeps the default (skipped: this database has administrators)',
				true
			);
		} else {
			await hooks.writeSettings({ 'rateLimit.trustedProxy': true });
			await hooks.apply();
			check(
				'a fresh database keeps the default and loses the old key',
				same(await hooks.readSettings(), {}),
				JSON.stringify(await hooks.readSettings())
			);
		}
	} finally {
		await hooks.removeAdministrator();
		await hooks.writeSettings(original);
	}
}

/*
 * The mail limit holds for the instance, not per process: twenty requests from one caller racing against a
 * limit of ten are admitted exactly ten times, because each is counted by one atomic increment in the
 * datastore before it is compared. Run against whichever backend the environment selects.
 */
export async function verifyMailTallyRace(check: Check): Promise<void> {
	const { ApplicationConfig } = await import('../lib/configs/application.js');
	const { setPeerResolverForTests } =
		await import('../lib/helpers/caller_address.js');
	const { admitMailRequest } = await import('../lib/mail_limit/tally.js');

	const limit = ApplicationConfig['mail.requestsPerCallerPerHour'];
	ApplicationConfig['mail.requestsPerCallerPerHour'] = 10;
	// A connection address no real caller has, so no tally of a real one is touched.
	const peer = `198.18.${String(Date.now() % 250)}.1`;
	setPeerResolverForTests(() => peer);
	try {
		const answers = await Promise.all(
			Array.from({ length: 20 }, () =>
				admitMailRequest(new Request('http://fidelity.invalid/'))
			)
		);
		const admitted = answers.filter((answer) => answer.admitted).length;
		check(
			'twenty racing mail requests from one caller against a limit of ten admit exactly ten',
			admitted === 10,
			`admitted ${String(admitted)}`
		);
	} finally {
		setPeerResolverForTests(null);
		ApplicationConfig['mail.requestsPerCallerPerHour'] = limit;
	}
}
