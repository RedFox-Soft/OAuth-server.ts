import { beforeAll, beforeEach, describe, expect, it } from 'bun:test';
import fc from 'fast-check';

import bootstrap from '../test_helper.ts';
import { takeAll } from 'lib/person_activity/buffer.ts';
import {
	noteApiCheck,
	noteSignedIn,
	noteSignInRefused
} from 'lib/person_activity/record.ts';

/*
 * Text a caller writes — a browser's `User-Agent`, an MCP client's `Mcp-Name` — generated over the characters that
 * break things, long enough that it cannot appear by chance in an id, a date or a fixed word.
 */
const callerText = fc.string({ unit: 'binary', minLength: 16, maxLength: 300 });

/* A header value as a request can carry one: visible ASCII and spaces, not starting or ending with a space. */
const headerText = fc.stringMatching(/^[!-~][ -~]{14,298}[!-~]$/);

const TABLE = {
	rows: [{ name: 'search_files', scopes: ['files:read'] }],
	otherTools: 'refuse' as const,
	withoutMethod: 'refuse' as const
};

function stored(): string {
	return JSON.stringify(takeAll());
}

/**
 * @proves For every text a caller can write into a request, nothing the server keeps about a person contains it:
 * the browser is kept only as one of a few families, and a tool only as the name of a row an administrator set, or
 * as "another tool".
 */
describe("a person's activity and the caller's own text", () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	beforeEach(() => {
		takeAll();
	});

	it('never keeps the browser string a sign-in sent', () => {
		fc.assert(
			fc.property(headerText, (userAgent) => {
				const request = new Request('http://e.ly/ui/x/resume', {
					headers: { 'user-agent': userAgent }
				});
				noteSignedIn({
					bucketId: 'acme',
					accountId: 'anna',
					clientId: 'activity-app',
					redirectUri: undefined,
					login: { accountId: 'anna' },
					request
				});
				noteSignInRefused({
					bucketId: 'acme',
					accountId: 'anna',
					reason: 'wrong_password',
					clientId: 'activity-app',
					request
				});
				expect(stored()).not.toContain(JSON.stringify(userAgent).slice(1, -1));
			})
		);
	});

	it('never keeps a tool name the caller wrote that is not a row of the table', () => {
		fc.assert(
			fc.property(
				callerText.filter((name) => name !== 'search_files'),
				(tool) => {
					noteApiCheck({
						api: {
							bucketId: 'acme',
							identifier: 'https://files.acme.test/mcp',
							tools: TABLE
						},
						accountId: 'anna',
						clientId: 'agent-1',
						outcome: 'refused',
						reason: 'tool_not_listed',
						tool
					});
					expect(stored()).not.toContain(JSON.stringify(tool).slice(1, -1));
				}
			)
		);
	});
});
