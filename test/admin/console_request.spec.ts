import { describe, it, expect, afterEach, spyOn, type Mock } from 'bun:test';
import { request } from 'lib/admin/ui/frame/request.ts';
import { fetchAnswering } from 'test/fetch_mock.ts';

let fetchSpy: Mock<typeof fetch> | undefined;

afterEach(() => {
	fetchSpy?.mockRestore();
	fetchSpy = undefined;
});

/**
 * @proves A refusal the console asks the server for — the preview an address change or a move answers with
 * 409 — reaches the screen whole, even though it carries no `message`.
 */
describe("the console's request helper", () => {
	it('keeps the content of a refusal that carries no message', async () => {
		fetchSpy = spyOn(globalThis, 'fetch').mockImplementation(
			fetchAnswering(async () =>
				Response.json(
					{
						confirmationRequired: true,
						from: 'https://e.ly/old',
						to: 'https://e.ly/new',
						applications: []
					},
					{ status: 409 }
				)
			)
		);

		const result = await request('POST', '/admin/api/buckets/b/address', {
			slug: 'new'
		});

		expect(result.ok).toBe(false);
		if (result.ok) return;
		expect(result.error.confirmationRequired).toBe(true);
		expect(result.error.to).toBe('https://e.ly/new');
		expect(result.error.message).toBeString();
	});
});
