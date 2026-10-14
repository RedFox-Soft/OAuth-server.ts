import { TestAdapter } from '../models.js';

/* The checkboxes a consent page submits, as a browser would read them from the markup. */
export interface Checkbox {
	value: string;
	checked: boolean;
}

function attribute(tag: string, name: string): string | undefined {
	const match = new RegExp(`\\s${name}="([^"]*)"`).exec(tag);
	return match?.[1]
		.replaceAll('&quot;', '"')
		.replaceAll('&#x27;', "'")
		.replaceAll('&lt;', '<')
		.replaceAll('&gt;', '>')
		.replaceAll('&amp;', '&');
}

export function checkboxes(html: string): Checkbox[] {
	return [...html.matchAll(/<input\b[^>]*>/g)]
		.map(([tag]) => tag)
		.filter(
			(tag) =>
				attribute(tag, 'type') === 'checkbox' &&
				attribute(tag, 'name') === 'allow'
		)
		.map((tag) => ({
			value: attribute(tag, 'value') ?? '',
			checked: /\schecked(=|\s|>|\/)/.test(tag)
		}));
}

/* The authorization code a consent decision redirected the browser to the client with. */
export function codeOf(response: Response): string {
	const location = response.headers.get('location') ?? '';
	const code = URL.parse(location)?.searchParams.get('code');
	if (!code) throw new Error(`no code in ${location}`);
	return code;
}

/* Every grant the application holds, as stored — to show a decision wrote nothing. */
export function grantsOf(clientId: string): string {
	return JSON.stringify(
		[...TestAdapter.for('Grant').store.entries()]
			.filter(
				([key, value]) =>
					key.startsWith('Grant:') &&
					(value as { clientId?: string }).clientId === clientId
			)
			.sort(([a], [b]) => a.localeCompare(b))
	);
}
