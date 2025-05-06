export default function redirectUri(
	uri: string,
	payload: Record<string, string>
): string {
	const parsed = new URL(uri);
	for (const [k, v] of Object.entries(payload)) {
		parsed.searchParams.set(k, v);
	}
	return parsed.href;
}
