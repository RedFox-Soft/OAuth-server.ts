export default function redirectUri(uri, payload) {
	const parsed = new URL(uri);
	for (const [k, v] of Object.entries(payload)) {
		parsed.searchParams.set(k, v);
	}
	return parsed.href;
}
